//! Credit repricing finishes before either native consent or public revocation consent is requested.
use super::credit::{CreditPlan, CreditRepriceTemplate};
use super::*;
use invisi_sdk_rpc::broadcaster::{request_hash, Trust, VerifiedQuote};
impl PreparedCredit {
    pub fn broadcaster_state(&self) -> Option<&PreparedBroadcasterState> {
        self.broadcaster.as_ref()
    }
    pub fn reattach_provenance(mut self, capability: Arc<PreparedProvenance>) -> Result<Self> {
        capability.validate(
            self.context,
            self.broadcaster.as_ref().and_then(|s| s.provenance_mode()),
        )?;
        self.provenance = Some(capability);
        Ok(self)
    }
    pub fn broadcaster_intent(&self) -> Result<TransactionCall> {
        if self.phase != Phase::Prepared {
            return Err("Credit relay intent requires unsigned preparation".into());
        }
        let contract =
            protocol::ProtocolContract::new(word_address(self.context.protocol_address)?)?;
        Ok(match &self.plan {
            CreditPlan::Create { params, .. } => contract.call(&InvisiCore::createCreditCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Update { params, .. } => contract.call(&InvisiCore::updateCreditCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Draw { params, .. } => contract.call(&InvisiCore::creditDrawCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Revoke {
                owner,
                token,
                grant_id,
                deadline,
                fee,
                ..
            } => contract.call(&InvisiCore::revokeCreditCall {
                token: *token,
                owner: *owner,
                grantId: *grant_id,
                deadline: U256::from(*deadline),
                feeRecipient: fee.recipient,
                feeAmount: fee.amount,
                signature: Bytes::new(),
            }),
        })
    }
    pub(crate) fn quote_for_broadcaster(
        &self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> Result<Self> {
        if options.fee_source.is_some() || options.funding_permit.is_some() {
            return Err("Credit fees use owner allowance or gross draw deduction".into());
        }
        if options
            .max_fee_amount
            .is_none_or(|cap| cap == U256::ZERO || cap >= U256::from(1) << 128)
        {
            return Err("positive maximum broadcaster fee required".into());
        }
        if self.phase != Phase::Prepared
            || chain.context() != self.context
            || !(1..=16).contains(&options.max_attempts)
        {
            return Err("Credit relay requires unsigned preparation and matching chain".into());
        }
        let config = relay.configuration();
        config.validate().map_err(|e| e.to_string())?;
        if let Some(cap) = &self.provenance {
            cap.validate(self.context, relay.provenance_mode())?;
        }
        let retained_reads = self
            .preparation_reads
            .as_ref()
            .filter(|reads| reads.matches(&chain))
            .cloned();
        let runtime = Invisi {
            chain: self
                .preparation_reads
                .as_ref()
                .map_or_else(|| chain.clone(), |reads| reads.for_quote(chain.clone())),
            provenance: self.provenance.clone(),
            provenance_factory: self.provenance_factory.clone(),
        };
        let template = self
            .reprice
            .as_ref()
            .ok_or("original Credit business preparation required for explicit repricing")?;
        let cancellation_token = options
            .schedule
            .as_ref()
            .map(|_| CancellationToken::generate());
        let schedule = options
            .schedule
            .as_ref()
            .map(|s| invisi_sdk_rpc::broadcaster::Schedule {
                publish_after: s.publish_after.to_string(),
                execute_before: s.execute_before.to_string(),
                cancel_token_hash: cancellation_token.as_ref().unwrap().commitment(),
            });
        if let Some(schedule) = &schedule {
            schedule.validate().map_err(|e| e.to_string())?;
        }
        let mut fee = relay.scheduled_fee(
            self.token,
            Some(&self.broadcaster_intent()?.data),
            schedule.as_ref(),
        )?;
        for _round in 0..options.max_attempts {
            if fee.fee_recipient != config.fee_recipient {
                return Err("Credit relay fee recipient mismatch".into());
            }
            let amount = decimal(&json!(fee.fee_amount))?;
            if options.max_fee_amount.is_some_and(|cap| amount > cap) {
                return Err("broadcaster fee exceeds maximum".into());
            }
            let f = Fee {
                recipient: fee.fee_recipient,
                amount,
            };
            f.validate()?;
            if amount == U256::ZERO {
                return Err("positive Credit relay fee required".into());
            }
            let mut candidate = match template {
                CreditRepriceTemplate::Create(state, payment, deadline) => runtime
                    .prepare_create_credit_with_initial_payment(
                        self.wallet
                            .as_ref()
                            .ok_or("complete wallet required for Credit repricing")?,
                        state.clone(),
                        payment
                            .clone()
                            .map(|mut p| -> Result<_> {
                                if let Some(net) = p.net_amount {
                                    p.amount = net
                                        .checked_add(amount)
                                        .ok_or("initial payment gross overflow")?;
                                }
                                Ok(p)
                            })
                            .transpose()?,
                        *deadline,
                        f,
                    )?,
                CreditRepriceTemplate::Update(input, changes, deadline) => runtime
                    .prepare_update_credit_explicit(
                        self.wallet
                            .as_ref()
                            .ok_or("complete wallet required for Credit repricing")?,
                        input.clone(),
                        changes.clone(),
                        *deadline,
                        f,
                    )?,
                CreditRepriceTemplate::Draw(inputs, recipient, deadline, payload) => runtime
                    .prepare_draw_credit_explicit(
                        self.wallet
                            .as_ref()
                            .ok_or("complete wallet required for Credit repricing")?,
                        inputs.clone(),
                        recipient,
                        *deadline,
                        f,
                        payload.clone(),
                    )?,
                CreditRepriceTemplate::Revoke(token, grant_id, deadline) => runtime
                    .prepare_revoke_credit_explicit(
                        self.owner_address,
                        *token,
                        *grant_id,
                        *deadline,
                        f,
                    )?,
            };
            let data = candidate.broadcaster_intent()?.data;
            let next = relay.scheduled_fee(self.token, Some(&data), schedule.as_ref())?;
            let next_amount = decimal(&json!(next.fee_amount))?;
            if next.fee_recipient != config.fee_recipient
                || next_amount == U256::ZERO
                || options.max_fee_amount.is_some_and(|cap| next_amount > cap)
            {
                return Err("broadcaster fee exceeds maximum or recipient changed".into());
            }
            if next_amount > amount {
                fee = next;
                continue;
            }
            let block = chain.snapshot()?;
            let quote = relay.scheduled_quote(
                &data,
                self.context.chain_id,
                word_address(self.context.protocol_address)?,
                chain.construction_timestamp(&block),
                &[],
                schedule.as_ref(),
            )?;
            if quote.signed().quote.schedule.as_ref() != schedule.as_ref() {
                return Err("broadcaster quote schedule mismatch".into());
            }
            let trust = Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: config.quote_signer,
            };
            invisi_sdk_rpc::broadcaster::verify_quote_for_provenance(
                quote.signed(),
                &trust,
                &data,
                chain.construction_timestamp(&block),
                relay.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            chain.canonical(&block)?;
            if let Some(reads) = retained_reads.clone() {
                candidate.preparation_reads = Some(reads);
            }
            candidate.broadcaster = Some(PreparedBroadcasterState {
                cancellation_token: cancellation_token.clone(),
                endpoint: config.endpoint,
                signer: config.quote_signer,
                fee_recipient: config.fee_recipient,
                quote: quote.signed().clone(),
                intent_hash: request_hash(&data).map_err(|e| e.to_string())?,
                sidecars: Vec::new(),
                attempted: false,
                submission_id: None,
                submitted_data: Vec::new(),
                member_proof: None,
            });
            return Ok(candidate);
        }
        Err("Credit relay fee convergence budget exceeded".into())
    }
    pub(crate) fn submit_for_broadcaster(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
        let state = self
            .broadcaster
            .as_ref()
            .ok_or("saved Credit relay context required")?;
        let config = relay.configuration();
        if config.endpoint != state.endpoint
            || config.quote_signer != state.signer
            || config.fee_recipient != state.fee_recipient
            || !state.sidecars.is_empty()
        {
            return Err("saved Credit relay context mismatch".into());
        }
        if state.attempted {
            let state = state.clone();
            journal::ManagedPrepared::Credit(self.clone())
                .snapshot()?
                .validate_broadcaster_submission(&state.submitted_data)?;
            let quote = VerifiedQuote::authenticate(
                state.quote.clone(),
                Trust {
                    chain_id: self.context.chain_id,
                    protocol: word_address(self.context.protocol_address)?,
                    signer: state.signer,
                },
                &state.submitted_data,
                0,
                state.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            if let Some(id) = &state.submission_id {
                let status = relay
                    .lookup_status(id)?
                    .ok_or("broadcaster submission not found; retain reservation")?;
                if &status.id != id {
                    return Err("broadcaster submission ID mismatch".into());
                }
                return Ok(status);
            }
            let result = relay.submit(&state.submitted_data, &quote, &[])?;
            if state
                .submission_id
                .as_ref()
                .is_some_and(|id| id != &result.id)
            {
                return Err("broadcaster submission ID mismatch".into());
            }
            self.broadcaster.as_mut().unwrap().submission_id = Some(result.id.clone());
            return Ok(result);
        }
        let data = self.calldata(chain, Address::ZERO)?.data;
        if request_hash(&data).map_err(|e| e.to_string())? != state.intent_hash {
            return Err("frozen Credit relay intent mismatch".into());
        }
        let block = chain.snapshot()?;
        let quote = VerifiedQuote::authenticate(
            state.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: state.signer,
            },
            &data,
            block.timestamp,
            state.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        relay.submission_requirements(&quote)?;
        chain.canonical(&block)?;
        let state = self.broadcaster.as_mut().unwrap();
        state.attempted = true;
        state.submitted_data = data.clone();
        let result = relay.submit(&data, &quote, &[])?;
        self.broadcaster.as_mut().unwrap().submission_id = Some(result.id.clone());
        Ok(result)
    }
}
