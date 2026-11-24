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
        if let Some(schedule) = &options.schedule {
            self.validate_usage_timestamp(schedule.publish_after)?;
            // execute_before is exclusive: equality with next midnight is safe.
            self.validate_usage_timestamp(schedule.execute_before.saturating_sub(1))?;
        }
        let config = relay.configuration();
        config.validate().map_err(|e| e.to_string())?;
        if let Some(cap) = &self.provenance {
            cap.validate(self.context, relay.provenance_mode())?;
        }
        if self.proof.is_some()
            || self.broadcaster.as_ref().is_some_and(|s| {
                s.attempted || s.submission_id.is_some() || !s.submitted_data.is_empty()
            })
        {
            return Err("cannot reprice an authorized or finalized Credit".into());
        }
        let now = self
            .quote_clock
            .ok_or("NEEDS_REPREPARATION: prepared Credit quote clock required")?
            .now()?;
        self.validate_usage_timestamp(now)?;
        let template = self
            .reprice
            .as_ref()
            .ok_or("NEEDS_REPREPARATION: original Credit business preparation required for explicit repricing")?;
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
        let initial = self.broadcaster_intent()?.data;
        let fee_lock = relay.lock_fee(
            &initial,
            self.context.chain_id,
            word_address(self.context.protocol_address)?,
            now,
        )?;
        let mut fee = relay.locked_scheduled_fee(
            self.token,
            Some(&self.broadcaster_intent()?.data),
            schedule.as_ref(),
            fee_lock.as_ref(),
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
            let mut candidate = self.reprice_credit(template, f)?;
            let data = candidate.broadcaster_intent()?.data;
            let next = relay.locked_scheduled_fee(
                self.token,
                Some(&data),
                schedule.as_ref(),
                fee_lock.as_ref(),
            )?;
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
            let quote = relay.locked_scheduled_quote(
                &data,
                self.context.chain_id,
                word_address(self.context.protocol_address)?,
                now,
                &[],
                schedule.as_ref(),
                fee_lock.as_ref(),
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
                now,
                relay.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            candidate.broadcaster = Some(PreparedBroadcasterState {
                cancellation_token: cancellation_token.clone(),
                endpoint: config.endpoint,
                signer: config.quote_signer,
                fee_recipient: config.fee_recipient,
                quote: quote.signed().clone(),
                intent_hash: request_hash(&data).map_err(|e| e.to_string())?,
                sidecars: Vec::new(),
                attempted: false,
                pre_send_refusal: None,
                submission_id: None,
                submitted_data: Vec::new(),
                member_proof: None,
            });
            return Ok(candidate);
        }
        Err("Credit relay fee convergence budget exceeded".into())
    }
    fn reprice_credit(&self, original: &CreditRepriceTemplate, fee: Fee) -> Result<Self> {
        let mut candidate = self.clone();
        let require_capacity = |amount: U256| {
            if self.fee_capacity.is_some_and(|cap| amount <= cap) {
                Ok(())
            } else {
                Err(
                    "NEEDS_REPREPARATION: prepare Credit with a sufficient gross fee budget"
                        .to_owned(),
                )
            }
        };
        let resize =
            |output: &NoteOutput, amount: U256, keys: &ReceivingKeys| -> Result<NoteOutput> {
                if amount == U256::ZERO {
                    return Err("Credit fee must leave a positive Note".into());
                }
                if output.amount == amount {
                    return Ok(output.clone());
                }
                let mut opening = output
                    .note
                    .clone()
                    .ok_or("NEEDS_REPREPARATION: Credit payment Note opening required")?;
                opening.amount = amount;
                NoteOutput::from_note(opening, Some(keys))
            };
        match (&mut candidate.plan, original) {
            (
                CreditPlan::Create {
                    params,
                    created,
                    initial_payment,
                },
                CreditRepriceTemplate::Create(initial, payment),
            ) => {
                if let (Some((_, output)), Some(payment)) = (initial_payment, payment) {
                    let gross = match payment.net_amount {
                        Some(net) => net
                            .checked_add(fee.amount)
                            .ok_or("initial payment gross overflow")?,
                        None => payment.amount,
                    };
                    model(crate::note::uint(gross, 126, "initial payment"))?;
                    let net = gross
                        .checked_sub(fee.amount)
                        .ok_or("initial payment must leave a positive Note")?;
                    require_capacity(gross)?;
                    if gross != params.totalAmount {
                        created.note = model(crate::credit::apply_credit_draw_usage(
                            &initial.note,
                            gross,
                            self.constructed_at,
                        ))?;
                        params.creditCommitment = field_word(model(created.note.commitment())?);
                        candidate.deliveries = credit::credit_deliveries(created)?;
                    } else {
                        candidate.deliveries.truncate(2);
                    }
                    *output = resize(output, net, &created.spender_receiving_keys)?;
                    params.totalAmount = gross;
                    params.noteCommitment = output.commitment;
                    candidate.deliveries.push(output.delivery.clone());
                } else {
                    require_capacity(fee.amount)?;
                }
                params.feeRecipient = fee.recipient;
                params.feeAmount = fee.amount;
            }
            (CreditPlan::Update { params, .. }, CreditRepriceTemplate::Update) => {
                require_capacity(fee.amount)?;
                params.feeRecipient = fee.recipient;
                params.feeAmount = fee.amount;
            }
            (CreditPlan::Draw { params, output, .. }, CreditRepriceTemplate::Draw(recipient)) => {
                let net = params
                    .totalAmount
                    .checked_sub(fee.amount)
                    .ok_or("draw fee exceeds gross payment")?;
                *output = resize(output, net, &recipient.receiving_keys)?;
                params.noteCommitment = output.commitment;
                *candidate
                    .deliveries
                    .last_mut()
                    .ok_or("missing Credit draw delivery")? = output.delivery.clone();
                params.feeRecipient = fee.recipient;
                params.feeAmount = fee.amount;
            }
            (
                CreditPlan::Revoke {
                    fee: current,
                    signature,
                    ..
                },
                CreditRepriceTemplate::Revoke,
            ) => {
                if !signature.is_empty() {
                    return Err("cannot reprice signed Credit revocation".into());
                }
                require_capacity(fee.amount)?;
                *current = fee;
            }
            _ => return Err("inconsistent Credit repricing template".into()),
        }
        Ok(candidate)
    }
    pub fn finalize_broadcaster(&mut self) -> Result<()> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved Credit relay context required")?;
        if saved.attempted || saved.submission_id.is_some() || saved.pre_send_refusal.is_some() {
            return Err("cannot finalize an attempted or retired Credit packet".into());
        }
        match &self.plan {
            CreditPlan::Revoke { signature, .. } if !signature.is_empty() => {}
            CreditPlan::Revoke { .. } => {
                return Err("revocation signature required before finalization".into())
            }
            _ if self.phase == Phase::Proved && self.proof.is_some() => {}
            _ => return Err("verified Credit proof required before finalization".into()),
        }
        let packet = journal::ManagedPrepared::Credit(self.clone())
            .snapshot()?
            .export_broadcaster_submission()?;
        if request_hash(&packet.data).map_err(|e| e.to_string())? != saved.intent_hash {
            return Err("frozen Credit relay intent mismatch".into());
        }
        VerifiedQuote::authenticate(
            saved.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: saved.signer,
            },
            &packet.data,
            0,
            saved.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        self.broadcaster.as_mut().unwrap().submitted_data = packet.data;
        Ok(())
    }
    pub(crate) fn submit_for_broadcaster(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
        self.submit_broadcaster_with_fence(chain, relay, &|network| network())
    }
    #[doc(hidden)]
    pub fn submit_broadcaster_with_fence(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
        fence: &SubmissionFence<'_>,
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
        if state.attempted || state.submission_id.is_some() {
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
        if let Some(reason) = &state.pre_send_refusal {
            return Err(format!("{reason}: Broadcaster refused before acceptance; abandon and prepare a fresh request"));
        }
        if state.submitted_data.is_empty() {
            return Err("FINALIZATION_REQUIRED: finalize Credit packet before submission".into());
        }
        self.validate_usage_period(chain)?;
        let data = self.calldata(chain, Address::ZERO)?.data;
        if state.submitted_data != data
            || request_hash(&data).map_err(|e| e.to_string())? != state.intent_hash
        {
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
        if relay.submission_requirements(&quote)?
            != (quote.signed().provenance_required == Some(true))
        {
            return Err("broadcaster provenance requirements changed".into());
        }
        chain.canonical(&block)?;
        self.validate_usage_period(chain)?;
        fence(&|| chain.validate_submission_network())?;
        let state = self.broadcaster.as_mut().unwrap();
        state.attempted = true;
        let result = match relay.submit_classified(&data, &quote, &[]) {
            Ok(status) => status,
            Err(error) => {
                if let Some(reason) = error.pre_send_refusal() {
                    let saved = self.broadcaster.as_mut().unwrap();
                    if saved.submission_id.is_none() {
                        // Keep exact frozen evidence for journal validation while
                        // restoring the live preflight gate for this known-unsent request.
                        saved.attempted = false;
                        saved.pre_send_refusal = Some(reason.into());
                        return Err(format!("{reason}: Broadcaster refused before acceptance; reauthorize and regenerate proof"));
                    }
                }
                return Err(error.to_string());
            }
        };
        self.broadcaster.as_mut().unwrap().submission_id = Some(result.id.clone());
        Ok(result)
    }
}
