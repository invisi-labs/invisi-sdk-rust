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
            CreditPlan::Create { params, .. } => contract.call(&InvisiProtocol::createCreditCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Update { params, .. } => contract.call(&InvisiProtocol::updateCreditCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Draw { params, .. } => contract.call(&InvisiProtocol::creditDrawCall {
                _0: Bytes::new(),
                p: params.clone(),
                _2: self.deliveries.clone(),
            }),
            CreditPlan::Revoke {
                owner,
                token,
                shard,
                slot,
                deadline,
                fee,
                ..
            } => contract.call(&InvisiProtocol::revokeCreditCall {
                token: *token,
                owner: *owner,
                shard: *shard,
                slot: *slot,
                deadline: U256::from(*deadline),
                feeRecipient: fee.recipient,
                feeAmount: fee.amount,
                signature: Bytes::new(),
            }),
        })
    }
    pub fn with_broadcaster(
        &self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> Result<Self> {
        if options.max_fee_amount.is_none_or(|cap| cap == U256::ZERO) {
            return Err("positive maximum broadcaster fee required".into());
        }
        if self.phase != Phase::Prepared
            || chain.context() != self.context
            || options.max_fee_rounds == 0
        {
            return Err("Credit relay requires unsigned preparation and matching chain".into());
        }
        let config = relay.configuration();
        config.validate().map_err(|e| e.to_string())?;
        if let Some(cap) = &self.provenance {
            cap.validate(self.context, relay.provenance_mode())?;
        }
        let runtime = Invisi {
            chain: chain.clone(),
            provenance: self.provenance.clone(),
        };
        let template = self
            .reprice
            .as_ref()
            .ok_or("original Credit business preparation required for explicit repricing")?;
        let mut fee = invisi_sdk_rpc::broadcaster::Fee {
            fee_recipient: config.fee_recipient,
            fee_amount: "1".into(),
            max_gas: "1".into(),
        };
        for round in 0..options.max_fee_rounds {
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
                CreditRepriceTemplate::Create(state, deadline) => {
                    runtime.prepare_create_credit(&self.wallet, state.clone(), *deadline, f)?
                }
                CreditRepriceTemplate::Update(input, changes, deadline) => runtime
                    .prepare_update_credit(
                        &self.wallet,
                        input.clone(),
                        changes.clone(),
                        *deadline,
                        f,
                    )?,
                CreditRepriceTemplate::Draw(inputs, recipient, deadline, payload) => runtime
                    .prepare_draw_credit(
                        &self.wallet,
                        inputs.clone(),
                        recipient,
                        *deadline,
                        f,
                        payload.clone(),
                    )?,
                CreditRepriceTemplate::Revoke(token, shard, slot, deadline) => runtime
                    .prepare_revoke_credit(&self.wallet, *token, *shard, *slot, *deadline, f)?,
            };
            let data = candidate.broadcaster_intent()?.data;
            let next = relay.fee(self.token, Some(&data))?;
            if round == 0
                || next.fee_amount != fee.fee_amount
                || next.fee_recipient != fee.fee_recipient
            {
                fee = next;
                continue;
            }
            let block = chain.snapshot()?;
            let quote = relay.quote(
                &data,
                self.context.chain_id,
                word_address(self.context.protocol_address)?,
                block.timestamp,
                &[],
            )?;
            let trust = Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: config.quote_signer,
            };
            invisi_sdk_rpc::broadcaster::verify_quote_for_provenance(
                quote.signed(),
                &trust,
                &data,
                block.timestamp,
                relay.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            chain.canonical(&block)?;
            candidate.broadcaster = Some(PreparedBroadcasterState {
                endpoint: config.endpoint,
                signer: config.quote_signer,
                fee_recipient: config.fee_recipient,
                quote: quote.signed().clone(),
                intent_hash: request_hash(&data).map_err(|e| e.to_string())?,
                sidecars: Vec::new(),
                attempted: false,
                submission_id: None,
                submitted_data: Vec::new(),
            });
            return Ok(candidate);
        }
        Err("Credit relay fee convergence budget exceeded".into())
    }
    pub fn submit_broadcaster(
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
            if let Some(id) = &state.submission_id {
                if let Some(status) = relay.lookup_status(id)? {
                    if &status.id != id {
                        return Err("broadcaster submission ID mismatch".into());
                    }
                    return Ok(status);
                }
            }
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
