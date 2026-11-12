use super::*;
use crate::{
    prover::Prover,
    sdk::{
        CreditInput, Phase, ShieldPreparation, TransferPreparation, WalletRequest, WalletResponse,
    },
};
use std::collections::BTreeSet;

pub struct Operation {
    session: WalletSession,
    id: String,
    generation: u64,
    prepared: ManagedPrepared,
    requests: BTreeMap<String, WalletRequest>,
}
pub(super) fn record_matches_transaction_data(record: &OperationRecord, data: &[u8]) -> bool {
    let Some(call) = &record.call else {
        return false;
    };
    if record.broadcaster_id.is_some() {
        if record
            .snapshot
            .validate_broadcaster_submission(&call.data)
            .is_err()
        {
            return false;
        }
        if let Some(execution) = record.snapshot.broadcaster_execution() {
            return crate::broadcaster::matches_execution_transaction(&call.data, execution, data);
        }
    }
    data == call.data
}
fn bind_provenance_call(
    record: &OperationRecord,
    value: sdk::PreparedTransaction,
) -> Result<sdk::PreparedTransaction> {
    let saved = record.snapshot.provenance_calldata()?;
    let data = if let Some(call) = &record.call {
        if saved.as_ref().is_some_and(|data| data != &call.data) {
            return Err("saved provenance final calldata mismatch".into());
        }
        Some(call.data.clone())
    } else {
        saved
    };
    match data {
        Some(data) => value.with_provenance_calldata(data),
        None => Ok(value),
    }
}
impl std::fmt::Debug for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Operation")
            .field("id", &self.id)
            .field("phase", &self.prepared.phase())
            .finish_non_exhaustive()
    }
}
impl Operation {
    /// Observe the recorded transaction without releasing reservations or changing operation state.
    pub fn confirmation(&self) -> Result<crate::rpc::TransactionConfirmation> {
        let state = self.session.snapshot()?;
        if self.session.invisi.chain.context() != self.session.scope.context {
            return Err("chain deployment mismatch".into());
        }
        let record = state
            .operations
            .get(&self.id)
            .ok_or("operation not found")?;
        match record.transaction_hash {
            Some(hash) => {
                if hash == B256::ZERO {
                    return Err("nonzero transaction hash required".into());
                }
                self.session.invisi.chain.snapshot()?;
                self.session.invisi.chain.transaction_confirmation(hash)
            }
            None => Ok(crate::rpc::TransactionConfirmation {
                level: crate::rpc::ConfirmationLevel::Pending,
                status: crate::rpc::FinalityStatus::Available,
                block: None,
            }),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn phase(&self) -> Phase {
        self.prepared.phase()
    }
    fn current(&self) -> Result<WalletState> {
        let state = self.session.snapshot()?;
        let record = state
            .operations
            .get(&self.id)
            .ok_or("operation not found")?;
        if record.generation != self.generation {
            return Err("stale operation handle".into());
        }
        if record.status.terminal() {
            return Err("operation is terminal".into());
        }
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        Ok(state)
    }
    fn persist(mut self, prepared: ManagedPrepared) -> Result<Self> {
        let mut state = self.current()?;
        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        record.snapshot = prepared.snapshot()?;
        if !record.externalized {
            record.status = phase_status(prepared.phase());
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        self.generation = record.generation;
        self.session.commit(state)?;
        self.prepared = prepared;
        self.requests.clear();
        Ok(self)
    }
    pub fn broadcaster_state(&self) -> Option<&sdk::PreparedBroadcasterState> {
        match &self.prepared {
            ManagedPrepared::Funds(v) => v.broadcaster_state(),
            ManagedPrepared::Credit(v) => v.broadcaster_state(),
        }
    }
    pub fn with_broadcaster(
        &mut self,
        relay: Arc<dyn sdk::PreparedBroadcaster>,
        options: &sdk::BroadcasterOptions,
    ) -> Result<()> {
        let mut state = self.current()?;
        if state.operations[&self.id].externalized {
            return Err("cannot reprice an externalized operation".into());
        }
        let prepared = match &self.prepared {
            ManagedPrepared::Funds(v) => ManagedPrepared::Funds(v.with_broadcaster(
                self.session.invisi.chain.clone(),
                relay,
                options,
            )?),
            ManagedPrepared::Credit(v) => ManagedPrepared::Credit(v.with_broadcaster(
                self.session.invisi.chain.clone(),
                relay,
                options,
            )?),
        };
        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        record.snapshot = prepared.snapshot()?;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        let generation = record.generation;
        self.session.commit(state)?;
        self.generation = generation;
        self.prepared = prepared;
        self.requests.clear();
        Ok(())
    }
    pub fn submit_broadcaster(
        &mut self,
        relay: &dyn sdk::PreparedBroadcaster,
    ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
        let local_id = self.id.clone();
        let id = local_id.as_str();
        let attempted = self
            .current()?
            .operations
            .get(&self.id)
            .ok_or("operation not found")?
            .broadcaster_id
            .is_some();
        if !attempted {
            match &mut self.prepared {
                ManagedPrepared::Funds(v) => {
                    v.freeze_broadcaster_evidence(self.session.invisi.chain.as_ref(), relay)?
                }
                ManagedPrepared::Credit(v) => {
                    let saved = v
                        .broadcaster_state()
                        .ok_or("saved broadcaster context required")?;
                    let call = v.calldata(self.session.invisi.chain.as_ref(), Address::ZERO)?;
                    let quote = crate::broadcaster::VerifiedQuote::authenticate(
                        saved.quote.clone(),
                        crate::broadcaster::Trust {
                            chain_id: self.session.scope.context.chain_id,
                            protocol: call.to,
                            signer: saved.signer,
                        },
                        &call.data,
                        0,
                        saved.provenance_mode(),
                    )
                    .map_err(|e| e.to_string())?;
                    relay.submission_requirements(&quote)?;
                }
            }
        }
        let mut state = self.current()?;
        let record = state
            .operations
            .get(&self.id)
            .ok_or("operation not found")?;
        let saved = self
            .broadcaster_state()
            .ok_or("saved broadcaster context required")?;
        let config = relay.configuration();
        if saved.endpoint != config.endpoint
            || saved.signer != config.quote_signer
            || saved.fee_recipient != config.fee_recipient
        {
            return Err("saved broadcaster configuration mismatch".into());
        }
        if let Some(original) = &record.broadcaster_id {
            if original != id {
                return Err("broadcaster retry ID differs from frozen submission".into());
            }
            let call = record
                .call
                .as_ref()
                .ok_or("saved broadcaster calldata required")?;
            record
                .snapshot
                .validate_broadcaster_submission(&call.data)?;
            if crate::broadcaster::request_hash(&call.data).map_err(|e| e.to_string())?
                != saved.intent_hash
                || sdk::address_word(call.to) != self.session.scope.context.protocol_address
                || call.value != U256::ZERO
            {
                return Err("saved broadcaster calldata mismatch".into());
            }
            crate::broadcaster::verify_quote_for_provenance(
                &saved.quote,
                &crate::broadcaster::Trust {
                    chain_id: self.session.scope.context.chain_id,
                    protocol: call.to,
                    signer: saved.signer,
                },
                &call.data,
                0,
                saved.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            if let Some(submission_id) = record.broadcaster_submission_id.as_deref() {
                let status = relay
                    .lookup_status(submission_id)?
                    .ok_or("broadcaster submission not found; retain reservation")?;
                if status.id != submission_id {
                    return Err("broadcaster status ID mismatch".into());
                }
                if let Some(hash) = status.transaction_hash {
                    self.track_transaction(hash)?;
                }
                return Ok(status);
            }
            let verified = crate::broadcaster::VerifiedQuote::authenticate(
                saved.quote.clone(),
                crate::broadcaster::Trust {
                    chain_id: self.session.scope.context.chain_id,
                    protocol: call.to,
                    signer: saved.signer,
                },
                &call.data,
                0,
                saved.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            let status = relay.submit_member(
                &call.data,
                &verified,
                &saved.sidecars,
                saved.member_proof.as_ref(),
            )?;
            if record
                .broadcaster_submission_id
                .as_ref()
                .is_some_and(|id| id != &status.id)
            {
                return Err("broadcaster submission ID mismatch".into());
            }
            let mut next = self.current()?;
            next.operations
                .get_mut(&self.id)
                .ok_or("operation not found")?
                .broadcaster_submission_id = Some(status.id.clone());
            self.session.commit(next)?;
            if let Some(hash) = status.transaction_hash {
                self.track_transaction(hash)?;
            }
            return Ok(status);
        }
        let call = match &self.prepared {
            ManagedPrepared::Funds(v) => crate::protocol::TransactionCall {
                to: sdk::word_address(self.session.scope.context.protocol_address)?,
                value: U256::ZERO,
                data: v.export_broadcaster_submission()?.data,
            },
            ManagedPrepared::Credit(v) => {
                v.calldata(self.session.invisi.chain.as_ref(), Address::ZERO)?
            }
        };
        let stored = StoredCall::from(call);
        if crate::broadcaster::request_hash(&stored.data).map_err(|e| e.to_string())?
            != saved.intent_hash
            || sdk::address_word(stored.to) != self.session.scope.context.protocol_address
            || stored.value != U256::ZERO
        {
            return Err("frozen broadcaster intent mismatch".into());
        }
        crate::broadcaster::verify_quote_for_provenance(
            &saved.quote,
            &crate::broadcaster::Trust {
                chain_id: self.session.scope.context.chain_id,
                protocol: stored.to,
                signer: saved.signer,
            },
            &stored.data,
            0,
            saved.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;

        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        if record
            .call
            .as_ref()
            .is_some_and(|previous| previous != &stored)
        {
            return Err("recovered broadcaster calldata differs from frozen transaction".into());
        }
        record.snapshot = self.prepared.snapshot()?;
        record.call = Some(stored);
        record.externalized = true;
        record.broadcaster_id = Some(id.into());
        if record.transaction_hash.is_none() {
            record.status = OperationStatus::Exported;
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        let generation = record.generation;
        self.session.commit(state)?;
        self.generation = generation;
        let status = match &mut self.prepared {
            ManagedPrepared::Funds(v) => {
                v.submit_broadcaster(self.session.invisi.chain.as_ref(), relay)
            }
            ManagedPrepared::Credit(v) => {
                v.submit_broadcaster(self.session.invisi.chain.as_ref(), relay)
            }
        }?;
        let mut next = self.current()?;
        next.operations
            .get_mut(&self.id)
            .ok_or("operation not found")?
            .broadcaster_submission_id = Some(status.id.clone());
        self.session.commit(next)?;
        if let Some(hash) = status.transaction_hash {
            self.track_transaction(hash)?;
        }
        Ok(status)
    }
    pub fn export_wallet_authorization(&self) -> Result<sdk::EvmSigningRequest> {
        self.current()?;
        match &self.prepared {
            ManagedPrepared::Funds(v) => v.export_wallet_authorization(),
            ManagedPrepared::Credit(v) => v.export_wallet_authorization(),
        }
    }
    pub fn with_wallet_signature(self, signature: &[u8]) -> Result<Self> {
        self.current()?;
        let prepared = match self.prepared.clone_for_stage() {
            ManagedPrepared::Funds(v) => {
                ManagedPrepared::Funds(v.with_wallet_signature(signature)?)
            }
            ManagedPrepared::Credit(v) => {
                ManagedPrepared::Credit(v.with_wallet_signature(signature)?)
            }
        };
        self.persist(prepared)
    }
    pub fn export_wallet_request(&mut self, id: impl Into<String>) -> Result<WalletRequest> {
        self.current()?;
        let id = id.into();
        if self.requests.contains_key(&id) {
            return Err("wallet request id already exported".into());
        }
        let request = match &self.prepared {
            ManagedPrepared::Funds(v) => v.export_wallet_request(id)?,
            ManagedPrepared::Credit(v) => v.export_wallet_request(id)?,
        };
        self.requests.insert(request.id.clone(), request.clone());
        Ok(request)
    }
    pub fn with_wallet_response(self, response: &WalletResponse) -> Result<Self> {
        self.current()?;
        let request = self
            .requests
            .get(&response.id)
            .ok_or("unknown operation wallet response id")?
            .clone();
        let prepared = self
            .prepared
            .clone_for_stage()
            .with_wallet_response(&request, response)?;
        self.persist(prepared)
    }
    pub fn export_provenance_proof(&self) -> Result<Option<sdk::ProvenanceProof>> {
        self.session.recover_provenance_proof(&self.id)
    }
    pub fn prove_provenance(&mut self) -> Result<sdk::ProvenanceProof> {
        self.prove_provenance_inner(false)
    }
    pub fn reprove_provenance(&mut self) -> Result<sdk::ProvenanceProof> {
        self.prove_provenance_inner(true)
    }
    fn prove_provenance_inner(&mut self, reprove: bool) -> Result<sdk::ProvenanceProof> {
        // Cached public evidence remains useful after the operation is consumed.
        if !reprove {
            if let Some(packet) = self.export_provenance_proof()? {
                return Ok(packet);
            }
        }
        let mut state = self.session.snapshot()?;
        let record = state
            .operations
            .get(&self.id)
            .ok_or("operation not found")?;
        if record.generation != self.generation {
            return Err("stale operation handle".into());
        }
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let staged = match self.prepared.clone_for_stage() {
            ManagedPrepared::Funds(value) => {
                ManagedPrepared::Funds(bind_provenance_call(record, value)?)
            }
            other => other,
        };
        let packet = match &staged {
            ManagedPrepared::Funds(v) => {
                if reprove {
                    v.reprove_provenance(&*self.session.invisi.chain)?
                } else {
                    v.prove_provenance(&*self.session.invisi.chain)?
                }
            }
            ManagedPrepared::Credit(_) => return Err("private Note transaction required".into()),
        };
        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        record.snapshot.update_provenance_proof(&staged)?;
        self.session.commit(state)?;
        self.prepared = staged;
        Ok(packet)
    }
    pub fn prove(self, backend: &dyn Prover, recursive: impl Into<Option<bool>>) -> Result<Self> {
        self.current()?;
        let prepared = self.prepared.clone_for_stage().prove(backend, recursive)?;
        self.persist(prepared)
    }
    pub fn ready(self) -> Result<Self> {
        self.current()?;
        let prepared = self.prepared.clone_for_stage().ready()?;
        self.persist(prepared)
    }
    pub fn with_revocation_signature(self, signature: Vec<u8>) -> Result<Self> {
        self.current()?;
        let prepared = self
            .prepared
            .clone_for_stage()
            .with_revocation_signature(&*self.session.invisi.chain, signature)?;
        self.persist(prepared)
    }
    pub fn export_revocation_signing_request(&self) -> Result<sdk::EvmSigningRequest> {
        self.current()?;
        match &self.prepared {
            ManagedPrepared::Credit(v) => v.export_revocation_signing_request(),
            _ => Err("Credit revocation operation required".into()),
        }
    }
    pub fn export_revocation_authorization(&self) -> Result<serde_json::Value> {
        self.current()?;
        match &self.prepared {
            ManagedPrepared::Credit(v) => v.export_revocation_authorization(),
            _ => Err("revocation operation required".into()),
        }
    }
    pub fn with_funding_terms(self, deadline: u64) -> Result<Self> {
        self.current()?;
        let prepared = self
            .prepared
            .clone_for_stage()
            .with_funding_terms(&*self.session.invisi.chain, deadline)?;
        self.persist(prepared)
    }
    pub fn export_funding_authorization(&self) -> Result<sdk::EvmSigningRequest> {
        self.current()?;
        self.prepared
            .export_funding_authorization(&*self.session.invisi.chain)
    }
    pub fn with_funding_signature(self, signature: Vec<u8>) -> Result<Self> {
        self.current()?;
        let prepared = self
            .prepared
            .clone_for_stage()
            .with_funding_signature(&*self.session.invisi.chain, signature)?;
        self.persist(prepared)
    }
    /// Exporting final calldata is irreversible from the journal's perspective until chain reconciliation.
    pub fn calldata(&mut self, caller: Address) -> Result<crate::protocol::TransactionCall> {
        let mut state = self.current()?;
        let call = match &self.prepared {
            ManagedPrepared::Funds(v) => v.calldata(&*self.session.invisi.chain, caller)?,
            ManagedPrepared::Credit(v) => v.calldata(&*self.session.invisi.chain, caller)?,
        };
        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        let stored = StoredCall::from(call.clone());
        if record
            .call
            .as_ref()
            .is_some_and(|previous| previous != &stored)
        {
            return Err("recovered calldata differs from exported transaction".into());
        }
        record.snapshot = self.prepared.snapshot()?;
        record.call = Some(stored);
        record.externalized = true;
        if record.transaction_hash.is_none() {
            record.status = OperationStatus::Exported;
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        self.generation = record.generation;
        self.session.commit(state)?;
        Ok(call)
    }

    /// Estimate the prepared workload locally without exporting or changing wallet state.
    pub fn estimate_gas(&self) -> Result<invisi_sdk_protocol::gas::GasEstimate> {
        match &self.prepared {
            ManagedPrepared::Funds(v) => v.estimate_gas(),
            ManagedPrepared::Credit(v) => v.estimate_gas(),
        }
    }
    pub fn track_transaction(&mut self, hash: B256) -> Result<()> {
        if hash == B256::ZERO {
            return Err("nonzero transaction hash required".into());
        }
        let mut state = self.current()?;
        let record = state
            .operations
            .get_mut(&self.id)
            .ok_or("operation not found")?;
        if !record.externalized || record.call.is_none() {
            return Err("export final calldata before tracking a transaction".into());
        }
        if record
            .transaction_hash
            .is_some_and(|previous| previous != hash)
        {
            return Err("operation already tracks another transaction".into());
        }
        record.transaction_hash = Some(hash);
        record.status = OperationStatus::Submitted;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        self.generation = record.generation;
        self.session.commit(state)
    }
    fn export_aggregate_member(&self) -> Result<crate::prover::AggregateMember> {
        self.current()?;
        match &self.prepared {
            ManagedPrepared::Funds(v) => v.export_aggregate_member(),
            _ => Err("only recursive funds transfers can be aggregated".into()),
        }
    }
    fn recursive_transaction(&self) -> Result<sdk::PreparedTransaction> {
        self.export_aggregate_member()?;
        match self.prepared.clone_for_stage() {
            ManagedPrepared::Funds(v) => Ok(v),
            _ => Err("funds transfer required".into()),
        }
    }
    pub fn cancel(self) -> Result<()> {
        self.session
            .cancel_operation(&self.id, Some(self.generation))
    }
}
fn phase_status(phase: Phase) -> OperationStatus {
    match phase {
        Phase::Prepared => OperationStatus::Prepared,
        Phase::Authorized => OperationStatus::Authorized,
        Phase::Proved => OperationStatus::Proved,
        Phase::Ready => OperationStatus::Ready,
        Phase::Exported => OperationStatus::Exported,
    }
}
impl WalletSession {
    pub fn register(&self, prepared: ManagedPrepared) -> Result<Operation> {
        if prepared.owner_address() != self.wallet.owner_address()
            || prepared
                .wallet()
                .is_some_and(|wallet| wallet != &self.wallet)
        {
            return Err("operation wallet differs from session".into());
        }
        let snapshot = prepared.snapshot()?;
        if snapshot.context() != self.scope.context {
            return Err("operation deployment differs from session".into());
        }
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let inputs = prepared.input_ids()?;
        let mut unique = BTreeSet::new();
        for input in &inputs {
            if !unique.insert(input) {
                return Err("duplicate reserved input".into());
            }
            reserve(&mut state, input, &id)?;
        }
        let (kind, deadline) = prepared.kind_deadline()?;
        state.operations.insert(
            id.clone(),
            OperationRecord {
                id: id.clone(),
                kind,
                status: phase_status(prepared.phase()),
                generation: 0,
                inputs,
                deadline,
                snapshot,
                transaction_hash: None,
                call: None,
                externalized: false,
                broadcaster_id: None,
                broadcaster_submission_id: None,
                resolved_at: None,
            },
        );
        self.commit(state)?;
        Ok(Operation {
            session: self.clone(),
            id,
            generation: 0,
            prepared,
            requests: BTreeMap::new(),
        })
    }
    pub fn prepare_transfer(&self, mut options: TransferPreparation) -> Result<Operation> {
        if options.inputs.is_empty() {
            let state = self.snapshot()?;
            if state.invalidated {
                return Err("wallet requires canonical resync".into());
            }
            let mut needed =
                options
                    .outputs
                    .iter()
                    .try_fold(options.fee.amount, |total, output| {
                        total
                            .checked_add(output.amount())
                            .ok_or("selection amount overflow")
                    })?;
            if let Some((_, amount)) = options.withdrawal {
                needed = needed
                    .checked_add(amount)
                    .ok_or("selection amount overflow")?;
            }
            needed = needed.saturating_sub(options.funding.amount);
            let mut candidates = state
                .notes
                .values()
                .filter(|v| {
                    !v.spent
                        && v.reserved_by.is_none()
                        && v.input.note.token_address == sdk::address_word(options.token)
                })
                .collect::<Vec<_>>();
            candidates.sort_by_key(|v| (v.input.note.amount, v.commitment));
            let mut selected = U256::ZERO;
            for note in candidates {
                if selected >= needed {
                    break;
                }
                selected = selected
                    .checked_add(note.input.note.amount)
                    .ok_or("selection overflow")?;
                options.inputs.push(note.input.clone());
            }
            if selected < needed {
                return Err("insufficient unreserved known Note balance".into());
            }
        }
        self.register(ManagedPrepared::Funds(
            self.invisi.prepare_transfer(&self.wallet, options)?,
        ))
    }
    pub fn prepare_shield(&self, options: ShieldPreparation) -> Result<Operation> {
        self.register(ManagedPrepared::Funds(
            self.invisi.prepare_shield(&self.wallet, options)?,
        ))
    }
    pub fn prepare_create_credit(
        &self,
        state: CreditDeliveryState,
        deadline: u64,
        fee: sdk::Fee,
    ) -> Result<Operation> {
        self.register(ManagedPrepared::Credit(self.invisi.prepare_create_credit(
            &self.wallet,
            state,
            deadline,
            fee,
        )?))
    }
    pub fn prepare_update_credit(
        &self,
        key: &str,
        changes: crate::credit::CreditUpdateChanges,
        deadline: u64,
        fee: sdk::Fee,
    ) -> Result<Operation> {
        let state = self.snapshot()?;
        let credit = state.credits.get(key).ok_or("Credit input not found")?;
        if credit.role != CreditRole::Owner
            || credit.consumed
            || credit.revoked
            || credit.reserved_by.is_some()
        {
            return Err("Credit input is unavailable for owner update".into());
        }
        let input = credit_input(credit, U256::ZERO);
        self.register(ManagedPrepared::Credit(self.invisi.prepare_update_credit(
            &self.wallet,
            input,
            changes,
            deadline,
            fee,
        )?))
    }
    pub fn prepare_draw_credit(
        &self,
        selections: &[(String, U256)],
        recipient: &Wallet,
        deadline: u64,
        fee: sdk::Fee,
        payload: Vec<u8>,
    ) -> Result<Operation> {
        let state = self.snapshot()?;
        let mut inputs = Vec::new();
        for (key, debit) in selections {
            let credit = state.credits.get(key).ok_or("Credit input not found")?;
            if credit.role != CreditRole::Spender
                || credit.consumed
                || credit.revoked
                || credit.reserved_by.is_some()
            {
                return Err("Credit input is unavailable for spender draw".into());
            }
            inputs.push(credit_input(credit, *debit));
        }
        self.register(ManagedPrepared::Credit(self.invisi.prepare_draw_credit(
            &self.wallet,
            inputs,
            recipient,
            deadline,
            fee,
            payload,
        )?))
    }
    pub fn prepare_revoke_credit(
        &self,
        token: Address,
        shard: u64,
        slot: u16,
        deadline: u64,
        fee: sdk::Fee,
    ) -> Result<Operation> {
        self.register(ManagedPrepared::Credit(self.invisi.prepare_revoke_credit(
            self.wallet.owner_address(),
            token,
            shard,
            slot,
            deadline,
            fee,
        )?))
    }
    /// Recovers the public proof packet, including for completed operations, without resuming spending.
    pub fn recover_provenance_proof(&self, id: &str) -> Result<Option<sdk::ProvenanceProof>> {
        let state = self.snapshot()?;
        let record = state.operations.get(id).ok_or("operation not found")?;
        let prepared = record.snapshot.restore(&self.wallet, None)?;
        match prepared {
            ManagedPrepared::Funds(v) => {
                let cap = self
                    .invisi
                    .provenance
                    .clone()
                    .ok_or("trusted provenance capability required")?;
                bind_provenance_call(record, v)?
                    .reattach_provenance(cap)?
                    .export_provenance_proof()
            }
            ManagedPrepared::Credit(_) => Err("private Note transaction required".into()),
        }
    }
    /// Refreshes Source evidence after restart while preserving terminal payment state.
    pub fn reprove_provenance_proof(&self, id: &str) -> Result<sdk::ProvenanceProof> {
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let record = state.operations.get_mut(id).ok_or("operation not found")?;
        let prepared = record.snapshot.restore(&self.wallet, None)?;
        let ManagedPrepared::Funds(value) = prepared else {
            return Err("private Note transaction required".into());
        };
        let cap = self
            .invisi
            .provenance
            .clone()
            .ok_or("trusted provenance capability required")?;
        let value = bind_provenance_call(record, value)?.reattach_provenance(cap)?;
        let packet = value.reprove_provenance(&*self.invisi.chain)?;
        record
            .snapshot
            .update_provenance_proof(&ManagedPrepared::Funds(value))?;
        self.commit(state)?;
        Ok(packet)
    }
    pub fn resume(&self, id: &str, backend: Option<&dyn Prover>) -> Result<Operation> {
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let record = state.operations.get_mut(id).ok_or("operation not found")?;
        if record.status.terminal() {
            return Err("cannot resume a terminal operation".into());
        }
        if record.snapshot.context() != self.scope.context {
            return Err("saved operation deployment mismatch".into());
        }
        let mut prepared = record.snapshot.restore(&self.wallet, backend)?;
        if let Some(cap) = &self.invisi.provenance {
            match &mut prepared {
                ManagedPrepared::Funds(v) => *v = v.clone().reattach_provenance(cap.clone())?,
                ManagedPrepared::Credit(v) => *v = v.clone().reattach_provenance(cap.clone())?,
            }
        }
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        let generation = record.generation;
        if !record.externalized {
            record.status = phase_status(prepared.phase());
            record.snapshot = prepared.snapshot()?;
        }
        self.commit(state)?;
        Ok(Operation {
            session: self.clone(),
            id: id.into(),
            generation,
            prepared,
            requests: BTreeMap::new(),
        })
    }
    pub fn cancel_operation(&self, id: &str, generation: Option<u64>) -> Result<()> {
        let mut state = self.snapshot()?;
        let record = state.operations.get_mut(id).ok_or("operation not found")?;
        if generation.is_some_and(|v| v != record.generation) {
            return Err("stale operation handle".into());
        }
        if record.externalized || record.transaction_hash.is_some() {
            return Err(
                "exported operation requires canonical reconciliation before release".into(),
            );
        }
        if record.status.terminal() {
            return Err("operation is already terminal".into());
        }
        record.status = OperationStatus::Cancelled;
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        super::sync::release_inputs(&mut state, id);
        self.commit(state)
    }
    pub fn reconcile(&self, id: &str) -> Result<Reconciliation> {
        let base = self.snapshot()?;
        let record = base.operations.get(id).ok_or("operation not found")?;
        if record.status.terminal() {
            return Err("operation is already terminal".into());
        }
        let hash = record
            .transaction_hash
            .ok_or("operation has no tracked transaction")?;
        let Some(receipt) = self.source.receipt(hash)? else {
            return Ok(Reconciliation::Pending);
        };
        let transaction = self
            .source
            .transaction(hash)?
            .ok_or("canonical transaction missing")?;
        let call = record
            .call
            .as_ref()
            .ok_or("exported calldata unavailable")?;
        if receipt.transaction_hash != hash
            || transaction.hash != hash
            || transaction.to != Some(call.to)
            || !record_matches_transaction_data(record, &transaction.input)
            || transaction.value != call.value
            || transaction.chain_id != self.scope.context.chain_id
            || transaction.block.as_ref() != Some(&receipt.block)
        {
            return Err("tracked transaction does not match exported operation".into());
        }
        self.invisi.chain.canonical(&receipt.block)?;
        let number = base
            .observed_through
            .as_ref()
            .map_or(receipt.block.number, |b| b.number.max(receipt.block.number));
        let anchor = self.source.block(number)?;
        let generation = record.generation;
        let success = receipt.success;
        use alloy_sol_types::SolCall;
        let aggregate = call.data.get(..4)
            == Some(crate::protocol::InvisiProtocol::transact_1Call::SELECTOR.as_slice());
        let completions = if aggregate {
            base.operations
                .values()
                .filter(|other| {
                    !other.status.terminal()
                        && other.transaction_hash == Some(hash)
                        && other.call.as_ref() == Some(call)
                })
                .map(|other| (other.id.clone(), other.generation, success))
                .collect()
        } else {
            vec![(id.into(), generation, success)]
        };
        Ok(Reconciliation::Ready(self.stage_refresh(
            base,
            anchor,
            vec![receipt],
            RefreshOptions {
                from_block: number,
                to_block: Some(number),
                page_size: 10000,
                reset: false,
            },
            Some(completions),
        )?))
    }
    /// Aggregate same-session members and atomically externalize every journal record before returning calldata.
    pub fn aggregate(
        &self,
        backend: &dyn Prover,
        operations: &mut [Operation],
        caller: Address,
    ) -> Result<crate::protocol::TransactionCall> {
        if operations.is_empty() {
            return Err("aggregate members required".into());
        }
        let mut ids = BTreeSet::new();
        let mut members = Vec::new();
        for operation in operations.iter() {
            if operation.session.scope != self.scope
                || !Arc::ptr_eq(&operation.session.store, &self.store)
                || !ids.insert(operation.id.clone())
            {
                return Err(
                    "aggregate requires unique operations in one wallet store scope".into(),
                );
            }
            members.push(operation.recursive_transaction()?);
        }
        let aggregate = self.invisi.aggregate(backend, members)?;
        let call = aggregate.calldata(&*self.invisi.chain, caller)?;
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let stored = StoredCall::from(call.clone());
        let mut generations = Vec::new();
        for (operation, member) in operations.iter().zip(aggregate.members()) {
            let record = state
                .operations
                .get_mut(&operation.id)
                .ok_or("aggregate operation missing")?;
            if record.generation != operation.generation || record.status.terminal() {
                return Err("stale aggregate operation".into());
            }
            let member_snapshot = ManagedPrepared::snapshot_funds(member).snapshot()?;
            if serde_json::to_vec(&record.snapshot).map_err(|_| "journal encoding failed")?
                != serde_json::to_vec(&member_snapshot).map_err(|_| "member encoding failed")?
            {
                return Err("aggregate member differs from durable frozen plan".into());
            }
            if record
                .call
                .as_ref()
                .is_some_and(|previous| previous != &stored)
            {
                return Err("aggregate differs from already exported transaction".into());
            }
            record.call = Some(stored.clone());
            record.externalized = true;
            record.status = OperationStatus::Exported;
            record.generation = record
                .generation
                .checked_add(1)
                .ok_or("operation generation exhausted")?;
            generations.push(record.generation);
        }
        self.commit(state)?;
        for (operation, generation) in operations.iter_mut().zip(generations) {
            operation.generation = generation;
        }
        Ok(call)
    }
    pub fn track_aggregate(&self, operations: &mut [Operation], hash: B256) -> Result<()> {
        if hash == B256::ZERO || operations.is_empty() {
            return Err("aggregate operations and nonzero transaction hash required".into());
        }
        let mut state = self.snapshot()?;
        let mut expected: Option<StoredCall> = None;
        let mut ids = BTreeSet::new();
        let mut generations = Vec::new();
        for operation in operations.iter() {
            if operation.session.scope != self.scope
                || !Arc::ptr_eq(&operation.session.store, &self.store)
                || !ids.insert(operation.id.clone())
            {
                return Err("aggregate scope or member mismatch".into());
            }
            let record = state
                .operations
                .get_mut(&operation.id)
                .ok_or("aggregate operation missing")?;
            if record.generation != operation.generation
                || record.status.terminal()
                || !record.externalized
            {
                return Err("aggregate member not awaiting tracking".into());
            }
            let call = record.call.as_ref().ok_or("aggregate calldata missing")?;
            use alloy_sol_types::SolCall;
            if call.data.get(..4)
                != Some(crate::protocol::InvisiProtocol::transact_1Call::SELECTOR.as_slice())
            {
                return Err("member does not reference an aggregate call".into());
            }
            if expected.as_ref().is_some_and(|previous| previous != call) {
                return Err("members do not share one aggregate transaction".into());
            }
            expected = Some(call.clone());
            if record
                .transaction_hash
                .is_some_and(|previous| previous != hash)
            {
                return Err("aggregate member already tracks another hash".into());
            }
            record.transaction_hash = Some(hash);
            record.status = OperationStatus::Submitted;
            record.generation = record
                .generation
                .checked_add(1)
                .ok_or("operation generation exhausted")?;
            generations.push(record.generation);
        }
        self.commit(state)?;
        for (operation, generation) in operations.iter_mut().zip(generations) {
            operation.generation = generation;
        }
        Ok(())
    }
    pub fn import_note(&self, input: NoteInput, transaction: B256) -> Result<()> {
        input.validate(
            self.wallet.owner_address(),
            self.scope.context,
            sdk::word_address(input.note.token_address)?,
        )?;
        let anchor = self.invisi.chain.snapshot()?;
        if !self
            .invisi
            .chain
            .known_root(input.tree_id, sdk::field_word(input.root), &anchor)?
        {
            return Err("imported Note root is not canonical".into());
        }
        let receipt = self
            .source
            .receipt(transaction)?
            .ok_or("imported Note canonical receipt missing")?;
        if receipt.transaction_hash != transaction {
            return Err("import transaction mismatch".into());
        }
        self.invisi.chain.canonical(&receipt.block)?;
        let decoded = crate::protocol::decode_receipt_outputs(
            sdk::word_address(self.scope.context.protocol_address)?,
            &receipt,
        )?;
        let commitment = sdk::field_word(input.note.commitment().map_err(|e| e.to_string())?);
        if !decoded.notes.iter().any(|n| {
            n.leaf.commitment == commitment
                && n.leaf.tree_id == input.tree_id
                && n.leaf.leaf_index == input.leaf_index as u32
        }) {
            return Err("imported Note lacks canonical insertion".into());
        }
        let nullifier = sdk::field_word(input.note.nullifier().map_err(|e| e.to_string())?);
        let spent = self.invisi.chain.nullifier_spent(nullifier, &anchor)?;
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        if state.notes.contains_key(&commitment) {
            return Err("Note already imported".into());
        }
        state.notes.insert(
            commitment,
            StoredNote {
                input,
                commitment,
                nullifier,
                block: receipt.block,
                transaction_hash: transaction,
                spent,
                reserved_by: None,
            },
        );
        state.observed_through = None;
        self.invisi.chain.canonical(&anchor)?;
        self.commit(state)
    }
    /// Release only when canonical post-deadline facts prove the exported input spend cannot execute.
    pub fn expire_operation(&self, id: &str) -> Result<()> {
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let record = state.operations.get(id).ok_or("operation not found")?;
        if record.status.terminal() {
            return Err("operation is already terminal".into());
        }
        let block = self.invisi.chain.snapshot()?;
        if block.timestamp <= record.deadline {
            return Err("operation has not expired on chain".into());
        }
        if record.externalized {
            let hash = record
                .transaction_hash
                .ok_or("exported operation needs a tracked hash before expiry reconciliation")?;
            if self.source.receipt(hash)?.is_some() {
                return Err("mined transaction requires receipt reconciliation".into());
            }
        }
        for input in &record.inputs {
            if let Some(raw) = input.strip_prefix("note:") {
                let commitment: B256 = raw.parse().map_err(|_| "invalid input reference")?;
                let note = state
                    .notes
                    .get(&commitment)
                    .ok_or("reserved Note disappeared")?;
                if self.invisi.chain.nullifier_spent(note.nullifier, &block)? {
                    return Err("spent input has uncertain execution; reconcile first".into());
                }
            }
            if let Some(raw) = input.strip_prefix("credit:") {
                let commitment: B256 = raw.parse().map_err(|_| "invalid input reference")?;
                let credit = state
                    .credits
                    .values()
                    .find(|c| c.commitment == commitment)
                    .ok_or("reserved Credit disappeared")?;
                if self
                    .invisi
                    .chain
                    .nullifier_spent(credit.nullifier, &block)?
                {
                    return Err("consumed Credit has uncertain execution; reconcile first".into());
                }
            }
        }
        self.invisi.chain.canonical(&block)?;
        let record = state.operations.get_mut(id).ok_or("operation not found")?;
        record.status = OperationStatus::Expired;
        record.resolved_at = Some(block);
        record.generation = record
            .generation
            .checked_add(1)
            .ok_or("operation generation exhausted")?;
        super::sync::release_inputs(&mut state, id);
        self.commit(state)
    }
}
pub enum Reconciliation {
    Pending,
    Ready(PendingWalletRefresh),
}
fn credit_input(value: &StoredCredit, debit: U256) -> CreditInput {
    CreditInput {
        delivery: value.delivery.clone(),
        tree_id: value.tree_id,
        leaf_index: value.leaf_index,
        path: value.path,
        root: value.root,
        debit,
    }
}
fn reserve(state: &mut WalletState, input: &str, id: &str) -> Result<()> {
    if let Some(hash) = input.strip_prefix("note:") {
        let hash: B256 = hash.parse().map_err(|_| "invalid Note input reference")?;
        let note = state
            .notes
            .get_mut(&hash)
            .ok_or("Note input is not in session inventory")?;
        if note.spent || note.reserved_by.is_some() {
            return Err("Note input already spent or reserved".into());
        }
        note.reserved_by = Some(id.into());
        return Ok(());
    }
    if let Some(hash) = input.strip_prefix("credit:") {
        let hash: B256 = hash.parse().map_err(|_| "invalid Credit input reference")?;
        let matching = state
            .credits
            .values()
            .filter(|v| v.commitment == hash)
            .collect::<Vec<_>>();
        if matching.is_empty()
            || matching
                .iter()
                .any(|v| v.consumed || v.revoked || v.reserved_by.is_some())
        {
            return Err("Credit input already consumed, revoked or reserved".into());
        }
        for credit in state.credits.values_mut().filter(|v| v.commitment == hash) {
            credit.reserved_by = Some(id.into());
        }
        return Ok(());
    }
    Err("unknown operation input reference".into())
}
