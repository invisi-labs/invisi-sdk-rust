//! Durable, whitelisted prepared plans. Native authorization witnesses are never serialized.
use super::credit::{CreditPlan, CreditRepriceTemplate};
use super::*;
use crate::protocol::{IInvisiProtocol as abi, InvisiProtocol as P};
use crate::sdk;
use alloy_sol_types::{SolCall, SolInterface};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
struct NoteInputRecord {
    note: Note,
    tree_id: u64,
    leaf_index: u16,
    path: [U256; 16],
    root: U256,
}
impl From<&NoteInput> for NoteInputRecord {
    fn from(v: &NoteInput) -> Self {
        Self {
            note: v.note.clone(),
            tree_id: v.tree_id,
            leaf_index: v.leaf_index,
            path: v.path,
            root: v.root,
        }
    }
}
impl From<NoteInputRecord> for NoteInput {
    fn from(v: NoteInputRecord) -> Self {
        Self {
            note: v.note,
            tree_id: v.tree_id,
            leaf_index: v.leaf_index,
            path: v.path,
            root: v.root,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputSnapshot {
    context: ProtocolContext,
    token: Address,
    identity: U256,
    amount: U256,
    commitment: B256,
    note: Option<crate::note::Note>,
    #[serde(with = "crate::note::bytes_hex")]
    ciphertext: Vec<u8>,
    #[serde(with = "crate::note::bytes_hex")]
    clue: Vec<u8>,
}
impl OutputSnapshot {
    fn capture(v: &NoteOutput) -> Self {
        Self {
            context: v.context(),
            token: v.token(),
            identity: v.identity_value(),
            amount: v.amount(),
            commitment: v.commitment(),
            note: v.note().cloned(),
            ciphertext: v.delivery().ciphertext.to_vec(),
            clue: v.delivery().clue.to_vec(),
        }
    }
    fn restore(&self) -> Result<NoteOutput> {
        NoteOutput::restore(
            self.context,
            self.token,
            self.identity,
            self.amount,
            self.commitment,
            self.note.clone(),
            abi::Delivery {
                ciphertext: self.ciphertext.clone().into(),
                clue: self.clue.clone().into(),
            },
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditInputSnapshot {
    delivery: CreditDeliveryState,
    tree_id: u64,
    leaf_index: u16,
    path: [U256; 16],
    root: U256,
    debit: U256,
}
impl From<&CreditInput> for CreditInputSnapshot {
    fn from(v: &CreditInput) -> Self {
        Self {
            delivery: v.delivery.clone(),
            tree_id: v.tree_id,
            leaf_index: v.leaf_index,
            path: v.path,
            root: v.root,
            debit: v.debit,
        }
    }
}
impl From<CreditInputSnapshot> for CreditInput {
    fn from(v: CreditInputSnapshot) -> Self {
        Self {
            delivery: v.delivery,
            tree_id: v.tree_id,
            leaf_index: v.leaf_index,
            path: v.path,
            root: v.root,
            debit: v.debit,
        }
    }
}
/// This durable whitelist excludes authorization witnesses, account keys and private proving buffers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSnapshot {
    context: ProtocolContext,
    token: Address,
    anchor: CanonicalBlock,
    unsigned_call: Vec<u8>,
    inputs: Vec<NoteInputRecord>,
    credit_inputs: Vec<CreditInputSnapshot>,
    outputs: Vec<OutputSnapshot>,
    states: Vec<CreditDeliveryState>,
    changes: Option<crate::credit::CreditUpdateChanges>,
    capacity: usize,
    needs_authorization: bool,
    proof: Option<ProofBundle>,
    target: String,
    ready: bool,
    broadcaster: Option<PreparedBroadcasterState>,
    credit_recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provenance_packet: Option<sdk::ProvenanceProof>,
}
pub enum ManagedPrepared {
    Funds(PreparedTransaction),
    Credit(PreparedCredit),
}
impl ManagedPrepared {
    pub fn snapshot_funds(value: &PreparedTransaction) -> Self {
        Self::Funds(PreparedTransaction {
            wallet: value.wallet.clone(),
            context: value.context,
            token: value.token,
            anchor: value.anchor.clone(),
            plan: value.plan.clone(),
            phase: value.phase,
            authorization: value.authorization.clone(),
            proof: value.proof.clone(),
            needs_authorization: value.needs_authorization,
            target: value.target.clone(),
            provenance: value.provenance.clone(),
            provenance_data: value.provenance_data.clone(),
            provenance_packet: value.provenance_packet.clone(),
            broadcaster: value.broadcaster.clone(),
            reprice: value.reprice.clone(),
        })
    }
    pub fn phase(&self) -> Phase {
        match self {
            Self::Funds(v) => v.phase(),
            Self::Credit(v) => v.phase(),
        }
    }
    pub fn wallet(&self) -> &Wallet {
        match self {
            Self::Funds(v) => v.wallet(),
            Self::Credit(v) => v.wallet(),
        }
    }
    pub fn snapshot(&self) -> Result<PreparedSnapshot> {
        let empty = |context, token, anchor| PreparedSnapshot {
            context,
            token,
            anchor,
            unsigned_call: Vec::new(),
            inputs: Vec::new(),
            credit_inputs: Vec::new(),
            outputs: Vec::new(),
            states: Vec::new(),
            changes: None,
            capacity: 0,
            needs_authorization: false,
            proof: None,
            target: "evm".into(),
            ready: false,
            broadcaster: None,
            credit_recipient: None,
            provenance_packet: None,
        };
        Ok(match self {
            Self::Funds(v) => {
                let mut s = empty(v.context, v.token, v.anchor.clone());
                s.broadcaster = v.broadcaster.clone();
                s.provenance_packet = v.export_provenance_proof()?;
                s.inputs = v.inputs().iter().map(NoteInputRecord::from).collect();
                s.outputs = v.outputs().iter().map(OutputSnapshot::capture).collect();
                s.needs_authorization = v.needs_authorization;
                s.proof = v.proof.clone();
                s.target = v.target.clone();
                s.ready = matches!(v.phase, Phase::Ready | Phase::Exported);
                s.unsigned_call = match &v.plan {
                    Plan::Shield {
                        params,
                        outputs,
                        funding,
                    } => P::shieldCall {
                        p: params.clone(),
                        _1: outputs
                            .iter()
                            .map(|v| abi::ShieldOutput {
                                identity: sdk::field_word(v.identity_value()),
                                amount: v.amount(),
                            })
                            .collect(),
                        _2: outputs.iter().map(|v| v.delivery().clone()).collect(),
                        _3: funding.clone(),
                    }
                    .abi_encode(),
                    Plan::Transfer {
                        params,
                        outputs,
                        funding,
                        capacity,
                        ..
                    } => {
                        s.capacity = *capacity;
                        P::transact_0Call {
                            _0: Default::default(),
                            r: abi::TransactRequest {
                                params: params.clone(),
                                deliveries: outputs.iter().map(|v| v.delivery().clone()).collect(),
                                funding: funding.clone(),
                            },
                        }
                        .abi_encode()
                    }
                };
                s
            }
            Self::Credit(v) => {
                let mut s = empty(v.context, v.token, v.anchor.clone());
                s.broadcaster = v.broadcaster.clone();
                if let Some(CreditRepriceTemplate::Draw(_, recipient, _, _)) = &v.reprice {
                    s.credit_recipient = Some(recipient.address()?);
                }
                s.proof = v.proof.clone();
                s.credit_inputs = v
                    .credit_inputs()
                    .into_iter()
                    .map(CreditInputSnapshot::from)
                    .collect();
                s.ready = matches!(v.phase, Phase::Ready | Phase::Exported);
                s.unsigned_call = match &v.plan {
                    CreditPlan::Create { params, created } => {
                        s.states.push(created.clone());
                        P::createCreditCall {
                            _0: Default::default(),
                            p: params.clone(),
                            _2: v.deliveries.clone(),
                        }
                        .abi_encode()
                    }
                    CreditPlan::Update {
                        params,
                        changes,
                        next,
                        ..
                    } => {
                        s.states.push(next.clone());
                        s.changes = Some(changes.clone());
                        P::updateCreditCall {
                            _0: Default::default(),
                            p: params.clone(),
                            _2: v.deliveries.clone(),
                        }
                        .abi_encode()
                    }
                    CreditPlan::Draw {
                        params,
                        successors,
                        output,
                        ..
                    } => {
                        s.states = successors.clone();
                        s.outputs.push(OutputSnapshot::capture(output));
                        P::creditDrawCall {
                            _0: Default::default(),
                            p: params.clone(),
                            _2: v.deliveries.clone(),
                        }
                        .abi_encode()
                    }
                    CreditPlan::Revoke {
                        owner,
                        token,
                        shard,
                        slot,
                        deadline,
                        fee,
                        signature,
                    } => P::revokeCreditCall {
                        token: *token,
                        owner: *owner,
                        shard: *shard,
                        slot: *slot,
                        deadline: U256::from(*deadline),
                        feeRecipient: fee.recipient,
                        feeAmount: fee.amount,
                        signature: signature.clone().into(),
                    }
                    .abi_encode(),
                };
                s
            }
        })
    }
    pub fn input_ids(&self) -> Result<Vec<String>> {
        match self {
            Self::Funds(v) => v
                .inputs()
                .iter()
                .map(|i| {
                    i.note
                        .commitment()
                        .map(|n| format!("note:{}", sdk::field_word(n)))
                        .map_err(|e| e.to_string())
                })
                .collect(),
            Self::Credit(v) => v
                .credit_inputs()
                .iter()
                .map(|i| {
                    i.delivery
                        .note
                        .commitment()
                        .map(|n| format!("credit:{}", sdk::field_word(n)))
                        .map_err(|e| e.to_string())
                })
                .collect(),
        }
    }
    pub fn kind_deadline(&self) -> Result<(String, u64)> {
        let s = self.snapshot()?;
        let call = P::InvisiProtocolCalls::abi_decode(&s.unsigned_call, true)
            .map_err(|e| e.to_string())?;
        let (kind, d) = match call {
            P::InvisiProtocolCalls::shield(c) => ("shield", c.p.deadline),
            P::InvisiProtocolCalls::transact_0(c) => ("transfer", c.r.params.deadline),
            P::InvisiProtocolCalls::createCredit(c) => ("create-credit", c.p.deadline),
            P::InvisiProtocolCalls::updateCredit(c) => ("update-credit", c.p.deadline),
            P::InvisiProtocolCalls::creditDraw(c) => ("draw-credit", c.p.deadline),
            P::InvisiProtocolCalls::revokeCredit(c) => ("revoke-credit", c.deadline),
            _ => return Err("unsupported managed operation".into()),
        };
        Ok((
            kind.into(),
            u64::try_from(d).map_err(|_| "deadline overflow")?,
        ))
    }
}
impl PreparedSnapshot {
    pub fn restore(
        &self,
        wallet: &Wallet,
        backend: Option<&dyn Prover>,
    ) -> Result<ManagedPrepared> {
        self.context.validate().map_err(|e| e.to_string())?;
        let call = P::InvisiProtocolCalls::abi_decode(&self.unsigned_call, true)
            .map_err(|e| e.to_string())?;
        if call.abi_encode() != self.unsigned_call {
            return Err("noncanonical saved operation".into());
        }
        let outputs = self
            .outputs
            .iter()
            .map(OutputSnapshot::restore)
            .collect::<Result<Vec<_>>>()?;
        let inputs = self
            .inputs
            .clone()
            .into_iter()
            .map(NoteInput::from)
            .collect::<Vec<_>>();
        for input in &inputs {
            input.validate(wallet.owner_address(), self.context, self.token)?;
        }
        validate_outputs(&outputs, self.context, self.token)?;
        if !["evm", "noir-recursive"].contains(&self.target.as_str()) {
            return Err("unsupported saved proving target".into());
        }
        let mut managed = match call {
            P::InvisiProtocolCalls::shield(c) => {
                validate_funding(&c._3)?;
                Fee {
                    recipient: c.p.feeRecipient,
                    amount: c.p.feeAmount,
                }
                .validate()?;
                if c.p.token != self.token
                    || !inputs.is_empty()
                    || self.needs_authorization
                    || self.capacity != 0
                    || outputs.is_empty()
                    || outputs.len() > 10
                    || sum(outputs.iter().map(NoteOutput::amount))?.checked_add(c.p.feeAmount)
                        != Some(c._3.amount)
                    || c.p.deadline < U256::from(self.anchor.timestamp)
                {
                    return Err("saved shield financial invariants mismatch".into());
                }
                if outputs.len() != c._1.len()
                    || outputs.len() != c._2.len()
                    || outputs.len() != c.p.noteCommitments.len()
                {
                    return Err("saved shield dimensions mismatch".into());
                }
                for (i, o) in outputs.iter().enumerate() {
                    if o.commitment() != c.p.noteCommitments[i]
                        || (o.delivery().ciphertext != c._2[i].ciphertext
                            || o.delivery().clue != c._2[i].clue)
                        || sdk::field_word(o.identity_value()) != c._1[i].identity
                        || o.amount() != c._1[i].amount
                    {
                        return Err("saved shield output mismatch".into());
                    }
                }
                ManagedPrepared::Funds(PreparedTransaction {
                    wallet: wallet.clone(),
                    context: self.context,
                    token: self.token,
                    anchor: self.anchor.clone(),
                    plan: Plan::Shield {
                        params: c.p,
                        outputs,
                        funding: c._3,
                    },
                    phase: if self.ready {
                        Phase::Ready
                    } else {
                        Phase::Prepared
                    },
                    authorization: None,
                    proof: None,
                    needs_authorization: false,
                    target: "evm".into(),
                    provenance: None,
                    provenance_data: None,
                    provenance_packet: Arc::new(std::sync::Mutex::new(
                        self.provenance_packet.clone(),
                    )),
                    broadcaster: self.broadcaster.clone(),
                    reprice: None,
                })
            }
            P::InvisiProtocolCalls::transact_0(c) => {
                validate_funding(&c.r.funding)?;
                Fee {
                    recipient: c.r.params.feeRecipient,
                    amount: c.r.params.feeAmount,
                }
                .validate()?;
                let expected_capacity = capacity(inputs.len(), outputs.len())?;
                let available = sum(inputs.iter().map(|input| input.note.amount))?
                    .checked_add(c.r.funding.amount)
                    .ok_or("saved funds amount overflow")?;
                let required = sum(outputs.iter().map(NoteOutput::amount))?
                    .checked_add(c.r.params.withdrawalAmount)
                    .and_then(|n| n.checked_add(c.r.params.feeAmount))
                    .ok_or("saved funds amount overflow")?;
                let needs_authorization = !inputs.is_empty()
                    && !(c.r.params.withdrawalAddress == wallet.owner_address()
                        && c.r.params.withdrawalAmount == available
                        && outputs.is_empty()
                        && c.r.funding.amount == U256::ZERO
                        && c.r.params.feeAmount == U256::ZERO);
                let sources = sorted_sources(&inputs)?;
                if c.r.params.token != self.token
                    || available != required
                    || self.capacity != expected_capacity
                    || self.target == "noir-recursive" && expected_capacity > 10
                    || self.needs_authorization != needs_authorization
                    || sources.len() != c.r.params.sources.len()
                    || sources
                        .iter()
                        .zip(&c.r.params.sources)
                        .any(|(a, b)| a.treeId != b.treeId || a.merkleRoot != b.merkleRoot)
                    || c.r.params.deadline < U256::from(self.anchor.timestamp)
                {
                    return Err("saved transfer financial or statement invariants mismatch".into());
                }
                let mut unique = std::collections::BTreeSet::new();
                if c.r
                    .params
                    .nullifiers
                    .iter()
                    .any(|value| !unique.insert(value))
                {
                    return Err("duplicate saved input nullifier".into());
                }
                if !c._0.is_empty()
                    || outputs.len() != c.r.deliveries.len()
                    || outputs.len() != c.r.params.noteCommitments.len()
                    || inputs.len() != c.r.params.nullifiers.len()
                {
                    return Err("saved transfer dimensions mismatch".into());
                }
                for (i, o) in outputs.iter().enumerate() {
                    if o.commitment() != c.r.params.noteCommitments[i]
                        || (o.delivery().ciphertext != c.r.deliveries[i].ciphertext
                            || o.delivery().clue != c.r.deliveries[i].clue)
                    {
                        return Err("saved transfer output mismatch".into());
                    }
                }
                for (i, input) in inputs.iter().enumerate() {
                    if sdk::field_word(input.note.nullifier().map_err(|e| e.to_string())?)
                        != c.r.params.nullifiers[i]
                    {
                        return Err("saved input nullifier mismatch".into());
                    }
                }
                ManagedPrepared::Funds(PreparedTransaction {
                    wallet: wallet.clone(),
                    context: self.context,
                    token: self.token,
                    anchor: self.anchor.clone(),
                    plan: Plan::Transfer {
                        params: c.r.params,
                        inputs,
                        outputs,
                        funding: c.r.funding,
                        capacity: self.capacity,
                    },
                    phase: Phase::Prepared,
                    authorization: None,
                    proof: None,
                    needs_authorization: self.needs_authorization,
                    target: self.target.clone(),
                    provenance: None,
                    provenance_data: None,
                    provenance_packet: Arc::new(std::sync::Mutex::new(
                        self.provenance_packet.clone(),
                    )),
                    broadcaster: self.broadcaster.clone(),
                    reprice: None,
                })
            }
            other => {
                let mut credit_inputs = self
                    .credit_inputs
                    .clone()
                    .into_iter()
                    .map(CreditInput::from)
                    .collect::<Vec<_>>();
                for input in &credit_inputs {
                    input.delivery.validate().map_err(|e| e.to_string())?;
                    if input.tree_id == 0
                        || input.delivery.note.context != self.context
                        || input.delivery.note.token_address != address_word(self.token)
                        || merkle_root(
                            model(input.delivery.note.commitment())?,
                            input.leaf_index,
                            &input.path,
                        )? != input.root
                    {
                        return Err("saved Credit input membership mismatch".into());
                    }
                }
                for state in &self.states {
                    state.validate().map_err(|e| e.to_string())?;
                }
                let (plan, deliveries) = match other {
                    P::InvisiProtocolCalls::createCredit(c) => {
                        if !c._0.is_empty()
                            || !credit_inputs.is_empty()
                            || !outputs.is_empty()
                            || c._2.len() != 2
                            || c.p.token != self.token
                            || c.p.owner != wallet.owner_address()
                        {
                            return Err("saved Credit creation shape mismatch".into());
                        }
                        if self.states.len() != 1 {
                            return Err("saved creation state required".into());
                        }
                        let state = &self.states[0].note;
                        if state.context != self.context
                            || state.token_address != address_word(self.token)
                            || state.owner_wallet_identity != address_word(wallet.owner_address())
                            || state.revocation_shard != c.p.revocationShard
                            || state.revocation_slot != c.p.revocationSlot
                            || field_word(model(state.commitment())?) != c.p.creditCommitment
                            || state.usage != crate::credit::CreditUsage::default()
                            || c.p.deadline > U256::from(state.expiry)
                        {
                            return Err("saved initial Credit state mismatch".into());
                        }
                        (
                            CreditPlan::Create {
                                params: c.p,
                                created: self.states[0].clone(),
                            },
                            c._2,
                        )
                    }
                    P::InvisiProtocolCalls::updateCredit(c) => {
                        if !c._0.is_empty()
                            || !outputs.is_empty()
                            || c._2.len() != 2
                            || c.p.token != self.token
                            || c.p.owner != wallet.owner_address()
                        {
                            return Err("saved Credit update shape mismatch".into());
                        }
                        if credit_inputs.len() != 1 || self.states.len() != 1 {
                            return Err("saved update state required".into());
                        }
                        let input = &credit_inputs[0];
                        let state = &input.delivery.note;
                        let expected = model(crate::credit::derive_credit_update(
                            state,
                            self.changes
                                .as_ref()
                                .ok_or("saved update changes required")?,
                            u64::try_from(c.p.deadline).map_err(|_| "saved deadline overflow")?,
                        ))?;
                        if state.context != self.context
                            || state.token_address != address_word(self.token)
                            || state.owner_wallet_identity != address_word(wallet.owner_address())
                            || c.p.source.treeId != U256::from(input.tree_id)
                            || c.p.source.merkleRoot != field_word(input.root)
                            || c.p.nullifier != field_word(model(state.nullifier())?)
                            || expected.state != self.states[0].note
                            || field_word(expected.state_commitment) != c.p.creditCommitment
                            || state.revocation_shard != c.p.revocationShard
                            || state.revocation_slot != c.p.revocationSlot
                        {
                            return Err("saved Credit update invariants mismatch".into());
                        }
                        (
                            CreditPlan::Update {
                                params: c.p,
                                input: credit_inputs.remove(0),
                                changes: self
                                    .changes
                                    .clone()
                                    .ok_or("saved update changes required")?,
                                next: self.states[0].clone(),
                            },
                            c._2,
                        )
                    }
                    P::InvisiProtocolCalls::creditDraw(c) => {
                        let n = credit_inputs.len();
                        if !c._0.is_empty()
                            || n == 0
                            || n > 80
                            || c.p.token != self.token
                            || c.p.nullifiers.len() != n
                            || c.p.creditCommitments.len() != n
                            || c.p.recoveryAmounts.len() != n
                            || c.p.grantRefs.len() != n
                            || c.p.payers.len() > n
                            || c.p.sources.len() > n
                            || c._2.len() != 2 * n + 1
                        {
                            return Err("saved Credit draw statement dimensions mismatch".into());
                        }
                        if self.states.len() != credit_inputs.len() || outputs.len() != 1 {
                            return Err("saved draw dimensions mismatch".into());
                        }
                        let mut total = U256::ZERO;
                        for (i, input) in credit_inputs.iter().enumerate() {
                            let state = &input.delivery.note;
                            let expected = model(crate::credit::derive_credit_state(
                                state,
                                input.debit,
                                self.anchor.timestamp,
                            ))?;
                            if state.context != self.context
                                || state.token_address != address_word(self.token)
                                || state.spender_wallet_identity
                                    != address_word(wallet.owner_address())
                                || expected.state != self.states[i].note
                                || field_word(expected.state_commitment) != c.p.creditCommitments[i]
                                || field_word(expected.nullifier) != c.p.nullifiers[i]
                                || field_word(expected.recovery_amount) != c.p.recoveryAmounts[i]
                            {
                                return Err("saved Credit draw transition mismatch".into());
                            }
                            total = total
                                .checked_add(input.debit)
                                .ok_or("saved Credit debit overflow")?;
                        }
                        if c.p.totalAmount != total
                            || total <= c.p.feeAmount
                            || total.checked_sub(c.p.feeAmount) != Some(outputs[0].amount())
                            || outputs[0].commitment() != c.p.noteCommitment
                        {
                            return Err("saved Credit recipient amount mismatch".into());
                        }
                        (
                            CreditPlan::Draw {
                                params: c.p,
                                inputs: credit_inputs,
                                successors: self.states.clone(),
                                output: outputs[0].clone(),
                            },
                            c._2,
                        )
                    }
                    P::InvisiProtocolCalls::revokeCredit(c) => (
                        CreditPlan::Revoke {
                            owner: c.owner,
                            token: c.token,
                            shard: c.shard,
                            slot: c.slot,
                            deadline: u64::try_from(c.deadline)
                                .map_err(|_| "saved deadline overflow")?,
                            fee: sdk::Fee {
                                recipient: c.feeRecipient,
                                amount: c.feeAmount,
                            },
                            signature: c.signature.to_vec(),
                        },
                        Vec::new(),
                    ),
                    _ => return Err("unsupported saved operation".into()),
                };
                let reprice = if self.broadcaster.is_none() {
                    match &plan {
                        CreditPlan::Create { params, created } => {
                            Some(CreditRepriceTemplate::Create(
                                created.clone(),
                                u64::try_from(params.deadline)
                                    .map_err(|_| "saved Credit deadline overflow")?,
                            ))
                        }
                        CreditPlan::Update {
                            params,
                            input,
                            changes,
                            ..
                        } => Some(CreditRepriceTemplate::Update(
                            input.clone(),
                            changes.clone(),
                            u64::try_from(params.deadline)
                                .map_err(|_| "saved Credit deadline overflow")?,
                        )),
                        CreditPlan::Draw {
                            params,
                            inputs,
                            output,
                            ..
                        } => {
                            let recipient = Wallet::from_address(
                                self.credit_recipient
                                    .as_deref()
                                    .ok_or("saved Credit draw public recipient required")?,
                            )?;
                            let note = output
                                .note()
                                .ok_or("saved Credit draw output opening required")?;
                            if recipient.receiving_keys().is_none()
                                || address_word(recipient.owner) != note.owner_address
                            {
                                return Err("saved Credit draw recipient mismatch".into());
                            }
                            Some(CreditRepriceTemplate::Draw(
                                inputs.clone(),
                                recipient,
                                u64::try_from(params.deadline)
                                    .map_err(|_| "saved Credit deadline overflow")?,
                                note.payload.clone(),
                            ))
                        }
                        CreditPlan::Revoke {
                            token,
                            shard,
                            slot,
                            deadline,
                            ..
                        } => Some(CreditRepriceTemplate::Revoke(
                            *token, *shard, *slot, *deadline,
                        )),
                    }
                } else {
                    None
                };
                ManagedPrepared::Credit(PreparedCredit {
                    wallet: wallet.clone(),
                    context: self.context,
                    token: self.token,
                    anchor: self.anchor.clone(),
                    plan,
                    deliveries,
                    phase: Phase::Prepared,
                    authorization: None,
                    proof: None,
                    provenance: None,
                    broadcaster: self.broadcaster.clone(),
                    reprice,
                })
            }
        };
        if let (Some(proof), Some(backend)) = (&self.proof, backend) {
            let words = match &managed {
                ManagedPrepared::Funds(v) => v.public_inputs()?,
                ManagedPrepared::Credit(v) => v.public_inputs()?,
            };
            let statement = prover::statement(
                &proof.circuit_name,
                &proof.target,
                words.into_iter().map(sdk::field_word).collect(),
            )?;
            prover::assert_bundle(proof, &statement)?;
            if !backend.verify(proof, &statement)? {
                return Err("recovered proof verification failed".into());
            }
            match &mut managed {
                ManagedPrepared::Funds(v) => {
                    v.proof = Some(proof.clone());
                    v.phase = Phase::Proved;
                }
                ManagedPrepared::Credit(v) => {
                    v.proof = Some(proof.clone());
                    v.phase = Phase::Proved;
                }
            }
        }
        Ok(managed)
    }
}

impl PreparedSnapshot {
    /// Reconstructs retained final Note calldata for Source-only proof recovery.
    pub fn provenance_calldata(&self) -> Result<Option<Vec<u8>>> {
        let Some(proof) = &self.proof else {
            return Ok(None);
        };
        let P::InvisiProtocolCalls::transact_0(mut call) =
            P::InvisiProtocolCalls::abi_decode(&self.unsigned_call, true)
                .map_err(|e| e.to_string())?
        else {
            return Ok(None);
        };
        call._0 = proof.proof.clone().into();
        Ok(Some(call.abi_encode()))
    }
    /// Updates public Source evidence without changing the saved payment or verified proof state.
    pub fn update_provenance_proof(&mut self, prepared: &ManagedPrepared) -> Result<()> {
        let candidate = prepared.snapshot()?;
        if candidate.context != self.context
            || candidate.token != self.token
            || candidate.unsigned_call != self.unsigned_call
        {
            return Err("provenance update payment mismatch".into());
        }
        self.provenance_packet = candidate.provenance_packet;
        Ok(())
    }
    pub fn context(&self) -> ProtocolContext {
        self.context
    }
    pub fn token(&self) -> Address {
        self.token
    }
    pub fn anchor(&self) -> &CanonicalBlock {
        &self.anchor
    }
}
impl ManagedPrepared {
    pub fn clone_for_stage(&self) -> Self {
        match self {
            Self::Funds(v) => Self::Funds(PreparedTransaction {
                wallet: v.wallet.clone(),
                context: v.context,
                token: v.token,
                anchor: v.anchor.clone(),
                plan: v.plan.clone(),
                phase: v.phase,
                authorization: v.authorization.clone(),
                proof: v.proof.clone(),
                needs_authorization: v.needs_authorization,
                target: v.target.clone(),
                provenance: v.provenance.clone(),
                provenance_data: v.provenance_data.clone(),
                provenance_packet: Arc::new(std::sync::Mutex::new(
                    v.provenance_packet
                        .lock()
                        .expect("provenance cache lock")
                        .clone(),
                )),
                broadcaster: v.broadcaster.clone(),
                reprice: v.reprice.clone(),
            }),
            Self::Credit(v) => Self::Credit(PreparedCredit {
                wallet: v.wallet.clone(),
                context: v.context,
                token: v.token,
                anchor: v.anchor.clone(),
                plan: v.plan.clone(),
                deliveries: v.deliveries.clone(),
                phase: v.phase,
                authorization: v.authorization.clone(),
                proof: v.proof.clone(),
                provenance: v.provenance.clone(),
                broadcaster: v.broadcaster.clone(),
                reprice: v.reprice.clone(),
            }),
        }
    }
    pub fn export_wallet_request(&self, id: impl Into<String>) -> Result<WalletRequest> {
        match self {
            Self::Funds(v) => v.export_wallet_request(id),
            Self::Credit(v) => v.export_wallet_request(id),
        }
    }
    pub fn with_wallet_response(self, q: &WalletRequest, r: &WalletResponse) -> Result<Self> {
        match self {
            Self::Funds(v) => Ok(Self::Funds(v.with_wallet_response(q, r)?)),
            Self::Credit(v) => Ok(Self::Credit(v.with_wallet_response(q, r)?)),
        }
    }
    pub fn prove(self, backend: &dyn Prover, recursive: bool) -> Result<Self> {
        match self {
            Self::Funds(v) => Ok(Self::Funds(v.prove(backend, recursive)?)),
            Self::Credit(v) => {
                if recursive {
                    return Err("Credit operations cannot use funds aggregation".into());
                }
                Ok(Self::Credit(v.prove(backend)?))
            }
        }
    }
    pub fn ready(self) -> Result<Self> {
        match self {
            Self::Funds(v) => Ok(Self::Funds(v.ready()?)),
            _ => Err("ready requires a shield operation".into()),
        }
    }
    pub fn with_revocation_signature(
        self,
        chain: &dyn ChainState,
        signature: Vec<u8>,
    ) -> Result<Self> {
        match self {
            Self::Credit(v) => Ok(Self::Credit(v.with_revocation_signature(chain, signature)?)),
            _ => Err("revocation operation required".into()),
        }
    }
    pub fn export_revocation_authorization(&self) -> Result<Value> {
        match self {
            Self::Credit(v) => v.export_revocation_authorization(),
            _ => Err("revocation operation required".into()),
        }
    }
    pub fn with_funding_terms(self, chain: &dyn ChainState, deadline: u64) -> Result<Self> {
        match self {
            Self::Funds(v) => Ok(Self::Funds(v.with_funding_terms(chain, deadline)?)),
            _ => Err("ordinary funding operation required".into()),
        }
    }
    pub fn export_funding_authorization(
        &self,
        chain: &dyn ChainState,
    ) -> Result<EvmSigningRequest> {
        match self {
            Self::Funds(v) => v.export_funding_authorization(chain),
            _ => Err("ordinary funding operation required".into()),
        }
    }
    pub fn with_funding_signature(
        self,
        chain: &dyn ChainState,
        signature: Vec<u8>,
    ) -> Result<Self> {
        match self {
            Self::Funds(v) => Ok(Self::Funds(v.with_funding_signature(chain, signature)?)),
            _ => Err("ordinary funding operation required".into()),
        }
    }
    pub fn calldata(&self, chain: &dyn ChainState, caller: Address) -> Result<TransactionCall> {
        match self {
            Self::Funds(v) => v.calldata(chain, caller),
            Self::Credit(v) => v.calldata(chain, caller),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputHistory {
    pub recipient: Option<Address>,
    pub amount: U256,
    pub payload: Vec<u8>,
    pub commitment: B256,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingHistory {
    pub payer: Address,
    pub amount: U256,
    pub authorization: &'static str,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditHistory {
    pub owner: Address,
    pub spender: Address,
    pub available_credit: U256,
    pub unlimited: bool,
    pub expiry: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedHistory {
    pub token: Address,
    pub outputs: Vec<OutputHistory>,
    pub credits: Vec<CreditHistory>,
    pub funding: Option<FundingHistory>,
    pub withdrawal: Option<(Address, U256)>,
    pub fee_recipient: Address,
    pub fee_amount: U256,
}
impl PreparedSnapshot {
    /// Detached business intent only; no signatures, paths, shared keys or proving witness buffers.
    pub fn history(&self) -> Result<PreparedHistory> {
        let call = P::InvisiProtocolCalls::abi_decode(&self.unsigned_call, true)
            .map_err(|e| e.to_string())?;
        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                Ok(OutputHistory {
                    recipient: output
                        .note
                        .as_ref()
                        .map(|note| word_address(note.owner_address))
                        .transpose()?,
                    amount: output.amount,
                    payload: output
                        .note
                        .as_ref()
                        .map_or_else(Vec::new, |note| note.payload.clone()),
                    commitment: output.commitment,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let credits = self
            .states
            .iter()
            .map(|state| {
                Ok(CreditHistory {
                    owner: word_address(state.note.owner_wallet_identity)?,
                    spender: word_address(state.note.spender_wallet_identity)?,
                    available_credit: state.note.available_credit,
                    unlimited: state.note.unlimited,
                    expiry: state.note.expiry,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let funding = |value: &abi::FundingParams| FundingHistory {
            payer: value.payer,
            amount: value.amount,
            authorization: if value.amount == U256::ZERO {
                "none"
            } else if value.signature.is_empty() {
                "caller"
            } else {
                "signature"
            },
        };
        let (token, fee_recipient, fee_amount, funding, withdrawal) = match call {
            P::InvisiProtocolCalls::shield(c) => (
                c.p.token,
                c.p.feeRecipient,
                c.p.feeAmount,
                Some(funding(&c._3)),
                None,
            ),
            P::InvisiProtocolCalls::transact_0(c) => (
                c.r.params.token,
                c.r.params.feeRecipient,
                c.r.params.feeAmount,
                Some(funding(&c.r.funding)),
                if c.r.params.withdrawalAmount == U256::ZERO {
                    None
                } else {
                    Some((c.r.params.withdrawalAddress, c.r.params.withdrawalAmount))
                },
            ),
            P::InvisiProtocolCalls::createCredit(c) => {
                (c.p.token, c.p.feeRecipient, c.p.feeAmount, None, None)
            }
            P::InvisiProtocolCalls::updateCredit(c) => {
                (c.p.token, c.p.feeRecipient, c.p.feeAmount, None, None)
            }
            P::InvisiProtocolCalls::creditDraw(c) => {
                (c.p.token, c.p.feeRecipient, c.p.feeAmount, None, None)
            }
            P::InvisiProtocolCalls::revokeCredit(c) => {
                (c.token, c.feeRecipient, c.feeAmount, None, None)
            }
            _ => return Err("unsupported saved business intent".into()),
        };
        if token != self.token {
            return Err("saved history token mismatch".into());
        }
        Ok(PreparedHistory {
            token,
            outputs,
            credits,
            funding,
            withdrawal,
            fee_recipient,
            fee_amount,
        })
    }
}
