//! Managed native wallets: explicit host requests, authenticated receipts and atomic private state.
use crate::{
    delivery::{CreditDeliveryState, CreditRole},
    note::ProtocolContext,
    rpc::CanonicalBlock,
    sdk::{self, Invisi, NoteInput, Wallet},
};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
pub type Result<T> = std::result::Result<T, String>;
mod store;
pub use store::*;
mod history;
pub use history::*;
mod status;
pub use status::*;
mod sync;
pub use sync::*;
mod journal;
pub use journal::*;
mod preparation;
pub use preparation::RetainedPreparation;
mod transaction;
pub use transaction::*;
mod operation;
pub use operation::*;
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletScope {
    pub namespace: String,
    pub context: ProtocolContext,
    pub owner_address: Address,
}
impl WalletScope {
    pub fn key(&self) -> String {
        serde_json::to_string(self).expect("serializable scope")
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredNote {
    #[serde(with = "note_input_codec")]
    pub input: NoteInput,
    pub commitment: B256,
    pub nullifier: B256,
    pub block: CanonicalBlock,
    pub transaction_hash: B256,
    pub spent: bool,
    pub reserved_by: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredCredit {
    pub delivery: CreditDeliveryState,
    pub commitment: B256,
    pub nullifier: B256,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub path: [U256; 16],
    pub root: U256,
    pub block: CanonicalBlock,
    pub transaction_hash: B256,
    pub role: CreditRole,
    pub consumed: bool,
    pub revoked: bool,
    pub reserved_by: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct UnresolvedDelivery {
    pub receipt: crate::rpc::CanonicalReceipt,
    pub key: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletState {
    #[serde(default)]
    pub preparation_snapshot: Option<RetainedPreparation>,
    pub format_version: u32,
    pub scope: Option<WalletScope>,
    pub revision: u64,
    pub notes: BTreeMap<B256, StoredNote>,
    pub credits: BTreeMap<String, StoredCredit>,
    pub operations: BTreeMap<String, OperationRecord>,
    pub observed_through: Option<CanonicalBlock>,
    pub discovery_through: Option<CanonicalBlock>,
    pub invalidated: bool,
    #[serde(default)]
    pub discovery_ranges: Vec<crate::public_history::CoverageRange>,
    #[serde(default)]
    pub unresolved_deliveries: BTreeMap<String, UnresolvedDelivery>,
    #[serde(default)]
    pub unresolved_delivery_count: Option<usize>,
    #[serde(default)]
    pub public_history_generation: Option<u64>,
    #[serde(default)]
    pub recovery_boundary: Option<u64>,
    #[serde(default)]
    pub credit_replay_from: Option<u64>,
    #[serde(default)]
    pub credit_replay_target: Option<u64>,
    #[serde(default)]
    pub credit_replay_revision: u64,
    #[serde(default)]
    pub credit_replay_through: Option<u64>,
}
impl Default for WalletState {
    fn default() -> Self {
        Self {
            preparation_snapshot: None,
            format_version: 2,
            scope: None,
            revision: 0,
            notes: BTreeMap::new(),
            credits: BTreeMap::new(),
            operations: BTreeMap::new(),
            observed_through: None,
            discovery_through: None,
            invalidated: false,
            unresolved_deliveries: BTreeMap::new(),
            unresolved_delivery_count: None,
            discovery_ranges: vec![],
            public_history_generation: None,
            recovery_boundary: None,
            credit_replay_from: None,
            credit_replay_target: None,
            credit_replay_revision: 0,
            credit_replay_through: None,
        }
    }
}
impl std::fmt::Debug for WalletState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletState")
            .field("revision", &self.revision)
            .field("notes", &self.notes.len())
            .field("credits", &self.credits.len())
            .field("operations", &self.operations.len())
            .field("invalidated", &self.invalidated)
            .finish()
    }
}
pub(crate) fn credit_key(commitment: B256, role: CreditRole) -> String {
    format!("{commitment}:{role:?}")
}
#[derive(Clone)]
pub struct WalletSession {
    validated_snapshot: Arc<std::sync::Mutex<Option<[u8; 32]>>>,
    pub(crate) invisi: Invisi,
    pub(crate) wallet: Wallet,
    pub(crate) scope: WalletScope,
    pub(crate) store: Arc<dyn WalletStore>,
    pub(crate) source: Arc<dyn SessionSource>,
    pub(crate) public_history: Option<Arc<crate::public_history::PublicHistory>>,
}
impl std::fmt::Debug for WalletSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSession")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl WalletSession {
    pub fn connect(
        invisi: Invisi,
        wallet: Wallet,
        store: Arc<dyn WalletStore>,
        source: Arc<dyn SessionSource>,
        namespace: impl Into<String>,
    ) -> Result<Self> {
        let namespace = namespace.into();
        if namespace.is_empty() || namespace.len() > 128 || !namespace.is_ascii() {
            return Err("invalid wallet namespace".into());
        }
        let context = source.context();
        context.validate().map_err(|e| e.to_string())?;
        let scope = WalletScope {
            namespace,
            context,
            owner_address: wallet.owner_address(),
        };
        let mut session = Self {
            validated_snapshot: Arc::new(std::sync::Mutex::new(None)),
            invisi,
            wallet,
            scope,
            store,
            source,
            public_history: None,
        };
        let state = session.store.snapshot(&session.scope.key())?;
        if session.cached_preparation(&state)?.is_none() {
            if session.invisi.chain.context() != context {
                return Err("session chain deployment mismatch".into());
            }
            session.invisi.chain.snapshot()?;
        }
        if let Some(runtime_code_hash) = session.source.runtime_code_hash() {
            let public_scope = crate::public_history::PublicHistoryScope {
                chain_id: context.chain_id,
                protocol_address: sdk::word_address(context.protocol_address)?,
                runtime_code_hash,
                deployment_block: session.source.deployment_start(),
            };
            let store = crate::public_history::ephemeral_store(
                Arc::as_ptr(&session.invisi.chain) as *const () as usize,
                &public_scope,
            )?;
            session.public_history = Some(Arc::new(crate::public_history::PublicHistory::new(
                store,
                public_scope,
                session.source.clone(),
            )?));
        }
        session.snapshot()?;
        Ok(session)
    }
    pub fn with_public_history(
        mut self,
        history: Arc<crate::public_history::PublicHistory>,
    ) -> Result<Self> {
        if history.scope.chain_id != self.scope.context.chain_id
            || history.scope.protocol_address
                != sdk::word_address(self.scope.context.protocol_address)?
            || history.scope.deployment_block != self.source.deployment_start()
            || self
                .source
                .runtime_code_hash()
                .is_some_and(|h| h != history.scope.runtime_code_hash)
        {
            return Err("session public history deployment mismatch".into());
        }
        self.public_history = Some(history);
        Ok(self)
    }
    pub(crate) fn fence_public_history(&self) -> Result<()> {
        if let Some(history) = &self.public_history {
            let public = history.snapshot()?;
            let state = self.store.read_summary(&self.scope.key())?;
            let generation =
                state
                    .public_history_generation
                    .unwrap_or(if state.observed_through.is_some() {
                        1
                    } else {
                        public.generation
                    });
            if generation != public.generation && !state.invalidated {
                self.invalidate_reorg_from(
                    public.reorg_from.unwrap_or(self.source.deployment_start()),
                )?;
            }
        }
        Ok(())
    }
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
    pub fn scope(&self) -> &WalletScope {
        &self.scope
    }
    pub fn snapshot(&self) -> Result<WalletState> {
        self.fence_public_history()?;
        let state = self.store.snapshot(&self.scope.key())?;
        if state.format_version != 2
            || state
                .scope
                .as_ref()
                .is_some_and(|scope| scope != &self.scope)
            || state.revision > 0 && state.scope.is_none()
        {
            return Err("wallet state schema or scope mismatch".into());
        }
        self.cached_preparation(&state)?;
        use sha2::{Digest, Sha256};
        let raw = zeroize::Zeroizing::new(
            serde_json::to_vec(&state).map_err(|_| "wallet validation encoding failed")?,
        );
        let digest: [u8; 32] = Sha256::digest(&*raw).into();
        if *self
            .validated_snapshot
            .lock()
            .map_err(|_| "wallet validation cache poisoned")?
            == Some(digest)
        {
            return Ok(state);
        }
        for (commitment, stored) in &state.notes {
            stored.input.validate(
                self.wallet.owner_address(),
                self.scope.context,
                sdk::word_address(stored.input.note.token_address)?,
            )?;
            if *commitment != stored.commitment
                || sdk::field_word(stored.input.note.commitment().map_err(|e| e.to_string())?)
                    != *commitment
                || sdk::field_word(stored.input.note.nullifier().map_err(|e| e.to_string())?)
                    != stored.nullifier
            {
                return Err("stored Note identity mismatch".into());
            }
            if stored.reserved_by.as_ref().is_some_and(|id| {
                !state.operations.get(id).is_some_and(|op| {
                    !op.status.terminal() && op.inputs.contains(&format!("note:{commitment}"))
                })
            }) {
                return Err("stored Note reservation mismatch".into());
            }
        }
        for (key, stored) in &state.credits {
            stored.delivery.validate().map_err(|e| e.to_string())?;
            let identity = if stored.role == CreditRole::Owner {
                stored.delivery.note.owner_wallet_identity
            } else {
                stored.delivery.note.spender_wallet_identity
            };
            if *key != credit_key(stored.commitment, stored.role)
                || stored.delivery.note.context != self.scope.context
                || identity != sdk::address_word(self.wallet.owner_address())
                || sdk::field_word(
                    stored
                        .delivery
                        .note
                        .commitment()
                        .map_err(|e| e.to_string())?,
                ) != stored.commitment
                || sdk::field_word(
                    stored
                        .delivery
                        .note
                        .nullifier()
                        .map_err(|e| e.to_string())?,
                ) != stored.nullifier
                || sdk::merkle_root(
                    U256::from_be_slice(stored.commitment.as_slice()),
                    stored.leaf_index,
                    &stored.path,
                )? != stored.root
            {
                return Err("stored Credit identity mismatch".into());
            }
            if stored.reserved_by.as_ref().is_some_and(|id| {
                !state.operations.get(id).is_some_and(|op| {
                    !op.status.terminal()
                        && op.inputs.contains(&format!("credit:{}", stored.commitment))
                })
            }) {
                return Err("stored Credit reservation mismatch".into());
            }
        }
        for (id, operation) in &state.operations {
            if operation.id != *id || operation.snapshot.context() != self.scope.context {
                return Err("stored operation scope mismatch".into());
            }
        }
        *self
            .validated_snapshot
            .lock()
            .map_err(|_| "wallet validation cache poisoned")? = Some(digest);
        Ok(state)
    }
    pub(crate) fn commit(&self, mut next: WalletState) -> Result<()> {
        next.scope = Some(self.scope.clone());
        let revision = next.revision;
        self.store
            .compare_and_swap(&self.scope.key(), revision, next)
    }
    pub fn balance(&self, token: Address) -> Result<Balance> {
        self.fence_public_history()?;
        let state = self.snapshot()?;
        let mut known = U256::ZERO;
        let mut reserved = U256::ZERO;
        for note in state
            .notes
            .values()
            .filter(|note| note.input.note.token_address == sdk::address_word(token) && !note.spent)
        {
            known = known
                .checked_add(note.input.note.amount)
                .ok_or("balance overflow")?;
            if note.reserved_by.is_some() {
                reserved = reserved
                    .checked_add(note.input.note.amount)
                    .ok_or("reserved balance overflow")?;
            }
        }
        Ok(Balance {
            known,
            reserved,
            available: if state.invalidated || state.observed_through.is_none() {
                None
            } else {
                Some(known - reserved)
            },
            checked_through: state.observed_through,
            invalidated: state.invalidated,
        })
    }
    pub fn history(&self, token: Option<Address>) -> Result<WalletHistory> {
        self.fence_public_history()?;
        let public_generation = self.history_generation()?;
        let state = self.store.full_snapshot(&self.scope.key())?;
        let mut incoming: Vec<IncomingHistory> = state
            .notes
            .values()
            .filter(|n| {
                token.is_none_or(|token| n.input.note.token_address == sdk::address_word(token))
            })
            .map(|n| IncomingHistory {
                commitment: n.commitment,
                tree_id: n.input.tree_id,
                leaf_index: n.input.leaf_index,
                token: sdk::word_address(n.input.note.token_address).expect("validated token"),
                amount: n.input.note.amount,
                payload: n.input.note.payload.clone(),
                transaction_hash: n.transaction_hash,
                block: n.block.clone(),
                spent: n.spent,
                reserved_by: n.reserved_by.clone(),
            })
            .collect();
        let mut outgoing = state
            .operations
            .values()
            .filter(|o| token.is_none_or(|token| o.snapshot.token() == token))
            .map(|o| {
                Ok(OutgoingHistory {
                    id: o.id.clone(),
                    kind: o.kind.clone(),
                    status: o.status,
                    transaction_hash: o.transaction_hash,
                    deadline: o.deadline,
                    prepared_at: o.snapshot.anchor().clone(),
                    token: o.snapshot.token(),
                    input_count: o.inputs.len(),
                    intent: o.snapshot.history()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        incoming.sort_by_key(|entry: &IncomingHistory| {
            (
                std::cmp::Reverse(entry.block.number),
                entry.tree_id,
                entry.leaf_index,
                entry.commitment,
            )
        });
        outgoing.sort_by_key(|entry| {
            (
                std::cmp::Reverse(entry.prepared_at.number),
                entry.id.clone(),
            )
        });
        self.ensure_history_generation(public_generation, state.revision)?;
        Ok(WalletHistory {
            scope: self.scope.clone(),
            revision: state.revision,
            checked_through: state.discovery_through,
            incoming,
            outgoing,
            invalidated: state.invalidated,
        })
    }
    pub fn credit_inventory(
        &self,
        token: Option<Address>,
        role: Option<CreditRole>,
    ) -> Result<Vec<(String, StoredCredit)>> {
        let state = self.snapshot()?;
        Ok(state
            .credits
            .into_iter()
            .filter(|(_, record)| {
                token.is_none_or(|token| {
                    record.delivery.note.token_address == sdk::address_word(token)
                }) && role.is_none_or(|role| record.role == role)
            })
            .collect())
    }
    pub(crate) fn terminal_is_canonical(&self, operation: &OperationRecord) -> bool {
        operation.status == OperationStatus::Failed
            || operation.status.terminal()
                && operation
                    .resolved_at
                    .as_ref()
                    .is_some_and(|block| self.invisi.chain.canonical(block).is_ok())
    }
    pub fn invalidate_reorg(&self) -> Result<()> {
        self.invalidate_reorg_from(self.source.deployment_start())
    }
    fn invalidate_reorg_from(&self, from: u64) -> Result<()> {
        self.store.recover_reorg(&self.scope.key(), from)?;
        let mut state = self.store.snapshot(&self.scope.key())?;
        state
            .unresolved_deliveries
            .retain(|_, v| v.receipt.block.number < from);
        state.unresolved_delivery_count = Some(state.unresolved_deliveries.len());
        state.preparation_snapshot = None;
        state.invalidated = true;
        state.observed_through = None;
        state.discovery_through = None;
        for operation in state.operations.values_mut() {
            if !self.terminal_is_canonical(operation) {
                operation.status = OperationStatus::Reorged;
                operation.resolved_at = None;
                operation.generation = operation
                    .generation
                    .checked_add(1)
                    .ok_or("operation generation exhausted")?;
            }
        }
        self.commit(state)
    }
}
#[derive(Clone, Debug)]
pub struct Balance {
    pub known: U256,
    pub reserved: U256,
    pub available: Option<U256>,
    pub checked_through: Option<CanonicalBlock>,
    pub invalidated: bool,
}
#[derive(Clone, Debug)]
pub struct IncomingHistory {
    pub commitment: B256,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub token: Address,
    pub amount: U256,
    pub payload: Vec<u8>,
    pub transaction_hash: B256,
    pub block: CanonicalBlock,
    pub spent: bool,
    pub reserved_by: Option<String>,
}
#[derive(Clone, Debug)]
pub struct OutgoingHistory {
    pub id: String,
    pub kind: String,
    pub status: OperationStatus,
    pub transaction_hash: Option<B256>,
    pub deadline: u64,
    pub prepared_at: CanonicalBlock,
    pub token: Address,
    pub input_count: usize,
    pub intent: crate::sdk::journal::PreparedHistory,
}
#[derive(Clone, Debug)]
pub struct WalletHistory {
    pub checked_through: Option<CanonicalBlock>,
    pub scope: WalletScope,
    pub revision: u64,
    pub incoming: Vec<IncomingHistory>,
    pub outgoing: Vec<OutgoingHistory>,
    pub invalidated: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct NoteInputRecord {
    pub note: crate::note::Note,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub path: [U256; 16],
    pub root: U256,
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
mod note_input_codec {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        v: &NoteInput,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        NoteInputRecord::from(v).serialize(s)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<NoteInput, D::Error> {
        Ok(NoteInputRecord::deserialize(d)?.into())
    }
}

#[cfg(test)]
mod tests;
