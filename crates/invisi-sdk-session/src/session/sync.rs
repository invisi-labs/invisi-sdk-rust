use super::*;
use crate::{
    protocol::{self, InvisiCore as P},
    rpc::{
        self, CanonicalHead, CanonicalReceipt, CanonicalTransaction, ChainReceipts,
        ChainTransactions, Membership, MembershipInput, ProtocolRpcClient, RpcTransport,
    },
};
use std::{collections::BTreeSet, sync::Mutex};

/// Indexed discovery chooses candidates; receipts and membership follow the configured chain reader.
/// With `TrustedProvider`, chain facts are trusted service assertions rather than independent reads.
pub trait SessionSource: Send + Sync {
    fn context(&self) -> ProtocolContext;
    fn deployment_start(&self) -> u64;
    fn runtime_code_hash(&self) -> Option<B256> {
        None
    }
    fn indexed_head(&self) -> Result<CanonicalBlock>;
    fn known_head(&self) -> Result<CanonicalBlock> {
        self.indexed_head()
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock>;
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>>;
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>>;
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>>;
    fn membership(&self, input: &MembershipInput, block: &CanonicalBlock) -> Result<Membership>;
    fn known_root(&self, _tree: u64, _root: B256, _block: &CanonicalBlock) -> Result<bool> {
        Err("shared public proofs require canonical root verification".into())
    }
}
impl<T: RpcTransport, C: CanonicalHead + ChainReceipts + ChainTransactions> SessionSource
    for ProtocolRpcClient<T, C>
{
    fn context(&self) -> ProtocolContext {
        ProtocolContext {
            chain_id: self.deployment().chain_id().expect("validated deployment"),
            protocol_address: sdk::address_word(self.deployment().protocol.address),
        }
    }
    fn deployment_start(&self) -> u64 {
        self.deployment().protocol.from_block
    }
    fn runtime_code_hash(&self) -> Option<B256> {
        Some(self.deployment().protocol.runtime_code_hash)
    }
    fn known_root(&self, tree: u64, root: B256, block: &CanonicalBlock) -> Result<bool> {
        use alloy_sol_types::SolCall;
        if self.chain.block(block.number).map_err(|e| e.to_string())? != *block {
            return Err("canonical root block changed".into());
        }
        let data = P::rootHistoryCall {
            _0: U256::from(tree),
            _1: root,
        }
        .abi_encode();
        let data = self
            .chain
            .call(self.deployment().protocol.address, &data, block.number)
            .map_err(|e| e.to_string())?;
        if data.len() != 32 {
            return Err("invalid canonical root response".into());
        }
        let value = U256::from_be_slice(&data);
        if value > U256::from(1) {
            return Err("noncanonical root boolean".into());
        }
        if self.chain.block(block.number).map_err(|e| e.to_string())? != *block {
            return Err("canonical root block changed".into());
        }
        Ok(value == U256::from(1))
    }

    fn known_head(&self) -> Result<CanonicalBlock> {
        self.chain.head().map_err(|e| e.to_string())
    }
    fn indexed_head(&self) -> Result<CanonicalBlock> {
        self.get_status()
            .map_err(|e| e.to_string())?
            .indexed_head
            .ok_or_else(|| "Protocol RPC has no indexed head".into())
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        self.chain.block(number).map_err(|e| e.to_string())
    }
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>> {
        let notes = self.get_note_updates(from, to).map_err(|e| e.to_string())?;
        let credits = self
            .get_credit_transitions(from, to)
            .map_err(|e| e.to_string())?;
        if notes.block != credits.block {
            return Err("indexed discovery anchor mismatch".into());
        }
        Ok(notes
            .items
            .into_iter()
            .map(|v| v.leaf.transaction_hash)
            .chain(credits.items.into_iter().map(|v| v.transaction_hash))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        self.chain.receipt(hash).map_err(|e| e.to_string())
    }
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>> {
        self.chain.transaction(hash).map_err(|e| e.to_string())
    }
    fn membership(&self, input: &MembershipInput, block: &CanonicalBlock) -> Result<Membership> {
        self.get_membership(input, block).map_err(|e| e.to_string())
    }
}
#[derive(Clone, Debug)]
pub struct RefreshOptions {
    pub from_block: u64,
    pub to_block: Option<u64>,
    pub page_size: u64,
    pub reset: bool,
}
impl RefreshOptions {
    pub fn from_block(from_block: u64) -> Self {
        Self {
            from_block,
            to_block: None,
            page_size: 10000,
            reset: false,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RefreshResult {
    pub block: CanonicalBlock,
    pub notes: usize,
    pub credits: usize,
    pub revision: u64,
}
#[derive(Clone)]
enum Candidate {
    Note(rpc::NoteOutput),
    Credit(rpc::IndexedCreditState, CreditRole),
}
#[derive(Clone)]
enum Decoded {
    Note(crate::note::Note),
    Credit(CreditDeliveryState),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApplyState {
    Pending,
    Applying,
    Applied,
}
pub struct PendingWalletRefresh {
    session: WalletSession,
    base: WalletState,
    anchor: CanonicalBlock,
    receipts: Vec<CanonicalReceipt>,
    candidates: BTreeMap<String, Candidate>,
    options: RefreshOptions,
    apply_state: Mutex<ApplyState>,
    pub(crate) completion: Option<Vec<(String, u64, bool)>>,
    pub(super) public_generation: Option<u64>,
    discovery_block: CanonicalBlock,
    queue_credit_replay: bool,
    replay_advance: Option<(u64, u64, u64)>,
    cancellation: Option<crate::public_history::CancellationToken>,
    pub(super) offline: bool,
    memberships: Vec<crate::public_history::CachedMembership>,
}
impl std::fmt::Debug for PendingWalletRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingWalletRefresh")
            .field("block", &self.anchor)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}
impl WalletSession {
    pub fn refresh(&self, options: RefreshOptions) -> Result<PendingWalletRefresh> {
        let mut base = self.snapshot()?;
        if let Some(history) = &self.public_history {
            let generation = history.snapshot()?.generation;
            if base
                .public_history_generation
                .is_some_and(|g| g != generation)
                && !base.invalidated
            {
                self.store.recover_reorg(
                    &self.scope.key(),
                    history
                        .snapshot()?
                        .reorg_from
                        .unwrap_or(self.source.deployment_start()),
                )?;
                base = self.snapshot()?;
                base.invalidated = true;
                self.commit(base.clone())?;
                base = self.snapshot()?;
            }
        }
        if base.invalidated && !options.reset {
            return Err("wallet requires canonical resync".into());
        }
        if options.from_block < self.source.deployment_start()
            || options.page_size == 0
            || options.page_size > rpc::MAX_UPDATE_BLOCKS
        {
            return Err("invalid refresh range or page size".into());
        }
        let head = self.source.indexed_head()?;
        let to = options.to_block.unwrap_or(head.number);
        if to < options.from_block || to > head.number {
            return Err("refresh outside indexed history".into());
        }
        let anchor = self.source.block(to)?;
        if anchor.number != to {
            return Err("wrong refresh block".into());
        }
        self.invisi.chain.canonical(&anchor)?;
        if !options.reset {
            if let Some(previous) = &base.observed_through {
                self.invisi.chain.canonical(previous)?;
            }
        }
        if let Some(history) = &self.public_history {
            let mut receipts = vec![];
            let mut generation = None;
            let mut start = options.from_block;
            loop {
                let end = start.saturating_add(options.page_size.min(256) - 1).min(to);
                let (page, acquired_generation) = history.acquire(
                    start,
                    end,
                    &crate::public_history::CancellationToken::default(),
                )?;
                if generation.is_some_and(|g| g != acquired_generation) {
                    return Err("public history generation changed during acquisition".into());
                }
                generation = Some(acquired_generation);
                receipts.extend(page.receipts);
                if end == to {
                    break;
                }
                start = end + 1;
            }
            let mut pending = self.stage_refresh(base, anchor, receipts, options, None)?;
            pending.bind_acquired_generation(
                generation.ok_or("public acquisition generation missing")?,
            )?;
            return Ok(pending);
        }
        let mut transactions = BTreeSet::new();
        let mut start = options.from_block;
        loop {
            let end = start.saturating_add(options.page_size - 1).min(to);
            transactions.extend(self.source.discover(start, end)?);
            if end == to {
                break;
            }
            start = end.checked_add(1).ok_or("refresh range overflow")?;
        }
        let mut receipts = Vec::new();
        for hash in transactions {
            if hash == B256::ZERO {
                return Err("zero discovery transaction hash".into());
            }
            let receipt = self
                .source
                .receipt(hash)?
                .ok_or("missing canonical candidate receipt")?;
            if receipt.transaction_hash != hash
                || !receipt.success
                || receipt.block.number < options.from_block
                || receipt.block.number > to
            {
                return Err("candidate receipt outside selected canonical range".into());
            }
            self.invisi.chain.canonical(&receipt.block)?;
            receipts.push(receipt);
        }
        receipts.sort_by_key(|r| (r.block.number, r.logs.first().map_or(0, |l| l.log_index)));
        self.stage_refresh(base, anchor, receipts, options, None)
    }
    pub(crate) fn stage_refresh(
        &self,
        base: WalletState,
        anchor: CanonicalBlock,
        receipts: Vec<CanonicalReceipt>,
        options: RefreshOptions,
        completion: Option<Vec<(String, u64, bool)>>,
    ) -> Result<PendingWalletRefresh> {
        let mut candidates = BTreeMap::new();
        let mut keys = BTreeSet::new();
        let protocol = sdk::word_address(self.scope.context.protocol_address)?;
        for receipt in &receipts {
            if !receipt.success {
                continue;
            }
            let decoded = protocol::decode_receipt_outputs(protocol, receipt)?;
            for note in decoded.notes {
                if note.delivery.ciphertext.is_empty() {
                    continue;
                }
                let key = format!(
                    "{}:{}:{}:funds",
                    receipt.transaction_hash, note.leaf.tree_id, note.leaf.leaf_index
                );
                if !keys.insert(key.clone()) {
                    continue;
                }
                candidates.insert(key, Candidate::Note(note));
            }
            for credit in decoded.credits {
                for role in [CreditRole::Owner, CreditRole::Spender] {
                    let key = format!(
                        "{}:{}:{}:{role:?}",
                        receipt.transaction_hash, credit.leaf.tree_id, credit.leaf.leaf_index
                    );
                    if !keys.insert(key.clone()) {
                        continue;
                    }
                    candidates.insert(key, Candidate::Credit(credit.clone(), role));
                }
            }
        }
        Ok(PendingWalletRefresh {
            session: self.clone(),
            base,
            discovery_block: anchor.clone(),
            queue_credit_replay: false,
            replay_advance: None,
            cancellation: None,
            offline: false,
            memberships: vec![],
            anchor,
            receipts,
            candidates,
            options,
            apply_state: Mutex::new(ApplyState::Pending),
            completion,
            public_generation: self
                .public_history
                .as_ref()
                .map(|h| h.snapshot().map(|s| s.generation))
                .transpose()?,
        })
    }
    pub(crate) fn verified_membership(
        &self,
        leaf: &rpc::LeafMetadata,
        anchor: &CanonicalBlock,
    ) -> Result<(U256, [U256; 16])> {
        let input = MembershipInput {
            tree_id: leaf.tree_id,
            leaf_index: leaf.leaf_index,
            commitment: leaf.commitment,
            root: None,
        };
        let proof = self.source.membership(&input, anchor)?;
        if proof.block != *anchor
            || proof.tree_id != leaf.tree_id
            || proof.leaf_index != leaf.leaf_index
            || proof.leaf != leaf.commitment
            || proof.path.len() != 16
        {
            return Err("membership response binding mismatch".into());
        }
        let root = U256::from_be_slice(proof.root.as_slice());
        let path: Vec<U256> = proof
            .path
            .iter()
            .map(|v| U256::from_be_slice(v.as_slice()))
            .collect();
        let path: [U256; 16] = path.try_into().map_err(|_| "membership depth mismatch")?;
        if sdk::merkle_root(
            U256::from_be_slice(leaf.commitment.as_slice()),
            u16::try_from(leaf.leaf_index).map_err(|_| "leaf index overflow")?,
            &path,
        )? != root
            || !self
                .invisi
                .chain
                .known_root(leaf.tree_id, proof.root, anchor)?
        {
            return Err("membership proof or canonical root mismatch".into());
        }
        Ok((root, path))
    }
}
impl PendingWalletRefresh {
    pub(super) fn bind_acquired_generation(&mut self, generation: u64) -> Result<()> {
        self.public_generation = Some(generation);
        if self
            .session
            .public_history
            .as_ref()
            .ok_or("public history unavailable")?
            .snapshot()?
            .generation
            != generation
        {
            return Err("public history generation changed during page handoff".into());
        }
        Ok(())
    }
    pub fn block(&self) -> &CanonicalBlock {
        &self.anchor
    }
    pub fn decrypt(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
    ) -> Result<RefreshResult> {
        {
            let mut status = self
                .apply_state
                .lock()
                .map_err(|_| "refresh lock poisoned")?;
            if *status != ApplyState::Pending {
                return Err("wallet refresh already applying or applied".into());
            }
            *status = ApplyState::Applying;
        }
        let result = self.apply(decryptor);
        let mut status = self
            .apply_state
            .lock()
            .map_err(|_| "refresh lock poisoned")?;
        *status = if result.is_ok() {
            ApplyState::Applied
        } else {
            ApplyState::Pending
        };
        result
    }
    fn apply(&self, decryptor: &dyn crate::delivery::DeliveryDecryptor) -> Result<RefreshResult> {
        let session = &self.session;
        if let Some(token) = &self.cancellation {
            token.check()?;
        }
        if session.snapshot()?.revision != self.base.revision {
            return Err("wallet changed; prepare refresh again".into());
        }
        let mut decoded = Vec::new();
        let mut unresolved = if self.options.reset {
            BTreeMap::new()
        } else {
            self.base.unresolved_deliveries.clone()
        };
        let candidates = self.candidates.iter().collect::<Vec<_>>();
        let detection = candidates
            .iter()
            .map(|(_, candidate)| {
                let (leaf, clue, role) = match candidate {
                    Candidate::Note(v) => (
                        &v.leaf,
                        v.delivery.clue.clone(),
                        crate::delivery::DeliveryRole::Funds,
                    ),
                    Candidate::Credit(v, r) => (
                        &v.leaf,
                        v.deliveries[if *r == CreditRole::Owner { 0 } else { 1 }]
                            .clue
                            .clone(),
                        if *r == CreditRole::Owner {
                            crate::delivery::DeliveryRole::Owner
                        } else {
                            crate::delivery::DeliveryRole::Spender
                        },
                    ),
                };
                crate::delivery::DetectionCandidate {
                    clue,
                    context: crate::delivery::DeliveryContext {
                        context: session.scope.context,
                        token_address: sdk::address_word(leaf.token),
                        output_commitment: U256::from_be_slice(leaf.commitment.as_slice()),
                    },
                    owner: sdk::address_word(session.wallet.owner_address()),
                    role,
                }
            })
            .collect::<Vec<_>>();
        let mut detected = vec![];
        for batch in detection.chunks(1024) {
            let matches = decryptor.detect(batch)?;
            if matches.len() != batch.len() {
                return Err("native detection result count mismatch".into());
            }
            detected.extend(matches);
        }
        if detected.len() != candidates.len() {
            return Err("native detection result count mismatch".into());
        }
        for (((key, candidate), context), detected) in
            candidates.into_iter().zip(detection.iter()).zip(detected)
        {
            if !detected {
                unresolved.remove(key);
                continue;
            }
            let (leaf, outcome) = match candidate {
                Candidate::Note(note) => (
                    &note.leaf,
                    decryptor.decrypt_note_outcome(
                        &note.delivery.ciphertext,
                        &context.context,
                        context.owner,
                    )?,
                ),
                Candidate::Credit(credit, role) => (
                    &credit.leaf,
                    decryptor.decrypt_credit_outcome(
                        &credit.deliveries[if *role == CreditRole::Owner { 0 } else { 1 }]
                            .ciphertext,
                        &context.context,
                        *role,
                        context.owner,
                    )?,
                ),
            };
            let plain = match outcome {
                crate::delivery::DecryptionOutcome::NonRecipient => {
                    unresolved.remove(key);
                    continue;
                }
                crate::delivery::DecryptionOutcome::AuthenticationFailed => {
                    let receipt = self
                        .receipts
                        .iter()
                        .find(|r| r.transaction_hash == leaf.transaction_hash)
                        .ok_or("unresolved receipt unavailable")?;
                    unresolved.insert(
                        key.clone(),
                        UnresolvedDelivery {
                            receipt: receipt.clone(),
                            key: key.clone(),
                        },
                    );
                    continue;
                }
                crate::delivery::DecryptionOutcome::Plaintext(p) => p,
            };
            let fixed = AuthenticatedPlaintext(zeroize::Zeroizing::new(plain));
            let value = match candidate {
                Candidate::Note(note) => Decoded::Note(
                    session
                        .wallet
                        .decrypt_note(&fixed, &note.delivery.ciphertext, &context.context)?
                        .ok_or("authenticated plaintext missing")?,
                ),
                Candidate::Credit(credit, role) => Decoded::Credit(
                    session
                        .wallet
                        .decrypt_credit(
                            &fixed,
                            &credit.deliveries[if *role == CreditRole::Owner { 0 } else { 1 }]
                                .ciphertext,
                            &context.context,
                            *role,
                        )?
                        .ok_or("authenticated plaintext missing")?,
                ),
            };
            unresolved.remove(key);
            decoded.push((candidate.clone(), value));
        }
        if session.source.context() != session.scope.context
            || !self.offline && session.source.block(self.anchor.number)? != self.anchor
        {
            return Err("canonical refresh anchor changed".into());
        }
        if !self.offline {
            session.invisi.chain.canonical(&self.anchor)?;
            for receipt in &self.receipts {
                if self.public_generation.is_none()
                    && session.source.receipt(receipt.transaction_hash)?.as_ref() != Some(receipt)
                {
                    return Err("canonical candidate receipt changed".into());
                }
                session.invisi.chain.canonical(&receipt.block)?;
            }
        }
        if let (Some(history), Some(generation)) = (&session.public_history, self.public_generation)
        {
            if history.snapshot()?.generation != generation {
                return Err("public history generation changed".into());
            }
        }
        let mut next = self.base.clone();
        next.unresolved_delivery_count = Some(unresolved.len());
        next.unresolved_deliveries = unresolved;
        if self.options.reset {
            next.notes.clear();
            next.credits.clear();
            next.invalidated = false;
            next.observed_through = None;
            next.discovery_through = None;
            next.discovery_ranges.clear();
            for record in next.operations.values_mut() {
                if if self.offline {
                    record.status != OperationStatus::Failed
                } else {
                    !session.terminal_is_canonical(record)
                } {
                    record.status = OperationStatus::Reorged;
                    record.generation = record
                        .generation
                        .checked_add(1)
                        .ok_or("operation generation exhausted")?;
                    record.resolved_at = None;
                }
            }
        }
        let mut fresh_roots = BTreeSet::new();
        let mut note_count = 0;
        let mut credit_count = 0;
        for (candidate, value) in decoded {
            match (candidate, value) {
                (Candidate::Note(output), Decoded::Note(note)) => {
                    if note.context != session.scope.context
                        || note.token_address != sdk::address_word(output.leaf.token)
                        || sdk::field_word(note.commitment().map_err(|e| e.to_string())?)
                            != output.leaf.commitment
                    {
                        return Err("decoded Note receipt context mismatch".into());
                    }
                    let (root, path) = membership_for(
                        session,
                        &output.leaf,
                        &self.anchor,
                        if self.offline {
                            Some(&self.memberships)
                        } else {
                            None
                        },
                    )?;
                    fresh_roots.insert((output.leaf.tree_id, sdk::field_word(root)));
                    let nullifier = sdk::field_word(note.nullifier().map_err(|e| e.to_string())?);
                    let reserved_by =
                        reservation_for(&next, &format!("note:{}", output.leaf.commitment));
                    if let Some(previous) = next.notes.get(&output.leaf.commitment) {
                        if previous.input.note != note
                            || previous.input.tree_id != output.leaf.tree_id
                            || previous.input.leaf_index as u32 != output.leaf.leaf_index
                            || previous.transaction_hash != B256::ZERO
                                && previous.transaction_hash != output.leaf.transaction_hash
                        {
                            return Err("conflicting canonical Note identity".into());
                        }
                    }
                    next.notes.insert(
                        output.leaf.commitment,
                        StoredNote {
                            input: NoteInput {
                                note,
                                tree_id: output.leaf.tree_id,
                                leaf_index: u16::try_from(output.leaf.leaf_index)
                                    .map_err(|_| "leaf index overflow")?,
                                path,
                                root,
                            },
                            commitment: output.leaf.commitment,
                            nullifier,
                            block: output.leaf.block,
                            transaction_hash: output.leaf.transaction_hash,
                            spent: false,
                            reserved_by,
                        },
                    );
                    note_count += 1;
                }
                (Candidate::Credit(output, role), Decoded::Credit(delivery)) => {
                    insert_credit(
                        session,
                        &mut next,
                        &output.leaf,
                        delivery,
                        role,
                        &self.anchor,
                        if self.offline {
                            Some(&self.memberships)
                        } else {
                            None
                        },
                    )?;
                    if let Some(credit) =
                        next.credits.get(&credit_key(output.leaf.commitment, role))
                    {
                        fresh_roots.insert((credit.tree_id, sdk::field_word(credit.root)));
                    }
                    credit_count += 1;
                }
                _ => return Err("decoded wallet result mismatch".into()),
            }
        }
        // A canonical draw can recover an owned successor using its authenticated predecessor shared key.
        for receipt in &self.receipts {
            if !receipt.success {
                continue;
            }
            let records = protocol::decode_receipt_outputs(
                sdk::word_address(session.scope.context.protocol_address)?,
                receipt,
            )?;
            for (_, event) in records.events {
                if let P::InvisiCoreEvents::CreditDraw(event) = event {
                    for (i, nullifier) in event.params.nullifiers.iter().enumerate() {
                        let predecessors = next
                            .credits
                            .values()
                            .filter(|record| record.nullifier == *nullifier)
                            .cloned()
                            .collect::<Vec<_>>();
                        for previous in predecessors {
                            let commitment = event.params.creditCommitments[i];
                            let key = credit_key(commitment, previous.role);
                            if next.credits.contains_key(&key) {
                                continue;
                            }
                            let recovered = crate::credit::recover_credit_state(
                                session.scope.context,
                                &previous.delivery.note,
                                &crate::credit::CreditStateRecovery {
                                    timestamp: receipt.block.timestamp,
                                    credit_nullifier: U256::from_be_slice(nullifier.as_slice()),
                                    state_commitment: U256::from_be_slice(commitment.as_slice()),
                                    recovery_amount: U256::from_be_slice(
                                        event.params.recoveryAmounts[i].as_slice(),
                                    ),
                                },
                            )
                            .map_err(|e| e.to_string())?;
                            let leaf = rpc::LeafMetadata {
                                block: receipt.block.clone(),
                                tree_id: u64::try_from(event.outputTreeId)
                                    .map_err(|_| "Credit tree overflow")?,
                                leaf_index: event.leafIndices[i],
                                commitment,
                                token: event.params.token,
                                transaction_hash: receipt.transaction_hash,
                                log_index: receipt.logs.first().map_or(0, |v| v.log_index),
                                kind: "CreditDraw".into(),
                            };
                            insert_credit(
                                session,
                                &mut next,
                                &leaf,
                                CreditDeliveryState {
                                    note: recovered,
                                    owner_receiving_keys: previous.delivery.owner_receiving_keys,
                                    spender_receiving_keys: previous
                                        .delivery
                                        .spender_receiving_keys,
                                },
                                previous.role,
                                &self.anchor,
                                if self.offline {
                                    Some(&self.memberships)
                                } else {
                                    None
                                },
                            )?;
                            credit_count += 1;
                        }
                    }
                }
            }
        }
        let observation = if self.offline {
            self.anchor.clone()
        } else {
            session.invisi.chain.snapshot()?
        };
        if !self.offline {
            session.invisi.chain.canonical(&observation)?;
            for note in next.notes.values_mut() {
                note.spent = session
                    .invisi
                    .chain
                    .nullifier_spent(note.nullifier, &observation)?;
            }
            for credit in next.credits.values_mut() {
                credit.consumed = session
                    .invisi
                    .chain
                    .nullifier_spent(credit.nullifier, &observation)?;
                let state = &credit.delivery.note;
                credit.revoked = session.invisi.chain.credit_revoked(
                    sdk::word_address(state.owner_wallet_identity)?,
                    sdk::word_address(state.token_address)?,
                    state.revocation_shard,
                    state.revocation_slot,
                    &observation,
                )?;
            }
        }
        let mut completions = self.completion.clone().unwrap_or_default();
        let mut completion_receipts = self
            .receipts
            .iter()
            .map(|r| (r.transaction_hash, r.clone()))
            .collect::<BTreeMap<_, _>>();
        if !self.offline {
            for operation in next
                .operations
                .values()
                .filter(|o| !o.status.terminal() && o.transaction_hash.is_some())
            {
                if completions.iter().any(|(id, _, _)| id == &operation.id) {
                    continue;
                }
                let hash = operation
                    .transaction_hash
                    .ok_or("tracked transaction hash missing")?;
                let receipt = if let Some(r) = completion_receipts.get(&hash) {
                    Some(r.clone())
                } else {
                    session.source.receipt(hash)?
                };
                if let Some(receipt) = receipt {
                    if receipt.transaction_hash != hash {
                        return Err("inflight receipt hash mismatch".into());
                    }
                    if receipt.block.number > observation.number {
                        continue;
                    }
                    session.invisi.chain.canonical(&receipt.block)?;
                    completions.push((operation.id.clone(), operation.generation, receipt.success));
                    completion_receipts.insert(hash, receipt);
                }
            }
        }
        {
            for (id, generation, success) in &completions {
                let record = next
                    .operations
                    .get_mut(id)
                    .ok_or("operation journal disappeared")?;
                if record.generation != *generation {
                    return Err("stale operation reconciliation".into());
                }
                let hash = record
                    .transaction_hash
                    .ok_or("operation transaction hash missing")?;
                let transaction = session
                    .source
                    .transaction(hash)?
                    .ok_or("canonical transaction missing")?;
                let call = record.call.as_ref().ok_or("operation calldata missing")?;
                if transaction.hash != hash
                    || transaction.chain_id != session.scope.context.chain_id
                    || transaction.to != Some(call.to)
                    || !super::operation::record_matches_transaction_data(
                        record,
                        &transaction.input,
                    )
                    || transaction.value != call.value
                    || transaction.block.as_ref().is_none_or(|block| {
                        completion_receipts
                            .get(&hash)
                            .is_none_or(|r| r.block != *block)
                    })
                {
                    return Err("reconciliation transaction differs from exported call".into());
                }
                record.status = if *success {
                    OperationStatus::Confirmed
                } else {
                    OperationStatus::Reverted
                };
                record.resolved_at = Some(
                    completion_receipts
                        .get(&hash)
                        .ok_or("completion receipt unavailable")?
                        .block
                        .clone(),
                );
                record.generation = record
                    .generation
                    .checked_add(1)
                    .ok_or("operation generation exhausted")?;
                release_inputs(&mut next, id);
            }
        }
        next.observed_through = if self.offline {
            None
        } else {
            Some(observation.clone())
        };
        if self.completion.is_none() {
            if next.discovery_ranges.is_empty() {
                if let Some(previous) = &next.discovery_through {
                    next.discovery_ranges
                        .push(crate::public_history::CoverageRange {
                            from_block: session.source.deployment_start(),
                            block: previous.clone(),
                        });
                }
            }
            next.discovery_ranges = crate::public_history::merge_coverage(
                &next.discovery_ranges,
                crate::public_history::CoverageRange {
                    from_block: self.options.from_block,
                    block: self.discovery_block.clone(),
                },
            )?;
            next.discovery_through = next
                .discovery_ranges
                .iter()
                .find(|r| r.from_block == session.source.deployment_start())
                .map(|r| r.block.clone());
            next.recovery_boundary = Some(
                next.recovery_boundary
                    .map_or(self.options.from_block, |v| v),
            );
        }
        if self.queue_credit_replay && credit_count > 0 {
            next.credit_replay_from = Some(
                next.credit_replay_from
                    .map_or(self.options.from_block, |n| n.min(self.options.from_block)),
            );
            let maximum = next
                .discovery_ranges
                .last()
                .map_or(self.anchor.number, |r| r.block.number)
                .max(self.anchor.number);
            next.credit_replay_target = Some(
                next.credit_replay_target
                    .map_or(maximum, |n| n.max(maximum)),
            );
            next.credit_replay_through = None;
            next.credit_replay_revision = next
                .credit_replay_revision
                .checked_add(1)
                .ok_or("credit replay revision exhausted")?;
        }
        if let Some((through, revision, required)) = self.replay_advance {
            if next.credit_replay_revision == revision {
                next.credit_replay_through = Some(through);
                if through >= required {
                    next.credit_replay_from = None;
                    next.credit_replay_target = None;
                    next.credit_replay_through = None;
                }
            }
        }
        next.public_history_generation = self.public_generation.or(next.public_history_generation);
        let no_fresh_roots = BTreeSet::new();
        if self.offline {
            next.preparation_snapshot = None;
        } else {
            session.retain_preparation(
                &mut next,
                &observation,
                if observation == self.anchor {
                    &fresh_roots
                } else {
                    &no_fresh_roots
                },
            )?;
        }
        if !self.offline {
            session.invisi.chain.canonical(&observation)?;
            session.invisi.chain.canonical(&self.anchor)?;
        }
        if let (Some(history), Some(generation)) = (&session.public_history, self.public_generation)
        {
            if history.snapshot()?.generation != generation {
                return Err("public history generation changed before commit".into());
            }
        }
        if let Some(token) = &self.cancellation {
            token.check()?;
        }
        let expected = next.revision;
        session.commit(next)?;
        if let (Some(history), Some(generation)) = (&session.public_history, self.public_generation)
        {
            if history.snapshot()?.generation != generation {
                session.fence_public_history()?;
                return Err("public history generation changed during private commit".into());
            }
        }
        Ok(RefreshResult {
            block: self.anchor.clone(),
            notes: note_count,
            credits: credit_count,
            revision: expected + 1,
        })
    }
}
fn reservation_for(state: &WalletState, input: &str) -> Option<String> {
    state
        .operations
        .values()
        .find(|op| !op.status.terminal() && op.inputs.iter().any(|value| value == input))
        .map(|op| op.id.clone())
}
pub(crate) fn release_inputs(state: &mut WalletState, id: &str) {
    for note in state.notes.values_mut() {
        if note.reserved_by.as_deref() == Some(id) {
            note.reserved_by = None;
        }
    }
    for credit in state.credits.values_mut() {
        if credit.reserved_by.as_deref() == Some(id) {
            credit.reserved_by = None;
        }
    }
}
fn insert_credit(
    session: &WalletSession,
    state: &mut WalletState,
    leaf: &rpc::LeafMetadata,
    delivery: CreditDeliveryState,
    role: CreditRole,
    anchor: &CanonicalBlock,
    memberships: Option<&Vec<crate::public_history::CachedMembership>>,
) -> Result<()> {
    delivery.validate().map_err(|e| e.to_string())?;
    let identity = if role == CreditRole::Owner {
        delivery.note.owner_wallet_identity
    } else {
        delivery.note.spender_wallet_identity
    };
    if identity != sdk::address_word(session.wallet.owner_address())
        || delivery.note.context != session.scope.context
        || delivery.note.token_address != sdk::address_word(leaf.token)
        || sdk::field_word(delivery.note.commitment().map_err(|e| e.to_string())?)
            != leaf.commitment
    {
        return Err("Credit receipt owner or context mismatch".into());
    }
    let (root, path) = membership_for(session, leaf, anchor, memberships)?;
    let key = credit_key(leaf.commitment, role);
    if let Some(previous) = state.credits.get(&key) {
        if previous.tree_id != leaf.tree_id
            || previous.leaf_index as u32 != leaf.leaf_index
            || previous
                .delivery
                .note
                .commitment()
                .map_err(|e| e.to_string())?
                != delivery.note.commitment().map_err(|e| e.to_string())?
        {
            return Err("conflicting canonical Credit identity".into());
        }
    }
    let nullifier = sdk::field_word(delivery.note.nullifier().map_err(|e| e.to_string())?);
    let reserved_by = reservation_for(state, &format!("credit:{}", leaf.commitment));
    state.credits.insert(
        key,
        StoredCredit {
            delivery,
            commitment: leaf.commitment,
            nullifier,
            tree_id: leaf.tree_id,
            leaf_index: u16::try_from(leaf.leaf_index).map_err(|_| "Credit index overflow")?,
            path,
            root,
            block: leaf.block.clone(),
            transaction_hash: leaf.transaction_hash,
            role,
            consumed: false,
            revoked: false,
            reserved_by,
        },
    );
    Ok(())
}

struct AuthenticatedPlaintext(zeroize::Zeroizing<Vec<u8>>);
impl crate::delivery::DeliveryDecryptor for AuthenticatedPlaintext {
    fn decrypt_note(
        &self,
        _: &[u8],
        _: &crate::delivery::DeliveryContext,
        _: U256,
    ) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.0.to_vec()))
    }
    fn decrypt_credit(
        &self,
        _: &[u8],
        _: &crate::delivery::DeliveryContext,
        _: CreditRole,
        _: U256,
    ) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.0.to_vec()))
    }
}
impl WalletSession {
    pub fn retry_unresolved(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
    ) -> Result<RefreshResult> {
        let base = self.snapshot()?;
        let anchor = self.source.indexed_head()?;
        let mut receipts = BTreeMap::new();
        for unresolved in base.unresolved_deliveries.values() {
            receipts.insert(
                unresolved.receipt.transaction_hash,
                unresolved.receipt.clone(),
            );
        }
        let keys = base
            .unresolved_deliveries
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut pending = self.stage_refresh(
            base,
            anchor.clone(),
            receipts.into_values().collect(),
            RefreshOptions {
                from_block: anchor.number,
                to_block: Some(anchor.number),
                page_size: 1,
                reset: false,
            },
            Some(vec![]),
        )?;
        pending.candidates.retain(|key, _| keys.contains(key));
        pending.queue_credit_replay = true;
        pending.options.from_block = pending
            .receipts
            .iter()
            .map(|r| r.block.number)
            .min()
            .unwrap_or(anchor.number);
        pending.decrypt(decryptor)
    }
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub from_block: Option<u64>,
    pub to_block: Option<u64>,
    pub page_size: u64,
    pub reset: bool,
    pub offline: bool,
}
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            from_block: None,
            to_block: None,
            page_size: 100,
            reset: false,
            offline: false,
        }
    }
}
impl WalletSession {
    pub fn scan(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
        options: ScanOptions,
    ) -> Result<RefreshResult> {
        self.scan_with_progress(
            decryptor,
            options,
            &crate::public_history::CancellationToken::default(),
            |_| Ok(()),
        )
    }
    pub fn scan_with_progress(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
        options: ScanOptions,
        cancel: &crate::public_history::CancellationToken,
        mut progress: impl FnMut(&RefreshResult) -> Result<()>,
    ) -> Result<RefreshResult> {
        cancel.check()?;
        self.fence_public_history()?;
        if !options.offline {
            if let Some(history) = &self.public_history {
                if let Err(error) = history.validate_canonical() {
                    self.fence_public_history()?;
                    return Err(error);
                }
            }
        }
        if options.page_size == 0 || options.page_size > 256 {
            return Err("scan page size must be 1..256".into());
        }
        let indexed = if options.offline {
            self.public_history
                .as_ref()
                .ok_or("offline scan requires public history")?
                .snapshot()?
                .indexed_head
                .ok_or("offline public head unavailable")?
        } else {
            self.source.indexed_head()?
        };
        let known = if options.offline {
            indexed.clone()
        } else {
            self.invisi.chain.snapshot()?
        };
        if !options.offline {
            self.invisi.chain.canonical(&known)?;
        }
        let target = options.to_block.unwrap_or(indexed.number);
        let lower = options.from_block.unwrap_or(self.source.deployment_start());
        if target > indexed.number || lower < self.source.deployment_start() || lower > target {
            return Err("scan outside indexed history".into());
        }
        if !options.offline {
            if let Some(history) = &self.public_history {
                history
                    .store
                    .note_head(&history.scope, indexed.clone(), known)?;
            }
        }
        let synthetic = crate::public_history::PublicHistorySnapshot {
            revision: 0,
            generation: 1,
            scope_key: String::new(),
            coverage: vec![],
            pages: vec![],
            through: None,
            indexed_head: Some(indexed.clone()),
            known_head: Some(indexed),
            reorg_from: None,
        };
        let history = if let Some(h) = &self.public_history {
            h.snapshot()?
        } else {
            synthetic
        };
        let initial = super::first_scan_range(
            &self.snapshot()?,
            &history,
            self.source.deployment_start(),
            lower,
            target,
            options.page_size,
            options.reset,
        );
        let boundary = initial.as_ref().map_or(lower, |r| r.from_block);
        let mut reset = options.reset;
        let mut first = true;
        let mut notes = 0;
        let mut credits = 0;
        let mut last = None;
        loop {
            cancel.check()?;
            let state = self.snapshot()?;
            if state.invalidated && !reset {
                return Err("wallet requires canonical resync".into());
            }
            let range = if first {
                initial.clone()
            } else {
                super::first_scan_range(
                    &state,
                    &history,
                    self.source.deployment_start(),
                    lower,
                    target,
                    options.page_size,
                    false,
                )
            };
            let Some(range) = range else { break };
            let settings = RefreshOptions {
                from_block: range.from_block,
                to_block: Some(range.to_block),
                page_size: options.page_size,
                reset,
            };
            let mut pending = if options.offline {
                let history = self
                    .public_history
                    .as_ref()
                    .ok_or("offline public history unavailable")?;
                let (page, generation) =
                    history.acquire_offline(range.from_block, range.to_block)?;
                let mut pending = self.stage_refresh(
                    state.clone(),
                    page.block.clone(),
                    page.receipts,
                    settings,
                    None,
                )?;
                pending.bind_acquired_generation(generation)?;
                pending.offline = true;
                pending.memberships = page.memberships;
                pending
            } else {
                self.refresh(settings)?
            };
            pending.cancellation = Some(cancel.clone());
            pending.queue_credit_replay =
                range.direction == "backward" || state.discovery_through.is_none();
            pending.base.recovery_boundary = Some(state.recovery_boundary.unwrap_or(boundary));
            pending.anchor = if options.offline {
                self.public_history
                    .as_ref()
                    .ok_or("offline public history unavailable")?
                    .acquire_offline(target, target)?
                    .0
                    .block
            } else {
                self.source.block(target)?
            };
            cancel.check()?;
            let result = pending.decrypt(decryptor)?;
            notes += result.notes;
            credits += result.credits;
            let mut committed = result.clone();
            committed.block = pending.discovery_block.clone();
            progress(&committed)?;
            last = Some(result);
            first = false;
            reset = false;
        }
        if first {
            let state = self.snapshot()?;
            let anchor = if options.offline {
                self.public_history
                    .as_ref()
                    .ok_or("offline public history unavailable")?
                    .acquire_offline(target, target)?
                    .0
                    .block
            } else {
                self.source.block(target)?
            };
            let mut pending = self.stage_refresh(
                state,
                anchor.clone(),
                vec![],
                RefreshOptions {
                    from_block: target,
                    to_block: Some(target),
                    page_size: 1,
                    reset: false,
                },
                Some(vec![]),
            )?;
            pending.offline = options.offline;
            last = Some(pending.decrypt(decryptor)?);
        }
        if !options.offline {
            credits += self.replay_credits(decryptor, target, options.page_size, cancel)?;
        }
        let mut result = last.ok_or("no scan result")?;
        result.notes = notes;
        result.credits = credits;
        result.revision = self.snapshot()?.revision;
        Ok(result)
    }
    pub fn replay_credits(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
        target: u64,
        size: u64,
        cancel: &crate::public_history::CancellationToken,
    ) -> Result<usize> {
        if size == 0 || size > 256 {
            return Err("invalid credit replay page size".into());
        }
        let state = self.snapshot()?;
        let Some(from) = state.credit_replay_from else {
            return Ok(0);
        };
        let required = state.credit_replay_target.unwrap_or(target).max(
            state
                .discovery_ranges
                .last()
                .map_or(target, |r| r.block.number),
        );
        let revision = state.credit_replay_revision;
        let mut start = state
            .credit_replay_through
            .map_or(from, |n| n.saturating_add(1));
        let mut count = 0;
        while start <= target {
            cancel.check()?;
            let end = start.saturating_add(size - 1).min(target);
            let mut pending = self.refresh(RefreshOptions {
                from_block: start,
                to_block: Some(end),
                page_size: size,
                reset: false,
            })?;
            pending.candidates.clear();
            pending.completion = Some(vec![]);
            pending.anchor = self.source.block(target)?;
            pending.replay_advance = Some((end, revision, required));
            pending.cancellation = Some(cancel.clone());
            cancel.check()?;
            count += pending.decrypt(decryptor)?.credits;
            if end == target {
                break;
            }
            start = end + 1;
        }
        Ok(count)
    }
}

fn membership_for(
    session: &WalletSession,
    leaf: &rpc::LeafMetadata,
    anchor: &CanonicalBlock,
    cached: Option<&Vec<crate::public_history::CachedMembership>>,
) -> Result<(U256, [U256; 16])> {
    if let Some(cached) = cached {
        let proof = cached
            .iter()
            .find(|p| {
                p.tree_id == leaf.tree_id
                    && p.leaf_index == leaf.leaf_index
                    && p.commitment == leaf.commitment
            })
            .ok_or("offline public membership unavailable; synchronize page online")?;
        if proof.block.number > anchor.number || proof.block.number < leaf.block.number {
            return Err("offline proof snapshot is outside selected history; synchronize exact range online".into());
        }
        if sdk::merkle_root(
            U256::from_be_slice(leaf.commitment.as_slice()),
            u16::try_from(leaf.leaf_index).map_err(|_| "leaf index overflow")?,
            &proof.path,
        )? != proof.root
        {
            return Err("offline public membership mismatch".into());
        }
        Ok((proof.root, proof.path))
    } else {
        session.verified_membership(leaf, anchor)
    }
}
