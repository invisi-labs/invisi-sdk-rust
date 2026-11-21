use super::*;
use crate::sdk::PreparationSnapshot;
use std::collections::BTreeSet;

/// Encrypted alongside the inventory revision that supplied the membership paths.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetainedPreparation {
    pub facts: PreparationSnapshot,
    pub generation: Option<u64>,
    pub runtime_code_hash: Option<B256>,
    pub deployment_start: u64,
}
impl WalletSession {
    pub(crate) fn cached_preparation<'a>(
        &self,
        state: &'a WalletState,
    ) -> Result<Option<&'a RetainedPreparation>> {
        let Some(snapshot) = &state.preparation_snapshot else {
            return Ok(None);
        };
        snapshot.facts.validate()?;
        if snapshot.facts.context != self.scope.context
            || snapshot.facts.deployment != self.invisi.chain.preparation_deployment()
            || snapshot.runtime_code_hash != self.source.runtime_code_hash()
            || snapshot.deployment_start != self.source.deployment_start()
        {
            return Err("preparation snapshot deployment mismatch; refresh online".into());
        }
        if state.invalidated
            || snapshot.generation != state.public_history_generation
            || state.observed_through.as_ref() != Some(&snapshot.facts.block)
        {
            return Ok(None);
        }
        Ok(Some(snapshot))
    }
    pub(crate) fn prepare_cached(
        &self,
        work: impl Fn(&Invisi) -> sdk::PreparationResult<ManagedPrepared>,
    ) -> sdk::PreparationResult<Operation> {
        let state = self.snapshot()?;
        if let Some(snapshot) = self.cached_preparation(&state)? {
            let mut invisi = self.invisi.clone();
            let facts = Arc::new(snapshot.facts.for_preparation());
            invisi.chain = facts.clone();
            match work(&invisi) {
                Ok(prepared) => {
                    return Ok(self.register_with_preparation(prepared, Some(snapshot.clone()))?)
                }
                Err(_) if facts.missing_read_observed() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(self.register_with_preparation(work(&self.invisi)?, None)?)
    }
    /// Resolve only selected wallet paths when no retained preparation is usable.
    /// The detached subset is never committed and cannot preload unrelated inventory.
    fn selected_preparation_paths(
        &self,
        commitments: &BTreeSet<B256>,
    ) -> Result<Option<WalletState>> {
        let mut state = self.snapshot()?;
        if self.cached_preparation(&state)?.is_some() || commitments.is_empty() {
            return Ok(None);
        }
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        state.notes.retain(|key, _| commitments.contains(key));
        state
            .credits
            .retain(|_, credit| commitments.contains(&credit.commitment));
        let block = self.invisi.chain.snapshot()?;
        self.invisi.chain.canonical(&block)?;
        if self.invisi.chain.context() != self.scope.context
            || self.source.context() != self.scope.context
        {
            return Err("preparation deployment mismatch".into());
        }
        self.align_preparation_paths(&mut state, &block, &BTreeSet::new())?;
        self.invisi.chain.canonical(&block)?;
        Ok(Some(state))
    }
    pub(crate) fn prepare_note_paths(&self, inputs: &mut [NoteInput]) -> Result<()> {
        let commitments = inputs
            .iter()
            .map(|n| {
                n.note
                    .commitment()
                    .map(sdk::field_word)
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if let Some(state) = self.selected_preparation_paths(&commitments)? {
            for input in inputs {
                let commitment =
                    sdk::field_word(input.note.commitment().map_err(|e| e.to_string())?);
                if let Some(note) = state.notes.get(&commitment) {
                    // Caller position/opening validation remains the transaction preparer's job.
                    if note.input.tree_id == input.tree_id
                        && note.input.leaf_index == input.leaf_index
                        && note.input.note == input.note
                    {
                        input.path = note.input.path;
                        input.root = note.input.root;
                    }
                }
            }
        }
        Ok(())
    }
    pub(crate) fn prepare_credit_paths(&self, inputs: &mut [sdk::CreditInput]) -> Result<()> {
        let commitments = inputs
            .iter()
            .map(|c| {
                c.delivery
                    .note
                    .commitment()
                    .map(sdk::field_word)
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if let Some(state) = self.selected_preparation_paths(&commitments)? {
            for input in inputs {
                let commitment = sdk::field_word(
                    input
                        .delivery
                        .note
                        .commitment()
                        .map_err(|e| e.to_string())?,
                );
                if let Some(credit) = state.credits.values().find(|c| {
                    c.commitment == commitment
                        && c.tree_id == input.tree_id
                        && c.leaf_index == input.leaf_index
                }) {
                    input.path = credit.path;
                    input.root = credit.root;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn retain_preparation(
        &self,
        state: &mut WalletState,
        block: &CanonicalBlock,
        fresh_roots: &BTreeSet<(u64, B256)>,
    ) -> Result<()> {
        let chain = &self.invisi.chain;
        let previous_owned = state.preparation_snapshot.clone();
        let previous = previous_owned.as_ref().filter(|p| {
            p.facts.block == *block
                && p.facts.context == self.scope.context
                && p.generation == state.public_history_generation
                && p.runtime_code_hash == self.source.runtime_code_hash()
                && p.deployment_start == self.source.deployment_start()
        });
        let mut facts = PreparationSnapshot::new(self.scope.context, block.clone());
        facts.deployment = chain.preparation_deployment();
        // Unsupported nonce readers preserve the original online-only behavior.
        let cached_nonce = previous.and_then(|p| {
            p.facts
                .funding_nonces
                .iter()
                .find(|(o, _)| *o == self.scope.owner_address)
                .map(|(_, n)| *n)
        });
        let nonce = match cached_nonce
            .map(Ok)
            .unwrap_or_else(|| chain.funding_nonce(self.scope.owner_address, block))
        {
            Ok(nonce) => nonce,
            Err(e) if e == "funding nonce reader required" => {
                state.preparation_snapshot = None;
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        facts.funding_nonces.push((self.scope.owner_address, nonce));
        self.align_preparation_paths(state, block, fresh_roots)?;
        let mut tokens = BTreeSet::new();
        let mut roots = BTreeSet::new();
        let mut nullifiers = BTreeMap::new();
        let mut revocations = BTreeMap::new();
        for note in state.notes.values().filter(|n| !n.spent) {
            tokens.insert(sdk::word_address(note.input.note.token_address)?);
            roots.insert((note.input.tree_id, sdk::field_word(note.input.root)));
            nullifiers.insert(note.nullifier, note.spent);
        }
        for credit in state.credits.values().filter(|c| !c.consumed) {
            let n = &credit.delivery.note;
            let token = sdk::word_address(n.token_address)?;
            tokens.insert(token);
            roots.insert((credit.tree_id, sdk::field_word(credit.root)));
            nullifiers.insert(credit.nullifier, credit.consumed);
            revocations.insert(
                (
                    sdk::word_address(n.owner_wallet_identity)?,
                    token,
                    n.grant_id,
                ),
                credit.status,
            );
        }
        for (tree, root) in roots {
            facts.roots.push((tree, root, true));
        }
        facts.spent.extend(nullifiers);
        facts
            .credit_statuses
            .extend(revocations.into_iter().map(|((o, t, id), v)| (o, t, id, v)));
        chain.canonical(block)?;
        if chain.context() != self.scope.context {
            return Err("preparation chain identity changed".into());
        }
        state.preparation_snapshot = Some(RetainedPreparation {
            facts,
            generation: state.public_history_generation,
            runtime_code_hash: self.source.runtime_code_hash(),
            deployment_start: self.source.deployment_start(),
        });
        Ok(())
    }
}

impl WalletSession {
    fn align_preparation_paths(
        &self,
        state: &mut WalletState,
        block: &CanonicalBlock,
        fresh_roots: &BTreeSet<(u64, B256)>,
    ) -> Result<()> {
        let mut records = state
            .notes
            .values()
            .filter(|n| !n.spent)
            .map(|n| {
                (
                    n.input.tree_id,
                    n.input.leaf_index,
                    n.commitment,
                    n.input.root,
                )
            })
            .chain(
                state
                    .credits
                    .values()
                    .filter(|c| !c.consumed)
                    .map(|c| (c.tree_id, c.leaf_index, c.commitment, c.root)),
            )
            .collect::<Vec<_>>();
        records.sort_by_key(|(tree, index, commitment, _)| {
            (*tree, std::cmp::Reverse(*index), *commitment)
        });
        records.dedup_by_key(|(tree, index, commitment, _)| (*tree, *index, *commitment));
        let mut pinned = BTreeMap::new();
        let mut leaders = BTreeSet::new();
        let mut missing = Vec::new();
        // The highest leaf establishes each tree's root before older paths are considered.
        for &(tree, index, commitment, root) in &records {
            if !leaders.insert(tree) {
                continue;
            }
            // Persisted root acceptance is untrusted on an online refresh, even
            // when its block/hash matches. Only evidence from this operation may
            // bypass the current canonical reader.
            let accepted = fresh_roots.contains(&(tree, sdk::field_word(root)))
                || self
                    .invisi
                    .chain
                    .known_root(tree, sdk::field_word(root), block)?;
            if accepted {
                pinned.insert(tree, root);
            } else {
                missing.push(crate::rpc::MembershipInput {
                    tree_id: tree,
                    leaf_index: index.into(),
                    commitment,
                    root: None,
                });
            }
        }
        let refreshed = self.fetch_preparation_paths(state, block, &missing)?;
        for input in &missing {
            pinned.insert(input.tree_id, refreshed[&input.commitment]);
        }
        let mut missing = Vec::new();
        for (tree, index, commitment, current) in records {
            if refreshed.contains_key(&commitment) {
                continue;
            }
            let selected = pinned[&tree];
            if current != selected {
                missing.push(crate::rpc::MembershipInput {
                    tree_id: tree,
                    leaf_index: index.into(),
                    commitment,
                    root: Some(sdk::field_word(selected)),
                });
            }
        }
        self.fetch_preparation_paths(state, block, &missing)
            .map(|_| ())
    }

    fn fetch_preparation_paths(
        &self,
        state: &mut WalletState,
        block: &CanonicalBlock,
        inputs: &[crate::rpc::MembershipInput],
    ) -> Result<BTreeMap<B256, U256>> {
        let mut verified_roots = BTreeSet::new();
        let mut refreshed = BTreeMap::new();
        for batch in inputs.chunks(256) {
            let proofs = self.source.memberships(batch, block)?;
            if proofs.len() != batch.len() {
                return Err("preparation membership count mismatch".into());
            }
            for (input, proof) in batch.iter().zip(proofs) {
                if proof.block != *block
                    || proof.tree_id != input.tree_id
                    || proof.leaf_index != input.leaf_index
                    || proof.leaf != input.commitment
                    || input.root.is_some_and(|r| r != proof.root)
                {
                    return Err("preparation membership response binding mismatch".into());
                }
                let path: [U256; 16] = proof
                    .path
                    .iter()
                    .map(|v| U256::from_be_slice(v.as_slice()))
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| "preparation membership depth mismatch")?;
                let root = U256::from_be_slice(proof.root.as_slice());
                if sdk::merkle_root(
                    U256::from_be_slice(input.commitment.as_slice()),
                    u16::try_from(input.leaf_index)
                        .map_err(|_| "preparation leaf index overflow")?,
                    &path,
                )? != root
                    || !verified_roots.contains(&(input.tree_id, proof.root))
                        && !self
                            .invisi
                            .chain
                            .known_root(input.tree_id, proof.root, block)?
                {
                    return Err("preparation membership or canonical root mismatch".into());
                }
                verified_roots.insert((input.tree_id, proof.root));
                refreshed.insert(input.commitment, root);
                if let Some(note) = state.notes.get_mut(&input.commitment) {
                    note.input.root = root;
                    note.input.path = path;
                }
                for credit in state
                    .credits
                    .values_mut()
                    .filter(|c| c.commitment == input.commitment)
                {
                    credit.root = root;
                    credit.path = path;
                }
            }
        }
        Ok(refreshed)
    }
}
