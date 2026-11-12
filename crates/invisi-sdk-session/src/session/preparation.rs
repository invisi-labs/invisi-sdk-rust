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
        work: impl Fn(&Invisi) -> Result<ManagedPrepared>,
    ) -> Result<Operation> {
        let state = self.snapshot()?;
        if let Some(snapshot) = self.cached_preparation(&state)? {
            let mut invisi = self.invisi.clone();
            invisi.chain = Arc::new(snapshot.facts.clone());
            match work(&invisi) {
                Ok(prepared) => {
                    return self.register_with_preparation(prepared, Some(snapshot.clone()))
                }
                Err(e) if e.contains("missing synchronized preparation data") => {}
                Err(e) => return Err(e),
            }
        }
        self.register_with_preparation(work(&self.invisi)?, None)
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
        self.align_preparation_paths(state, block, previous, fresh_roots)?;
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
                    n.revocation_shard,
                    n.revocation_slot,
                ),
                credit.revoked,
            );
        }
        for token in tokens {
            let cached = previous.and_then(|p| {
                p.facts
                    .allocations
                    .iter()
                    .find(|(o, t, _, _)| *o == self.scope.owner_address && *t == token)
                    .map(|(_, _, s, l)| (*s, *l))
            });
            let (shard, slot) = cached.map(Ok).unwrap_or_else(|| {
                chain.credit_allocation(self.scope.owner_address, token, block)
            })?;
            facts
                .allocations
                .push((self.scope.owner_address, token, shard, slot));
        }
        for (tree, root) in roots {
            facts.roots.push((tree, root, true));
        }
        facts.spent.extend(nullifiers);
        facts.revocations.extend(
            revocations
                .into_iter()
                .map(|((o, t, s, l), v)| (o, t, s, l, v)),
        );
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
        previous: Option<&RetainedPreparation>,
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
        for (tree, index, commitment, root) in records {
            let selected = pinned.get(&tree).copied();
            let accepted = if selected == Some(root) {
                true
            } else if selected.is_some() {
                false
            } else {
                let cached = if fresh_roots.contains(&(tree, sdk::field_word(root))) {
                    Some(true)
                } else {
                    previous.and_then(|p| {
                        p.facts
                            .roots
                            .iter()
                            .find(|(t, r, _)| *t == tree && *r == sdk::field_word(root))
                            .map(|(_, _, v)| *v)
                    })
                };
                cached.map(Ok).unwrap_or_else(|| {
                    self.invisi
                        .chain
                        .known_root(tree, sdk::field_word(root), block)
                })?
            };
            if accepted {
                pinned.insert(tree, root);
                continue;
            }
            // Reuse valid paths; only changed tree roots or expired roots need membership IO.
            let input = crate::rpc::MembershipInput {
                tree_id: tree,
                leaf_index: u32::from(index),
                commitment,
                root: selected.map(sdk::field_word),
            };
            let proof = self.source.membership(&input, block)?;
            if proof.block != *block
                || proof.tree_id != tree
                || proof.leaf_index != u32::from(index)
                || proof.leaf != commitment
                || selected.is_some_and(|r| sdk::field_word(r) != proof.root)
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
            if sdk::merkle_root(U256::from_be_slice(commitment.as_slice()), index, &path)? != root
                || selected.is_none() && !self.invisi.chain.known_root(tree, proof.root, block)?
            {
                return Err("preparation membership or canonical root mismatch".into());
            }
            pinned.insert(tree, root);
            if let Some(note) = state.notes.get_mut(&commitment) {
                note.input.root = root;
                note.input.path = path;
            }
            for credit in state
                .credits
                .values_mut()
                .filter(|c| c.commitment == commitment)
            {
                credit.root = root;
                credit.path = path;
            }
        }
        Ok(())
    }
}
