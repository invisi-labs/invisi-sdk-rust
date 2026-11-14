use super::*;
use crate::sdk::{Fee, TransferPreparation};
use std::collections::BTreeSet;

/// Collection deadline; zero selects construction time plus 300 seconds.
#[derive(Clone, Copy, Debug, Default)]
pub struct CollectionOptions {
    pub deadline: u64,
}

impl WalletSession {
    /// Authenticate explicit openings and their current membership without claiming discovery coverage.
    /// Existing spent flags, reservations and operation journals are retained atomically.
    /// Input path/root fields are ignored and replaced with authenticated current membership.
    pub fn import_notes(&self, inputs: &[NoteInput]) -> Result<()> {
        let mut state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let anchor = self.invisi.chain.snapshot()?;
        self.invisi.chain.canonical(&anchor)?;
        if self.invisi.chain.context() != self.scope.context
            || self.source.context() != self.scope.context
        {
            return Err("import deployment mismatch".into());
        }
        if let Some(previous) = &state.observed_through {
            self.invisi.chain.canonical(previous)?;
        }
        if let Some(previous) = &state.discovery_through {
            self.invisi.chain.canonical(previous)?;
        }
        let mut seen = BTreeSet::new();
        for input in inputs {
            input.note.validate().map_err(|e| e.to_string())?;
            if input.tree_id == 0
                || input.note.context != self.scope.context
                || input.note.owner_address != sdk::address_word(self.wallet.owner_address())
            {
                return Err("imported Note owner, deployment or position mismatch".into());
            }
            // Imports authenticate a fresh source proof, not a caller-supplied stale path.

            let commitment = sdk::field_word(input.note.commitment().map_err(|e| e.to_string())?);
            if !seen.insert(commitment) {
                return Err("duplicate imported Note".into());
            }
            let proof = self.source.membership(
                &crate::rpc::MembershipInput {
                    tree_id: input.tree_id,
                    leaf_index: input.leaf_index.into(),
                    commitment,
                    root: None,
                },
                &anchor,
            )?;
            let path: [U256; 16] = proof
                .path
                .iter()
                .map(|v| U256::from_be_slice(v.as_slice()))
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| "import membership depth mismatch")?;
            let root = U256::from_be_slice(proof.root.as_slice());
            if proof.block != anchor
                || proof.tree_id != input.tree_id
                || proof.leaf_index != u32::from(input.leaf_index)
                || proof.leaf != commitment
                || sdk::merkle_root(
                    U256::from_be_slice(commitment.as_slice()),
                    input.leaf_index,
                    &path,
                )? != root
                || !self
                    .invisi
                    .chain
                    .known_root(input.tree_id, proof.root, &anchor)?
            {
                return Err("import membership binding mismatch".into());
            }
            let nullifier = sdk::field_word(input.note.nullifier().map_err(|e| e.to_string())?);
            if let Some(old) = state.notes.get_mut(&commitment) {
                if old.input.note != input.note
                    || old.nullifier != nullifier
                    || old.input.tree_id != input.tree_id
                    || old.input.leaf_index != input.leaf_index
                {
                    return Err("import conflicts with stored Note".into());
                }
                old.input.path = path;
                old.input.root = root;
            } else {
                let mut input = input.clone();
                input.path = path;
                input.root = root;
                state.notes.insert(
                    commitment,
                    StoredNote {
                        input,
                        commitment,
                        nullifier,
                        block: anchor.clone(),
                        transaction_hash: B256::ZERO,
                        spent: false,
                        reserved_by: None,
                    },
                );
            }
        }
        for note in state.notes.values_mut() {
            note.spent |= self.invisi.chain.nullifier_spent(note.nullifier, &anchor)?;
        }
        for credit in state.credits.values_mut() {
            credit.consumed |= self
                .invisi
                .chain
                .nullifier_spent(credit.nullifier, &anchor)?;
            let n = &credit.delivery.note;
            credit.revoked |= self.invisi.chain.credit_revoked(
                sdk::word_address(n.owner_wallet_identity)?,
                sdk::word_address(n.token_address)?,
                n.revocation_shard,
                n.revocation_slot,
                &anchor,
            )?;
        }
        state.observed_through = Some(anchor.clone());
        state.preparation_snapshot = None;
        self.invisi.chain.canonical(&anchor)?;
        self.fence_public_history()?;
        self.commit(state)
    }

    /// Freeze exactly the selected available Notes into a full, unfunded public withdrawal.
    pub fn prepare_collection(
        &self,
        token: Address,
        recipient: Address,
        commitments: &[B256],
        options: CollectionOptions,
    ) -> sdk::PreparationResult<Operation> {
        if recipient == Address::ZERO || commitments.is_empty() {
            return Err("collection requires recipient and selected Notes".into());
        }
        let state = self.snapshot()?;
        if state.invalidated {
            return Err("wallet requires canonical resync".into());
        }
        let mut seen = BTreeSet::new();
        let mut inputs = Vec::new();
        let mut amount = U256::ZERO;
        for commitment in commitments {
            let note = state
                .notes
                .get(commitment)
                .ok_or("collection Note unavailable")?;
            if !seen.insert(*commitment)
                || note.spent
                || note.reserved_by.is_some()
                || note.input.note.token_address != sdk::address_word(token)
            {
                return Err("collection Note unavailable or duplicate".into());
            }
            amount = amount
                .checked_add(note.input.note.amount)
                .ok_or("collection amount overflow")?;
            inputs.push(note.input.clone());
        }
        self.prepare_cached(|invisi| {
            let deadline = if options.deadline == 0 {
                let anchor = invisi.chain.snapshot()?;
                invisi
                    .chain
                    .construction_timestamp(&anchor)
                    .checked_add(300)
                    .ok_or("collection deadline overflow")?
            } else {
                options.deadline
            };
            Ok(ManagedPrepared::Funds(invisi.prepare_transfer(
                &self.wallet,
                TransferPreparation {
                    token,
                    inputs: inputs.clone(),
                    outputs: vec![],
                    withdrawal: Some((recipient, amount)),
                    funding: sdk::empty_funding(),
                    fee: Fee::default(),
                    deadline,
                    automatic_change: false,
                },
            )?))
        })
    }
}
