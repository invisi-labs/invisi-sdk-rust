//! Financial delivery records authenticated against complete canonical receipt insertions.
use super::{IInvisiCore::Delivery, InvisiCore as P};
use crate::interfaces::{
    field, CanonicalReceipt, IndexedCreditState, IndexedDelivery, LeafMetadata, NoteOutput,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolEvent, SolEventInterface};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insertion {
    pub tree_id: u64,
    pub start_leaf_index: u32,
    pub commitments: Vec<B256>,
    pub log_index: u32,
}
pub struct ReceiptOutputs {
    pub notes: Vec<NoteOutput>,
    pub credits: Vec<IndexedCreditState>,
    pub nullifiers: Vec<B256>,
    pub credit_nullifiers: Vec<B256>,
    pub insertions: Vec<Insertion>,
    pub created_trees: Vec<u64>,
    pub events: Vec<(u32, P::InvisiCoreEvents)>,
}
fn tree(value: U256) -> Result<u64, String> {
    let tree = u64::try_from(value).map_err(|_| "tree id exceeds uint64")?;
    if tree == 0 {
        return Err("zero output tree".into());
    }
    Ok(tree)
}
fn delivery(value: &Delivery, allow_empty: bool) -> Result<IndexedDelivery, String> {
    let length = value.ciphertext.len();
    if length > 4096
        || !allow_empty && length == 0
        || value.clue.len() != if length == 0 { 0 } else { 68 }
    {
        return Err("invalid delivery dimensions".into());
    }
    if length > 0 && value.clue[64] != 24 {
        return Err("unsupported clue precision".into());
    }
    Ok(IndexedDelivery {
        ciphertext: value.ciphertext.to_vec(),
        clue: value.clue.to_vec(),
    })
}
fn metadata(
    receipt: &CanonicalReceipt,
    id: u64,
    index: u32,
    commitment: B256,
    token: Address,
    log_index: u32,
    kind: &str,
    inserted: &HashMap<(u64, u32), B256>,
) -> Result<LeafMetadata, String> {
    if index >= 65536 || inserted.get(&(id, index)) != Some(&commitment) {
        return Err("delivery does not match canonical transaction insertion".into());
    }
    if token == Address::ZERO {
        return Err("zero delivery token".into());
    }
    field(commitment).map_err(|e| e.to_string())?;
    Ok(LeafMetadata {
        block: receipt.block.clone(),
        tree_id: id,
        leaf_index: index,
        commitment,
        token,
        transaction_hash: receipt.transaction_hash,
        log_index,
        kind: kind.into(),
    })
}
/// The caller must obtain the receipt through an independent canonical Chain RPC.
/// Indexed service rows are not acceptable substitutes for the complete receipt.
pub fn decode_receipt_outputs(
    protocol_address: Address,
    receipt: &CanonicalReceipt,
) -> Result<ReceiptOutputs, String> {
    if protocol_address == Address::ZERO || receipt.transaction_hash == B256::ZERO {
        return Err("protocol address and transaction hash required".into());
    }
    if !receipt.success {
        return Err("cannot apply a reverted receipt".into());
    }
    let mut output = ReceiptOutputs {
        notes: vec![],
        credits: vec![],
        nullifiers: vec![],
        credit_nullifiers: vec![],
        insertions: vec![],
        created_trees: vec![],
        events: vec![],
    };
    let signatures = [
        P::CommitmentsInserted::SIGNATURE_HASH,
        P::BatchOutputs::SIGNATURE_HASH,
        P::Shield::SIGNATURE_HASH,
        P::Transact::SIGNATURE_HASH,
        P::CrossTreeTransact::SIGNATURE_HASH,
        P::CreditCreated::SIGNATURE_HASH,
        P::CreditDraw::SIGNATURE_HASH,
        P::CreditUpdated::SIGNATURE_HASH,
        P::CreditRevoked::SIGNATURE_HASH,
        P::BatchRequest::SIGNATURE_HASH,
        P::TreeCreated::SIGNATURE_HASH,
    ];
    let mut previous = None;
    for log in &receipt.logs {
        if previous.is_some_and(|last| last >= log.log_index) {
            return Err("canonical logs must be ordered and unique".into());
        }
        previous = Some(log.log_index);
        if log.address != protocol_address
            || !log
                .topics
                .first()
                .is_some_and(|topic| signatures.contains(topic))
        {
            continue;
        }
        let event = P::InvisiCoreEvents::decode_raw_log(&log.topics, &log.data, true)
            .map_err(|e| e.to_string())?;
        match &event {
            P::InvisiCoreEvents::CommitmentsInserted(value) => output.insertions.push(Insertion {
                tree_id: tree(value.treeId)?,
                start_leaf_index: value.startLeafIndex,
                commitments: value.commitments.clone(),
                log_index: log.log_index,
            }),
            P::InvisiCoreEvents::BatchOutputs(value) => output.insertions.push(Insertion {
                tree_id: tree(value.treeId)?,
                start_leaf_index: value.startLeafIndex,
                commitments: value.noteCommitments.clone(),
                log_index: log.log_index,
            }),
            P::InvisiCoreEvents::TreeCreated(value) => {
                output.created_trees.push(tree(value.treeId)?)
            }
            _ => {}
        }
        output.events.push((log.log_index, event));
    }
    let mut inserted = HashMap::new();
    let mut lengths = HashMap::new();
    for insertion in &output.insertions {
        if insertion.commitments.is_empty()
            || insertion.start_leaf_index as usize + insertion.commitments.len() > 65536
        {
            return Err("insertion exceeds tree capacity".into());
        }
        lengths.insert(
            (insertion.tree_id, insertion.start_leaf_index),
            insertion.commitments.len(),
        );
        for (offset, commitment) in insertion.commitments.iter().enumerate() {
            field(*commitment).map_err(|e| e.to_string())?;
            if inserted
                .insert(
                    (
                        insertion.tree_id,
                        insertion.start_leaf_index + offset as u32,
                    ),
                    *commitment,
                )
                .is_some()
            {
                return Err("duplicate canonical insertion".into());
            }
        }
    }
    for (log_index, event) in &output.events {
        let note =
            |id, index, commitment, token, value: &Delivery, kind| -> Result<NoteOutput, String> {
                Ok(NoteOutput {
                    leaf: metadata(
                        receipt, id, index, commitment, token, *log_index, kind, &inserted,
                    )?,
                    delivery: delivery(value, true)?,
                })
            };
        let credit = |id,
                      index,
                      commitment,
                      token,
                      values: &[Delivery],
                      kind|
         -> Result<IndexedCreditState, String> {
            if values.len() != 2 {
                return Err("Credit state requires owner and spender deliveries".into());
            }
            Ok(IndexedCreditState {
                leaf: metadata(
                    receipt, id, index, commitment, token, *log_index, kind, &inserted,
                )?,
                deliveries: [delivery(&values[0], false)?, delivery(&values[1], false)?],
            })
        };
        match event {
            P::InvisiCoreEvents::BatchOutputs(value) => {
                let id = tree(value.treeId)?;
                if value.tokens.len() != value.noteCommitments.len() {
                    return Err("batch token dimensions differ".into());
                }
                let packed = &value.packedDeliveries;
                let mut offset = 0usize;
                for (i, commitment) in value.noteCommitments.iter().enumerate() {
                    let prefix = packed
                        .get(offset..offset + 2)
                        .ok_or("truncated delivery length")?;
                    let length = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
                    offset += 2;
                    if length > 4096 {
                        return Err("delivery too large".into());
                    }
                    let ciphertext = packed
                        .get(offset..offset + length)
                        .ok_or("truncated delivery ciphertext")?;
                    offset += length;
                    let clue = if length == 0 {
                        &[][..]
                    } else {
                        let clue = packed
                            .get(offset..offset + 68)
                            .ok_or("truncated delivery clue")?;
                        offset += 68;
                        clue
                    };
                    output.notes.push(note(
                        id,
                        value.startLeafIndex + i as u32,
                        *commitment,
                        value.tokens[i],
                        &Delivery {
                            ciphertext: ciphertext.to_vec().into(),
                            clue: clue.to_vec().into(),
                        },
                        "BatchOutputs",
                    )?);
                }
                if offset != packed.len() {
                    return Err("trailing packed delivery data".into());
                }
            }
            P::InvisiCoreEvents::Shield(value) => {
                let id = tree(value.treeId)?;
                if lengths.get(&(id, value.startLeafIndex)) != Some(&value.deliveries.len()) {
                    return Err("Shield deliveries do not match insertion length".into());
                }
                for (i, value_delivery) in value.deliveries.iter().enumerate() {
                    let index = value.startLeafIndex + i as u32;
                    let commitment = *inserted
                        .get(&(id, index))
                        .ok_or("missing Shield insertion")?;
                    output.notes.push(note(
                        id,
                        index,
                        commitment,
                        value.token,
                        value_delivery,
                        "Shield",
                    )?);
                }
            }
            P::InvisiCoreEvents::Transact(value) => {
                output.nullifiers.extend_from_slice(&value.nullifiers);
                if value.noteCommitments.len() != value.leafIndices.len()
                    || value.noteCommitments.len() != value.deliveries.len()
                {
                    return Err("Transact output dimensions differ".into());
                }
                for (i, commitment) in value.noteCommitments.iter().enumerate() {
                    output.notes.push(note(
                        tree(value.outputTreeId)?,
                        value.leafIndices[i],
                        *commitment,
                        value.token,
                        &value.deliveries[i],
                        "Transact",
                    )?);
                }
            }
            P::InvisiCoreEvents::CrossTreeTransact(value) => {
                output.nullifiers.extend_from_slice(&value.nullifiers);
                if value.noteCommitments.len() != value.leafIndices.len()
                    || value.noteCommitments.len() != value.deliveries.len()
                {
                    return Err("CrossTreeTransact output dimensions differ".into());
                }
                for (i, commitment) in value.noteCommitments.iter().enumerate() {
                    output.notes.push(note(
                        tree(value.outputTreeId)?,
                        value.leafIndices[i],
                        *commitment,
                        value.token,
                        &value.deliveries[i],
                        "CrossTreeTransact",
                    )?);
                }
            }
            P::InvisiCoreEvents::BatchRequest(value) => {
                output.nullifiers.extend_from_slice(&value.nullifiers)
            }
            P::InvisiCoreEvents::CreditCreated(value) => output.credits.push(credit(
                tree(value.outputTreeId)?,
                value.leafIndex,
                value.creditCommitment,
                value.token,
                &value.deliveries,
                "CreditCreated",
            )?),
            P::InvisiCoreEvents::CreditUpdated(value) => {
                output.credit_nullifiers.push(value.params.nullifier);
                output.credits.push(credit(
                    tree(value.outputTreeId)?,
                    value.leafIndex,
                    value.params.creditCommitment,
                    value.params.token,
                    &value.deliveries,
                    "CreditUpdated",
                )?);
            }
            P::InvisiCoreEvents::CreditDraw(value) => {
                let p = &value.params;
                let n = p.creditCommitments.len();
                if n == 0
                    || p.nullifiers.len() != n
                    || p.recoveryAmounts.len() != n
                    || value.leafIndices.len() != n + 1
                    || value.deliveries.len() != 2 * n + 1
                {
                    return Err("CreditDraw state and Note dimensions differ".into());
                }
                output.credit_nullifiers.extend_from_slice(&p.nullifiers);
                let id = tree(value.outputTreeId)?;
                for (i, commitment) in p.creditCommitments.iter().enumerate() {
                    if *commitment == B256::ZERO {
                        return Err("zero successor Credit state".into());
                    }
                    output.credits.push(credit(
                        id,
                        value.leafIndices[i],
                        *commitment,
                        p.token,
                        &value.deliveries[2 * i..2 * i + 2],
                        "CreditDraw",
                    )?);
                }
                output.notes.push(note(
                    id,
                    value.leafIndices[n],
                    p.noteCommitment,
                    p.token,
                    &value.deliveries[2 * n],
                    "CreditDraw",
                )?);
            }
            _ => {}
        }
    }
    for nullifier in output.nullifiers.iter().chain(&output.credit_nullifiers) {
        field(*nullifier).map_err(|e| e.to_string())?;
    }
    Ok(output)
}
