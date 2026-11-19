//! Financial delivery records authenticated against complete canonical receipt insertions.
use super::{IInvisiCore::Delivery, InvisiCore as P};
use crate::interfaces::{
    field, CanonicalReceipt, IndexedCreditState, IndexedDelivery, LeafMetadata, NoteOutput,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
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
    let mut previous = None;
    for log in &receipt.logs {
        if previous.is_some_and(|last| last >= log.log_index) {
            return Err("canonical logs must be ordered and unique".into());
        }
        previous = Some(log.log_index);
        if log.address != protocol_address {
            continue;
        }
        let event = match log.topics.first() {
            Some(signature) if *signature == P::CommitmentsInserted::SIGNATURE_HASH => {
                P::CommitmentsInserted::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )
                .map(P::InvisiCoreEvents::CommitmentsInserted)
            }
            Some(signature) if *signature == P::TreeCreated::SIGNATURE_HASH => {
                P::TreeCreated::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::TreeCreated)
            }
            Some(signature) if *signature == P::NoteOperation::SIGNATURE_HASH => {
                P::NoteOperation::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::NoteOperation)
            }
            Some(signature) if *signature == P::NoteOutputs::SIGNATURE_HASH => {
                P::NoteOutputs::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::NoteOutputs)
            }
            Some(signature) if *signature == P::NoteStateTransition::SIGNATURE_HASH => {
                P::NoteStateTransition::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )
                .map(P::InvisiCoreEvents::NoteStateTransition)
            }
            Some(signature) if *signature == P::PublicDeposit::SIGNATURE_HASH => {
                P::PublicDeposit::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::PublicDeposit)
            }
            Some(signature) if *signature == P::PublicWithdrawal::SIGNATURE_HASH => {
                P::PublicWithdrawal::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::PublicWithdrawal)
            }
            Some(signature) if *signature == P::TransactAggregated::SIGNATURE_HASH => {
                P::TransactAggregated::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )
                .map(P::InvisiCoreEvents::TransactAggregated)
            }
            Some(signature) if *signature == P::CreditCreated::SIGNATURE_HASH => {
                P::CreditCreated::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::CreditCreated)
            }
            Some(signature) if *signature == P::CreditUpdated::SIGNATURE_HASH => {
                P::CreditUpdated::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::CreditUpdated)
            }
            Some(signature) if *signature == P::CreditDraw::SIGNATURE_HASH => {
                P::CreditDraw::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::CreditDraw)
            }
            Some(signature) if *signature == P::CreditStateTransition::SIGNATURE_HASH => {
                P::CreditStateTransition::decode_raw_log_validate(
                    log.topics.iter().copied(),
                    &log.data,
                )
                .map(P::InvisiCoreEvents::CreditStateTransition)
            }
            Some(signature) if *signature == P::CreditRevoked::SIGNATURE_HASH => {
                P::CreditRevoked::decode_raw_log_validate(log.topics.iter().copied(), &log.data)
                    .map(P::InvisiCoreEvents::CreditRevoked)
            }
            _ => continue,
        }
        .map_err(|error| error.to_string())?;
        match &event {
            P::InvisiCoreEvents::CommitmentsInserted(value) => output.insertions.push(Insertion {
                tree_id: tree(value.treeId)?,
                start_leaf_index: value.startLeafIndex,
                commitments: value.commitments.clone(),
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
    let mut claimed = std::collections::HashSet::new();
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
            P::InvisiCoreEvents::NoteOutputs(value) => {
                let operation = output
                    .events
                    .iter()
                    .filter_map(|(_, event)| match event {
                        P::InvisiCoreEvents::NoteOperation(op)
                            if op.operationId == value.operationId =>
                        {
                            Some(op)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if operation.len() != 1 {
                    return Err("missing or duplicate Note operation".into());
                }
                let operation = operation[0];
                let count =
                    usize::try_from(operation.outputCount).map_err(|_| "output count overflow")?;
                if count == 0 || count > 190 {
                    return Err("invalid Note output count".into());
                }
                let id = tree(value.treeId)?;
                let matching = output
                    .insertions
                    .iter()
                    .filter(|insertion| {
                        insertion.tree_id == id
                            && value.startLeafIndex >= insertion.start_leaf_index
                            && u64::from(value.startLeafIndex) + count as u64
                                <= u64::from(insertion.start_leaf_index)
                                    + insertion.commitments.len() as u64
                    })
                    .count();
                if matching != 1 {
                    return Err("output range has no unique matching insertion".into());
                }
                let mut offset = 0usize;
                for i in 0..count {
                    let packed = &value.packedDeliveries;
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
                        .ok_or("truncated ciphertext")?;
                    offset += length;
                    let clue = if length == 0 {
                        &[][..]
                    } else {
                        let clue = packed.get(offset..offset + 68).ok_or("truncated clue")?;
                        offset += 68;
                        clue
                    };
                    let index = value
                        .startLeafIndex
                        .checked_add(i as u32)
                        .ok_or("leaf overflow")?;
                    if !claimed.insert((id, index)) {
                        return Err("overlapping output ranges".into());
                    }
                    let commitment = *inserted.get(&(id, index)).ok_or("missing insertion")?;
                    output.notes.push(note(
                        id,
                        index,
                        commitment,
                        operation.token,
                        &Delivery {
                            ciphertext: ciphertext.to_vec().into(),
                            clue: clue.to_vec().into(),
                        },
                        "NoteOutputs",
                    )?);
                }
                if offset != value.packedDeliveries.len() {
                    return Err("trailing packed delivery data".into());
                }
            }
            P::InvisiCoreEvents::NoteStateTransition(value) => {
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
                output.notes.push(note(
                    tree(value.outputTreeId)?,
                    value.noteLeafIndex,
                    value.noteCommitment,
                    value.token,
                    &value.delivery,
                    "CreditDraw",
                )?);
            }
            P::InvisiCoreEvents::CreditStateTransition(value) => {
                let p = &value.state;
                let n = p.creditCommitments.len();
                if n == 0
                    || p.nullifiers.len() != n
                    || p.recoveryAmounts.len() != n
                    || value.creditLeafIndices.len() != n
                    || value.creditDeliveries.len() != 2 * n
                {
                    return Err("Credit state dimensions differ".into());
                }
                let results = output
                    .events
                    .iter()
                    .filter_map(|(_, event)| match event {
                        P::InvisiCoreEvents::CreditDraw(draw)
                            if draw.outputTreeId == value.outputTreeId
                                && draw.noteCommitment == value.noteCommitment =>
                        {
                            Some(draw)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if results.len() != 1 {
                    return Err("Credit transition requires unique draw result".into());
                }
                output.credit_nullifiers.extend_from_slice(&p.nullifiers);
                for (i, commitment) in p.creditCommitments.iter().enumerate() {
                    output.credits.push(credit(
                        tree(value.outputTreeId)?,
                        value.creditLeafIndices[i],
                        *commitment,
                        results[0].token,
                        &value.creditDeliveries[2 * i..2 * i + 2],
                        "CreditStateTransition",
                    )?);
                }
            }
            _ => {}
        }
    }
    let mut positions = std::collections::HashSet::new();
    for leaf in output
        .notes
        .iter()
        .map(|v| &v.leaf)
        .chain(output.credits.iter().map(|v| &v.leaf))
    {
        if !positions.insert((leaf.tree_id, leaf.leaf_index)) {
            return Err("overlapping financial output positions".into());
        }
    }
    for nullifier in output.nullifiers.iter().chain(&output.credit_nullifiers) {
        field(*nullifier).map_err(|e| e.to_string())?;
    }
    validate_operations(&output, None)?;
    Ok(output)
}

/// Decode and authenticate operation IDs against the deployment's chain domain.
pub fn decode_receipt_outputs_with_context(
    context: invisi_sdk_primitives::note::ProtocolContext,
    receipt: &CanonicalReceipt,
) -> Result<ReceiptOutputs, String> {
    let address = Address::from_slice(&context.protocol_address.to_be_bytes::<32>()[12..]);
    let outputs = decode_receipt_outputs(address, receipt)?;
    validate_operations(&outputs, Some((context.chain_id, address)))?;
    Ok(outputs)
}

fn validate_operations(
    outputs: &ReceiptOutputs,
    domain: Option<(u64, Address)>,
) -> Result<(), String> {
    use super::IInvisiCore::CrossTreeTransactParams;
    use alloy_primitives::keccak256;
    use alloy_sol_types::SolValue;
    use std::collections::HashSet;
    let mut operations = HashSet::new();
    let mut members = HashSet::new();
    for (index, event) in &outputs.events {
        let P::InvisiCoreEvents::NoteOperation(op) = event else {
            continue;
        };
        if !operations.insert(op.operationId)
            || op.kind > 1
            || op.token == Address::ZERO
            || op.deadline >= U256::from(1) << 64
            || op.feeAmount >= U256::from(1) << 128
            || (op.feeAmount == U256::ZERO) != (op.feeRecipient == Address::ZERO)
        {
            return Err("invalid or duplicate Note operation".into());
        }
        let mut params = CrossTreeTransactParams {
            token: op.token,
            sources: vec![],
            nullifiers: vec![],
            noteCommitments: vec![],
            withdrawalAddress: Address::ZERO,
            withdrawalAmount: U256::ZERO,
            deadline: op.deadline,
            feeRecipient: op.feeRecipient,
            feeAmount: op.feeAmount,
        };
        let mut payer = Address::ZERO;
        let mut amount = U256::ZERO;
        let mut deliveries = Vec::new();
        let mut seen = HashSet::new();
        for (event_index, event) in &outputs.events {
            let kind = match event {
                P::InvisiCoreEvents::NoteOutputs(v) if v.operationId == op.operationId => {
                    let tree = tree(v.treeId)?;
                    for note in outputs.notes.iter().filter(|n| {
                        n.leaf.kind == "NoteOutputs"
                            && n.leaf.tree_id == tree
                            && n.leaf.log_index == *event_index
                    }) {
                        params.noteCommitments.push(note.leaf.commitment);
                        deliveries.push(Delivery {
                            ciphertext: note.delivery.ciphertext.clone().into(),
                            clue: note.delivery.clue.clone().into(),
                        });
                    }
                    "outputs"
                }
                P::InvisiCoreEvents::NoteStateTransition(v) if v.operationId == op.operationId => {
                    params.sources = v.sources.clone();
                    params.nullifiers = v.nullifiers.clone();
                    let mut last = U256::ZERO;
                    if op.kind != 1
                        || v.nullifiers.is_empty()
                        || v.sources.is_empty()
                        || v.sources.len() > v.nullifiers.len()
                    {
                        return Err("invalid Note transition".into());
                    }
                    let mut nullifiers = HashSet::new();
                    for n in &v.nullifiers {
                        if !nullifiers.insert(n) {
                            return Err("duplicate Note nullifier".into());
                        }
                    }
                    for source in &v.sources {
                        if source.treeId <= last
                            || source.treeId >= U256::from(1) << 64
                            || source.merkleRoot == B256::ZERO
                        {
                            return Err("invalid source order".into());
                        }
                        last = source.treeId;
                    }
                    "state"
                }
                P::InvisiCoreEvents::PublicDeposit(v) if v.operationId == op.operationId => {
                    if v.token != op.token
                        || v.amount == U256::ZERO
                        || v.amount >= U256::from(1) << 128
                        || v.payer == Address::ZERO
                    {
                        return Err("invalid public deposit".into());
                    }
                    payer = v.payer;
                    amount = v.amount;
                    "deposit"
                }
                P::InvisiCoreEvents::PublicWithdrawal(v) if v.operationId == op.operationId => {
                    if v.token != op.token
                        || v.amount == U256::ZERO
                        || v.amount >= U256::from(1) << 128
                        || v.recipient == Address::ZERO
                    {
                        return Err("invalid public withdrawal".into());
                    }
                    params.withdrawalAddress = v.recipient;
                    params.withdrawalAmount = v.amount;
                    "withdrawal"
                }
                _ => continue,
            };
            if !seen.insert(kind) {
                return Err("duplicate operation fact".into());
            }
        }
        if U256::from(deliveries.len()) != op.outputCount
            || op.outputCount > U256::from(190)
            || op.kind == 0
                && (deliveries.is_empty()
                    || deliveries.len() > 10
                    || !params.nullifiers.is_empty()
                    || amount == U256::ZERO
                    || params.withdrawalAmount != U256::ZERO)
            || op.kind == 1 && params.nullifiers.is_empty() && amount == U256::ZERO
        {
            return Err("invalid Note operation funding or output count".into());
        }
        if let Some((chain, address)) = domain {
            let actual = keccak256(
                (
                    keccak256("Invisi.NoteOperation.v1"),
                    U256::from(chain),
                    address,
                    U256::from(op.kind),
                    params,
                    payer,
                    amount,
                    keccak256((deliveries,).abi_encode_params()),
                )
                    .abi_encode_params(),
            );
            if actual != op.operationId {
                return Err("Note operation hash mismatch".into());
            }
        }
        let _ = index;
    }
    for (index, event) in &outputs.events {
        match event {
            P::InvisiCoreEvents::TransactAggregated(v) => {
                if v.operationIds.is_empty() || v.operationIds.len() > 5 {
                    return Err("invalid aggregate membership".into());
                }
                for id in &v.operationIds {
                    if !members.insert(id) || !outputs.events.iter().any(|(i,e)|*i<*index && matches!(e,P::InvisiCoreEvents::NoteOperation(op) if op.operationId==*id && op.kind==1)) {return Err("invalid aggregate member".into());}
                }
            }
            P::InvisiCoreEvents::NoteOutputs(v) if !operations.contains(&v.operationId) => {
                return Err("orphan Note outputs".into())
            }
            P::InvisiCoreEvents::NoteStateTransition(v) if !operations.contains(&v.operationId) => {
                return Err("orphan Note transition".into())
            }
            P::InvisiCoreEvents::PublicDeposit(v) if !operations.contains(&v.operationId) => {
                return Err("orphan public deposit".into())
            }
            P::InvisiCoreEvents::PublicWithdrawal(v) if !operations.contains(&v.operationId) => {
                return Err("orphan public withdrawal".into())
            }
            _ => {}
        }
    }
    Ok(())
}
