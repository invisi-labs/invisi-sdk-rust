//! Locally checked evidence from a trusted RPC; chain and receipt authentication remain server claims.
use super::*;
use alloy_primitives::B256;
use serde_json::{json, Value};

/// A client pinned to one deployment, with no independent chain reader.
pub struct TrustedProtocolRpcClient<T: RpcTransport> {
    rpc: JsonRpc<T>,
    deployment: ProtocolDeployment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedNotePendingReason {
    NotObserved,
    PendingIndex,
    ConfirmationPending,
    FinalityUnsupported,
    FinalityUnavailable,
    FinalityInconsistent,
}
/// Native finality asserted by the trusted server, with locally checked bindings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedNoteConfirmation {
    pub finality: FinalityTag,
    pub verified_at: CanonicalBlock,
    pub finality_head: CanonicalBlock,
}
/// Distinct from independently authenticated `IndexedLookup` results.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedNoteLookup {
    Pending {
        indexed_head: Option<CanonicalBlock>,
        reason: TrustedNotePendingReason,
    },
    Confirmed {
        indexed_head: CanonicalBlock,
        output: NoteOutput,
        membership: Membership,
        confirmation: TrustedNoteConfirmation,
    },
}
impl<T: RpcTransport> TrustedProtocolRpcClient<T> {
    pub fn new(transport: T, deployment: ProtocolDeployment) -> Result<Self> {
        deployment.validate()?;
        Ok(Self {
            rpc: JsonRpc::new(transport),
            deployment,
        })
    }
    pub fn deployment(&self) -> &ProtocolDeployment {
        &self.deployment
    }
    /// Uses `[commitment, {"finality":"safe"|"finalized"}]`. No chain requests are made.
    pub fn get_note(&self, commitment: B256, finality: FinalityTag) -> Result<TrustedNoteLookup> {
        if commitment == B256::ZERO || finality == FinalityTag::Latest {
            return Err(Error::Invalid(
                "nonzero commitment and safe/finalized selector required",
            ));
        }
        field(commitment)?;
        let v = self.rpc.call(
            "invisi_getNote",
            json!([commitment, {"finality":finality.as_str()}]),
        )?;
        if v["apiVersion"] != "v1" || v["protocolVersion"] != "1" {
            return Err(Error::Invalid("unsupported service version"));
        }
        if ProtocolDeployment::parse(&v["deployment"])? != self.deployment {
            return Err(Error::Invalid("deployment pins mismatch"));
        }
        for name in [
            "indexedHead",
            "status",
            "reason",
            "output",
            "membership",
            "confirmation",
        ] {
            if v.get(name).is_none() {
                return Err(Error::Invalid("incomplete note confirmation envelope"));
            }
        }
        let head = if v["indexedHead"].is_null() {
            None
        } else {
            Some(self.block(&v["indexedHead"])?)
        };
        if v["status"] == "pending" {
            if ["output", "membership", "confirmation"]
                .iter()
                .any(|key| !v[*key].is_null())
            {
                return Err(Error::Invalid("pending result contains evidence"));
            }
            let reason = match v["reason"].as_str() {
                Some("not_observed") => TrustedNotePendingReason::NotObserved,
                Some("pending_index") => TrustedNotePendingReason::PendingIndex,
                Some("confirmation_pending") => TrustedNotePendingReason::ConfirmationPending,
                Some("finality_unsupported") => TrustedNotePendingReason::FinalityUnsupported,
                Some("finality_unavailable") => TrustedNotePendingReason::FinalityUnavailable,
                Some("finality_inconsistent") => TrustedNotePendingReason::FinalityInconsistent,
                _ => return Err(Error::Invalid("invalid note pending reason")),
            };
            return Ok(TrustedNoteLookup::Pending {
                indexed_head: head,
                reason,
            });
        }
        if v["status"] != "confirmed" || !v["reason"].is_null() {
            return Err(Error::Invalid("invalid note confirmation status"));
        }
        let head = head.ok_or(Error::Invalid("confirmed result requires indexed head"))?;
        let output = NoteOutput::parse(&v["output"])?;
        self.block(&v["output"]["block"])?;
        let leaf = &output.leaf;
        if leaf.commitment != commitment || leaf.transaction_hash == B256::ZERO {
            return Err(Error::Invalid("note output binding mismatch"));
        }
        let c = &v["confirmation"];
        if c["finality"] != finality.as_str() {
            return Err(Error::Invalid("confirmation finality mismatch"));
        }
        let verified = self.block(&c["verifiedAt"])?;
        let native = self.block(&c["finalityHead"])?;
        if verified.number != head.number.min(native.number) {
            return Err(Error::Invalid(
                "confirmation anchor is not indexed finality minimum",
            ));
        }
        let m = &v["membership"];
        let anchor = &m["anchor"];
        let root_block = self.block(&anchor["block"])?;
        let root = hash(&anchor["root"])?;
        field(root)?;
        let count = uint(&anchor["leafCount"], 32)?;
        if uint(&anchor["treeId"], 64)? != leaf.tree_id
            || uint(&m["leafIndex"], 32)? != leaf.leaf_index as u64
            || hash(&m["commitment"])? != commitment
            || count <= leaf.leaf_index as u64
            || count > 1 << TREE_DEPTH
            || leaf.block.number < self.deployment.protocol.from_block
            || leaf.block.number > root_block.number
            || root_block.number > verified.number
        {
            return Err(Error::Invalid("note membership binding mismatch"));
        }
        // All repeated heights must name identical blocks; adjacent blocks must link.
        let blocks = [&leaf.block, &root_block, &verified, &head, &native];
        for a in blocks {
            for b in blocks {
                consistent(a, b)?;
            }
        }
        let path = m["siblings"]
            .as_array()
            .ok_or(Error::Invalid("membership siblings required"))?
            .iter()
            .map(|v| hash(v).map_err(Error::from))
            .collect::<Result<Vec<_>>>()?;
        if path.len() != TREE_DEPTH {
            return Err(Error::Invalid("invalid Merkle depth"));
        }
        let mut current = crate::field::bytes_to_field(commitment.as_slice());
        for (level, sibling) in path.iter().enumerate() {
            field(*sibling)?;
            let sibling = crate::field::bytes_to_field(sibling.as_slice());
            current = if leaf.leaf_index >> level & 1 == 0 {
                crate::poseidon::hash(&[current, sibling])
            } else {
                crate::poseidon::hash(&[sibling, current])
            };
        }
        if crate::field::field_to_bytes_be(current).as_slice() != root.as_slice() {
            return Err(Error::Invalid("invalid Merkle path"));
        }
        Ok(TrustedNoteLookup::Confirmed {
            indexed_head: head,
            membership: Membership {
                tree_id: leaf.tree_id,
                leaf_index: leaf.leaf_index,
                leaf: commitment,
                root,
                path,
                block: verified.clone(),
            },
            output,
            confirmation: TrustedNoteConfirmation {
                finality,
                verified_at: verified,
                finality_head: native,
            },
        })
    }
    fn block(&self, value: &Value) -> Result<CanonicalBlock> {
        let b = CanonicalBlock::parse(value)?;
        if b.number < self.deployment.protocol.from_block || b.hash == B256::ZERO {
            return Err(Error::Invalid("invalid confirmation block"));
        }
        Ok(b)
    }
}
fn consistent(a: &CanonicalBlock, b: &CanonicalBlock) -> Result<()> {
    if a.number == b.number && a != b
        || a.number < b.number && (a.timestamp > b.timestamp || a.hash == b.hash)
        || a.number.checked_add(1) == Some(b.number) && a.hash != b.parent_hash
    {
        return Err(Error::Invalid("inconsistent confirmation blocks"));
    }
    Ok(())
}
