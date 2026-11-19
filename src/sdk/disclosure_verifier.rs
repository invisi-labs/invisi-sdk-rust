//! Read-only selective disclosure authenticated by canonical receipts and native finality.
use super::*;
use crate::disclosure::{Disclosure, DisclosureOutput, DisclosureResult, DisclosureRole};
use crate::rpc::{CanonicalChain, ChainReceipts, FinalityTag, ProtocolRpcClient, RpcTransport};
#[derive(Clone, Debug)]
pub struct DisclosureReference {
    pub transaction_hash: B256,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub role: DisclosureRole,
}
#[derive(Clone, Debug)]
pub struct DisclosureEvidence {
    pub reference: DisclosureReference,
    pub block: CanonicalBlock,
    pub finality: FinalityTag,
    pub output: DisclosureOutput,
}
#[derive(Clone, Debug)]
pub struct VerifiedDisclosure {
    pub result: DisclosureResult,
    pub reference: DisclosureReference,
    pub commitment: U256,
    pub block: CanonicalBlock,
    pub finality: FinalityTag,
}
pub struct DisclosureVerifier<'a, T: RpcTransport, C: CanonicalChain + ChainReceipts> {
    rpc: &'a ProtocolRpcClient<T, C>,
    token: Address,
    finality: FinalityTag,
}
impl<'a, T: RpcTransport, C: CanonicalChain + ChainReceipts> DisclosureVerifier<'a, T, C> {
    pub fn new(rpc: &'a ProtocolRpcClient<T, C>, token: Address) -> Result<Self> {
        Self::with_finality(rpc, token, FinalityTag::Finalized)
    }
    pub fn with_finality(
        rpc: &'a ProtocolRpcClient<T, C>,
        token: Address,
        finality: FinalityTag,
    ) -> Result<Self> {
        if token == Address::ZERO {
            return Err("nonzero disclosure token required".into());
        }
        Ok(Self {
            rpc,
            token,
            finality,
        })
    }
    fn barrier(&self, block: &CanonicalBlock) -> Result<()> {
        self.rpc.validate_deployment().map_err(|e| e.to_string())?;
        super::payment_note::finality_fence(&self.rpc.chain, self.finality, block)?;
        if self
            .rpc
            .chain
            .chain_id()
            .map_err(|e| e.to_string())?
            .to_string()
            != self.rpc.deployment().chain_id
        {
            return Err("disclosure chain changed".into());
        }
        Ok(())
    }
    pub fn read_output(&self, reference: DisclosureReference) -> Result<DisclosureEvidence> {
        if reference.transaction_hash == B256::ZERO || reference.tree_id == 0 {
            return Err("invalid disclosure reference".into());
        }
        self.rpc.validate_deployment().map_err(|e| e.to_string())?;
        let receipt = self
            .rpc
            .chain
            .receipt(reference.transaction_hash)
            .map_err(|e| e.to_string())?
            .ok_or("disclosure receipt unavailable")?;
        if receipt.transaction_hash != reference.transaction_hash
            || !receipt.success
            || receipt.block.number < self.rpc.deployment().protocol.from_block
        {
            return Err("disclosure receipt binding mismatch".into());
        }
        let outputs = protocol::decode_receipt_outputs_with_context(
            ProtocolContext {
                chain_id: self
                    .rpc
                    .deployment()
                    .chain_id()
                    .map_err(|e| e.to_string())?,
                protocol_address: address_word(self.rpc.deployment().protocol.address),
            },
            &receipt,
        )?;
        let matches = |leaf: &crate::rpc::LeafMetadata| {
            leaf.tree_id == reference.tree_id
                && leaf.leaf_index == reference.leaf_index as u32
                && leaf.token == self.token
        };
        let mut candidates = Vec::new();
        match reference.role {
            DisclosureRole::Funds => {
                for note in outputs.notes {
                    if matches(&note.leaf) {
                        candidates.push((note.leaf, note.delivery.ciphertext));
                    }
                }
            }
            DisclosureRole::Owner | DisclosureRole::Spender => {
                for credit in outputs.credits {
                    if matches(&credit.leaf) {
                        let i = if reference.role == DisclosureRole::Owner {
                            0
                        } else {
                            1
                        };
                        candidates.push((credit.leaf, credit.deliveries[i].ciphertext.clone()));
                    }
                }
            }
        }
        if candidates.len() != 1 {
            return Err("disclosure output has no unique canonical insertion and delivery".into());
        }
        let (leaf, ciphertext) = candidates.remove(0);
        self.barrier(&receipt.block)?;
        let context = ProtocolContext {
            chain_id: self
                .rpc
                .deployment()
                .chain_id
                .parse()
                .map_err(|_| "invalid deployment chain")?,
            protocol_address: address_word(self.rpc.deployment().protocol.address),
        };
        let output = DisclosureOutput {
            context: DeliveryContext {
                context,
                token_address: address_word(self.token),
                output_commitment: U256::from_be_slice(leaf.commitment.as_slice()),
            },
            role: reference.role,
            ciphertext: if ciphertext.is_empty() {
                None
            } else {
                Some(ciphertext)
            },
        };
        Ok(DisclosureEvidence {
            reference,
            block: receipt.block,
            finality: self.finality,
            output,
        })
    }
    pub fn verify(
        &self,
        disclosure: &Disclosure,
        reference: DisclosureReference,
    ) -> Result<VerifiedDisclosure> {
        let evidence = self.read_output(reference)?;
        let result = model(disclosure.verify(&evidence.output))?;
        self.barrier(&evidence.block)?;
        Ok(VerifiedDisclosure {
            result,
            reference: evidence.reference,
            commitment: evidence.output.context.output_commitment,
            block: evidence.block,
            finality: evidence.finality,
        })
    }
}
