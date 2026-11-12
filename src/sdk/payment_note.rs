//! Portable private Note openings and independent canonical-chain verification.
use super::*;
use crate::rpc::{CanonicalChain, FinalityTag, Membership, RpcTransport};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
#[derive(Clone)]
pub struct PaymentNote {
    note: Note,
    commitment: B256,
}
impl std::fmt::Debug for PaymentNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaymentNote([private opening])")
    }
}
impl PaymentNote {
    pub fn from_note(note: &Note) -> Result<Self> {
        model(note.validate())?;
        if note.context.chain_id == 0 || note.context.protocol_address == U256::ZERO {
            return Err("positive payment note chain and protocol required".into());
        }
        let mut note = note.clone();
        note.payload.clear();
        let commitment = field_word(model(note.commitment())?);
        if commitment == B256::ZERO {
            return Err("zero payment note commitment".into());
        }
        Ok(Self { note, commitment })
    }
    pub fn note(&self) -> &Note {
        &self.note
    }
    pub fn commitment(&self) -> B256 {
        self.commitment
    }
    pub fn encode(&self) -> String {
        let mut bytes = vec![1];
        bytes.extend(self.note.context.chain_id.to_be_bytes());
        bytes.extend(&self.note.context.protocol_address.to_be_bytes::<32>()[12..]);
        bytes.extend(&self.note.token_address.to_be_bytes::<32>()[12..]);
        bytes.extend(&self.note.amount.to_be_bytes::<32>()[16..]);
        bytes.extend(&self.note.owner_address.to_be_bytes::<32>()[12..]);
        bytes.extend(self.note.nonce.to_be_bytes::<32>());
        bytes.extend(self.commitment.as_slice());
        format!("ipn:{}", URL_SAFE_NO_PAD.encode(bytes))
    }
    pub fn decode(encoded: &str) -> Result<Self> {
        if encoded.len() != 203 || !encoded.starts_with("ipn:") {
            return Err("invalid payment note encoding".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&encoded[4..])
            .map_err(|_| "invalid payment note encoding")?;
        if bytes.len() != 149 || bytes[0] != 1 {
            return Err("unsupported payment note version or length".into());
        }
        let note = Note {
            context: ProtocolContext {
                chain_id: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
                protocol_address: U256::from_be_slice(&bytes[9..29]),
            },
            token_address: U256::from_be_slice(&bytes[29..49]),
            amount: U256::from_be_slice(&bytes[49..65]),
            owner_address: U256::from_be_slice(&bytes[65..85]),
            nonce: U256::from_be_slice(&bytes[85..117]),
            payload: vec![],
        };
        let result = Self::from_note(&note)?;
        if result.commitment.as_slice() != &bytes[117..] || result.encode() != encoded {
            return Err("payment note commitment or canonical encoding mismatch".into());
        }
        Ok(result)
    }
    pub fn verify<T: RpcTransport, C: CanonicalChain>(
        &self,
        rpc: &crate::rpc::ProtocolRpcClient<T, C>,
    ) -> Result<VerifiedPaymentNote> {
        self.verify_with_finality(rpc, FinalityTag::Finalized)
    }
    pub fn verify_spendable<T: RpcTransport, C: CanonicalChain>(
        &self,
        rpc: &crate::rpc::ProtocolRpcClient<T, C>,
        wallet: &Wallet,
    ) -> Result<SpendablePaymentNote> {
        self.verify_spendable_with_finality(rpc, wallet, FinalityTag::Finalized)
    }
    pub fn verify_with_finality<T: RpcTransport, C: CanonicalChain>(
        &self,
        rpc: &crate::rpc::ProtocolRpcClient<T, C>,
        finality: FinalityTag,
    ) -> Result<VerifiedPaymentNote> {
        let context = self.note.context;
        let deployment = rpc.deployment();
        if deployment.chain_id != context.chain_id.to_string()
            || deployment.protocol.address != word_address(context.protocol_address)?
        {
            return Err("payment note deployment mismatch".into());
        }
        rpc.validate_deployment().map_err(|e| e.to_string())?;
        let heads = crate::rpc::read_chain_finality(&rpc.chain);
        let head = match finality {
            FinalityTag::Latest => heads.latest,
            FinalityTag::Safe => heads.safe,
            FinalityTag::Finalized => heads.finalized,
        };
        let head = head.block.ok_or("requested native finality unavailable")?;
        let status = rpc.get_status().map_err(|e| e.to_string())?;
        let number = head.number.min(
            status
                .indexed_head
                .ok_or("protocol has no indexed blocks")?
                .number,
        );
        if number < deployment.protocol.from_block {
            return Err("insufficient confirmed blocks".into());
        }
        let checked_at = rpc.chain.block(number).map_err(|e| e.to_string())?;
        let lookup = rpc
            .get_note(self.commitment, &checked_at)
            .map_err(|e| e.to_string())?
            .ok_or("payment note not indexed")?;
        if lookup.output.leaf.token != word_address(self.note.token_address)? {
            return Err("payment note token mismatch".into());
        }
        canonical(&rpc.chain, &lookup.output.leaf.block)?;
        canonical(&rpc.chain, &lookup.membership.block)?;
        finality_fence(&rpc.chain, finality, &checked_at)?;
        rpc.validate_deployment().map_err(|e| e.to_string())?;
        canonical(&rpc.chain, &checked_at)?;
        Ok(VerifiedPaymentNote {
            membership: lookup.membership,
            checked_at,
        })
    }
    pub fn verify_spendable_with_finality<T: RpcTransport, C: CanonicalChain>(
        &self,
        rpc: &crate::rpc::ProtocolRpcClient<T, C>,
        wallet: &Wallet,
        finality: FinalityTag,
    ) -> Result<SpendablePaymentNote> {
        if address_word(wallet.owner_address()) != self.note.owner_address {
            return Err("payment note owner mismatch".into());
        }
        let verified = self.verify_with_finality(rpc, finality)?;
        let heads = crate::rpc::read_chain_finality(&rpc.chain);
        let current = heads.latest.block.ok_or("native latest head unavailable")?;
        if rpc
            .contract_read(
                rpc.deployment().protocol.address,
                &InvisiProtocol::isNullifierSpentCall {
                    nullifier: field_word(model(self.note.nullifier())?),
                },
                &current,
            )
            .map_err(|e| e.to_string())?
            ._0
        {
            return Err("payment note already spent".into());
        }
        let known = rpc
            .contract_read(
                rpc.deployment().protocol.address,
                &InvisiProtocol::rootHistoryCall {
                    _0: U256::from(verified.membership.tree_id),
                    _1: verified.membership.root,
                },
                &current,
            )
            .map_err(|e| e.to_string())?;
        if !known._0 {
            return Err("payment note root no longer spendable".into());
        }
        canonical(&rpc.chain, &current)?;
        finality_fence(&rpc.chain, finality, &verified.checked_at)?;
        rpc.validate_deployment().map_err(|e| e.to_string())?;
        canonical(&rpc.chain, &current)?;
        let path: Vec<U256> = verified
            .membership
            .path
            .iter()
            .map(|p| U256::from_be_slice(p.as_slice()))
            .collect();
        let input = NoteInput {
            note: self.note.clone(),
            tree_id: verified.membership.tree_id,
            leaf_index: u16::try_from(verified.membership.leaf_index)
                .map_err(|_| "invalid leaf index")?,
            path: path.try_into().map_err(|_| "invalid membership depth")?,
            root: U256::from_be_slice(verified.membership.root.as_slice()),
        };
        Ok(SpendablePaymentNote {
            verified,
            input,
            spendability_checked_at: current,
        })
    }
}
fn canonical<C: CanonicalChain>(chain: &C, block: &CanonicalBlock) -> Result<()> {
    if chain.block(block.number).map_err(|e| e.to_string())? != *block {
        return Err("verification block reorganized".into());
    }
    Ok(())
}
pub(super) fn finality_fence<C: CanonicalChain>(
    chain: &C,
    tag: FinalityTag,
    block: &CanonicalBlock,
) -> Result<()> {
    canonical(chain, block)?;
    let heads = crate::rpc::read_chain_finality(chain);
    let head = match tag {
        FinalityTag::Latest => heads.latest,
        FinalityTag::Safe => heads.safe,
        FinalityTag::Finalized => heads.finalized,
    };
    if head.block.is_none_or(|h| h.number < block.number) {
        return Err("native finality changed during verification".into());
    }
    canonical(chain, block)
}
#[derive(Clone, Debug)]
pub struct VerifiedPaymentNote {
    membership: Membership,
    checked_at: CanonicalBlock,
}
impl VerifiedPaymentNote {
    pub fn membership(&self) -> &Membership {
        &self.membership
    }
    pub fn checked_at(&self) -> &CanonicalBlock {
        &self.checked_at
    }
}
pub struct SpendablePaymentNote {
    verified: VerifiedPaymentNote,
    input: NoteInput,
    spendability_checked_at: CanonicalBlock,
}
impl SpendablePaymentNote {
    pub fn verified(&self) -> &VerifiedPaymentNote {
        &self.verified
    }
    pub fn to_input(&self) -> NoteInput {
        self.input.clone()
    }
    pub fn spendability_checked_at(&self) -> &CanonicalBlock {
        &self.spendability_checked_at
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionRecipient {
    Owner { owner_address: Address },
    Identity { identity: U256 },
}
#[derive(Clone)]
pub struct TransactionOutput {
    output: NoteOutput,
    change: bool,
}
impl TransactionOutput {
    pub fn token_address(&self) -> Address {
        self.output.token
    }
    pub fn recipient(&self) -> TransactionRecipient {
        match &self.output.note {
            Some(note) => TransactionRecipient::Owner {
                owner_address: Address::from_slice(&note.owner_address.to_be_bytes::<32>()[12..]),
            },
            None => TransactionRecipient::Identity {
                identity: self.output.identity,
            },
        }
    }
    pub fn context(&self) -> ProtocolContext {
        self.output.context
    }
    pub fn amount(&self) -> U256 {
        self.output.amount
    }
    pub fn commitment(&self) -> B256 {
        self.output.commitment
    }
    pub fn identity(&self) -> U256 {
        self.output.identity
    }
    pub fn nonce(&self) -> Option<U256> {
        self.output.note.as_ref().map(|n| n.nonce)
    }
    pub fn change(&self) -> bool {
        self.change
    }
    pub fn export_payment_note(&self) -> Result<String> {
        Ok(PaymentNote::from_note(
            self.output
                .note
                .as_ref()
                .ok_or("output opening unavailable")?,
        )?
        .encode())
    }
}
impl PreparedTransaction {
    pub fn get_outputs(&self) -> Vec<TransactionOutput> {
        self.outputs()
            .iter()
            .map(|o| TransactionOutput {
                output: o.clone(),
                change: o.change,
            })
            .collect()
    }
}
impl PreparedCredit {
    pub fn get_outputs(&self) -> Vec<TransactionOutput> {
        self.output_note()
            .map(|o| TransactionOutput {
                output: o.clone(),
                change: false,
            })
            .into_iter()
            .collect()
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    #[test]
    fn detached_outputs_keep_token_recipient_and_portable_opening() {
        let (chain, wallet, mut request, _) = test_support::note_fixture();
        let mut note = request.inputs[0].note.clone();
        note.amount = sum(request.inputs.iter().map(|i| i.note.amount)).unwrap();
        note.payload = vec![3];
        request.outputs = vec![NoteOutput::from_note(note.clone(), None).unwrap()];
        request.withdrawal = None;
        request.fee = Fee::default();
        request.automatic_change = false;
        let prepared = Invisi::new(chain)
            .prepare_transfer(&wallet, request)
            .unwrap();
        let output = prepared.get_outputs().remove(0);
        assert_eq!(
            output.token_address(),
            word_address(note.token_address).unwrap()
        );
        assert_eq!(
            output.recipient(),
            TransactionRecipient::Owner {
                owner_address: wallet.owner_address()
            }
        );
        assert!(!output.change());
        let portable = PaymentNote::decode(&output.export_payment_note().unwrap()).unwrap();
        assert_eq!(portable.commitment(), output.commitment());
        assert_eq!(portable.note().nonce, output.nonce().unwrap());
        assert!(portable.note().payload.is_empty());
        let identity = NoteOutput::identity(
            note.context,
            word_address(note.token_address).unwrap(),
            U256::from(9),
            U256::from(1),
        )
        .unwrap();
        let opaque = TransactionOutput {
            output: identity,
            change: false,
        };
        assert_eq!(
            opaque.recipient(),
            TransactionRecipient::Identity {
                identity: U256::from(9)
            }
        );
        assert!(opaque.export_payment_note().is_err());
    }
}
