use crate::{
    address::{ReceivingAddress, ReceivingKeys},
    protocol::{IAddressRegistry, InvisiAddressRegistry, TransactionCall},
    rpc::{
        CanonicalChain, CanonicalHead, ChainReceipts, ChainTransactions, Error, EthereumChain,
        ProtocolDeployment, Result, RpcTransport,
    },
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolCall, SolEvent, SolStruct};
use invisi_sdk_protocol::interfaces::CanonicalBlock;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

sol! {
    struct RegisterReceivingKeys { bytes32 walletIdentity; bytes viewingPublicKey; bytes32 clueKey; uint64 nonce; uint64 deadline; }
    struct UpdateReceivingKeys { bytes32 walletIdentity; bytes viewingPublicKey; bytes32 clueKey; uint64 nonce; uint64 deadline; }
    function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
}
pub trait RegistrationReader: CanonicalHead + ChainReceipts + ChainTransactions {
    fn registration_sender(&self, hash: B256) -> Result<Option<Address>>;
}
impl<T: RpcTransport> RegistrationReader for EthereumChain<T> {
    fn registration_sender(&self, hash: B256) -> Result<Option<Address>> {
        let value = self.rpc.call("eth_getTransactionByHash", json!([hash]))?;
        if value.is_null() {
            return Ok(None);
        }
        if value["hash"].as_str().and_then(|s| s.parse::<B256>().ok()) != Some(hash) {
            return Err(Error::Invalid("registry transaction identity mismatch"));
        }
        Ok(Some(
            value["from"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or(Error::Invalid("registry transaction sender missing"))?,
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationStatus {
    Prepared,
    Ready,
    Uncertain,
    Confirmed,
    Failed,
    Expired,
    Reorged,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RegistrationSnapshot")]
pub struct RegistrationOperation {
    deployment: ProtocolDeployment,
    owner: Address,
    keys: ReceivingKeys,
    nonce: u64,
    deadline: u64,
    update: bool,
    status: RegistrationStatus,
    signature: Option<Vec<u8>>,
    transaction_hash: Option<B256>,
    anchor: Option<CanonicalBlock>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationSnapshot {
    deployment: ProtocolDeployment,
    owner: Address,
    keys: ReceivingKeys,
    nonce: u64,
    deadline: u64,
    update: bool,
    status: RegistrationStatus,
    signature: Option<Vec<u8>>,
    transaction_hash: Option<B256>,
    anchor: Option<CanonicalBlock>,
}
impl TryFrom<RegistrationSnapshot> for RegistrationOperation {
    type Error = String;
    fn try_from(raw: RegistrationSnapshot) -> std::result::Result<Self, String> {
        let operation = Self {
            deployment: raw.deployment,
            owner: raw.owner,
            keys: raw.keys,
            nonce: raw.nonce,
            deadline: raw.deadline,
            update: raw.update,
            status: raw.status,
            signature: raw.signature,
            transaction_hash: raw.transaction_hash,
            anchor: raw.anchor,
        };
        operation.deployment.validate().map_err(|e| e.to_string())?;
        operation.keys.validate().map_err(|e| e.to_string())?;
        if operation.owner == Address::ZERO
            || operation.deployment.registry.is_none()
            || operation.nonce == u64::MAX
            || (operation.update != (operation.nonce > 0))
            || operation.transaction_hash == Some(B256::ZERO)
        {
            return Err("invalid registration snapshot".into());
        }
        if (operation.status == RegistrationStatus::Prepared) != operation.signature.is_none()
            || (operation.status == RegistrationStatus::Confirmed
                && (operation.anchor.is_none() || operation.transaction_hash.is_none()))
        {
            return Err("invalid registration state".into());
        }
        Ok(operation)
    }
}

impl RegistrationOperation {
    pub fn prepare<C: CanonicalHead>(
        chain: &C,
        deployment: ProtocolDeployment,
        receiving_address: &str,
        update: bool,
        deadline: Option<u64>,
    ) -> Result<Self> {
        deployment.validate()?;
        let address = ReceivingAddress::parse(receiving_address)
            .map_err(|_| Error::Invalid("invalid receiving address"))?;
        let owner = Address::from_slice(&address.owner_address.to_be_bytes::<32>()[12..]);
        let keys = address
            .keys
            .ok_or(Error::Invalid("full receiving keys required"))?;
        let head = chain.head()?;
        Self::validate_deployment(chain, &deployment, &head)?;
        let registry = deployment
            .registry
            .as_ref()
            .ok_or(Error::Invalid("receiving registry deployment required"))?;
        let raw = chain.call(
            registry.address,
            &InvisiAddressRegistry::receivingKeysOfCall {
                walletIdentity: owner.into_word(),
            }
            .abi_encode(),
            head.number,
        )?;
        let nonce = InvisiAddressRegistry::receivingKeysOfCall::abi_decode_returns_validate(&raw)
            .map_err(|_| Error::Invalid("invalid receiving registry response"))?
            .nonce;
        if nonce == u64::MAX {
            return Err(Error::Invalid("registry nonce exhausted"));
        }
        if (update && nonce == 0) || (!update && nonce != 0) {
            return Err(Error::Invalid("registry registration state changed"));
        }
        let deadline = deadline.unwrap_or(
            head.timestamp
                .checked_add(300)
                .ok_or(Error::Invalid("registration deadline overflow"))?,
        );
        if deadline < head.timestamp {
            return Err(Error::Invalid("registration expired"));
        }
        if chain.block(head.number)? != head {
            return Err(Error::Invalid("registry canonical block changed"));
        }
        Ok(Self {
            deployment,
            owner,
            keys,
            nonce,
            deadline,
            update,
            status: RegistrationStatus::Prepared,
            signature: None,
            transaction_hash: None,
            anchor: None,
        })
    }
    fn validate_deployment<C: CanonicalChain>(
        chain: &C,
        deployment: &ProtocolDeployment,
        head: &CanonicalBlock,
    ) -> Result<()> {
        let registry = deployment
            .registry
            .as_ref()
            .ok_or(Error::Invalid("receiving registry deployment required"))?;
        if chain.chain_id()? != deployment.chain_id()?
            || head.number < registry.from_block
            || keccak256(chain.code_at(registry.address, Some(head.number))?)
                != registry.runtime_code_hash
        {
            return Err(Error::Invalid("registry deployment mismatch"));
        }
        Ok(())
    }
    fn fresh<C: CanonicalHead>(&self, chain: &C) -> Result<CanonicalBlock> {
        let head = chain.head()?;
        Self::validate_deployment(chain, &self.deployment, &head)?;
        if head.timestamp > self.deadline {
            return Err(Error::Invalid("registration expired"));
        }
        let raw = chain.call(
            self.registry_address(),
            &InvisiAddressRegistry::receivingKeysOfCall {
                walletIdentity: self.owner.into_word(),
            }
            .abi_encode(),
            head.number,
        )?;
        let nonce = InvisiAddressRegistry::receivingKeysOfCall::abi_decode_returns_validate(&raw)
            .map_err(|_| Error::Invalid("invalid receiving registry response"))?
            .nonce;
        if nonce != self.nonce {
            return Err(Error::Invalid("registry nonce changed"));
        }
        if chain.block(head.number)? != head {
            return Err(Error::Invalid("registry canonical block changed"));
        }
        Ok(head)
    }
    pub fn owner(&self) -> Address {
        self.owner
    }
    pub fn registry_address(&self) -> Address {
        self.deployment
            .registry
            .as_ref()
            .expect("validated registry")
            .address
    }
    pub fn status(&self) -> RegistrationStatus {
        self.status
    }
    pub fn deadline(&self) -> u64 {
        self.deadline
    }
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    pub fn digest(&self) -> Result<B256> {
        let domain = eip712_domain! {name:"InvisiAddressRegistry",version:"1",chain_id:self.deployment.chain_id()?,verifying_contract:self.registry_address(),};
        let identity = self.owner.into_word();
        let viewing = Bytes::copy_from_slice(&self.keys.viewing_public_key);
        let clue = B256::from(self.keys.clue_key);
        Ok(if self.update {
            UpdateReceivingKeys {
                walletIdentity: identity,
                viewingPublicKey: viewing,
                clueKey: clue,
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(&domain)
        } else {
            RegisterReceivingKeys {
                walletIdentity: identity,
                viewingPublicKey: viewing,
                clueKey: clue,
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(&domain)
        })
    }
    pub fn authorization<C: CanonicalHead>(&self, chain: &C) -> Result<Value> {
        if self.status != RegistrationStatus::Prepared {
            return Err(Error::Invalid("registration is not awaiting authorization"));
        }
        self.fresh(chain)?;
        let primary = if self.update {
            "UpdateReceivingKeys"
        } else {
            "RegisterReceivingKeys"
        };
        Ok(
            json!({"domain":{"name":"InvisiAddressRegistry","version":"1","chainId":self.deployment.chain_id()?.to_string(),"verifyingContract":self.registry_address()},"primaryType":primary,"types":{(primary):[{"name":"walletIdentity","type":"bytes32"},{"name":"viewingPublicKey","type":"bytes"},{"name":"clueKey","type":"bytes32"},{"name":"nonce","type":"uint64"},{"name":"deadline","type":"uint64"}]},"message":{"walletIdentity":self.owner.into_word(),"viewingPublicKey":format!("0x{}",hex::encode(self.keys.viewing_public_key)),"clueKey":B256::from(self.keys.clue_key),"nonce":self.nonce.to_string(),"deadline":self.deadline.to_string()}}),
        )
    }
    pub fn authorize_direct<C: CanonicalHead>(
        mut self,
        chain: &C,
        caller: Address,
    ) -> Result<Self> {
        if self.status != RegistrationStatus::Prepared || caller != self.owner {
            return Err(Error::Invalid("registration direct caller mismatch"));
        }
        self.fresh(chain)?;
        self.signature = Some(Vec::new());
        self.status = RegistrationStatus::Ready;
        Ok(self)
    }
    pub fn with_signature<C: CanonicalHead>(
        mut self,
        chain: &C,
        signature: Vec<u8>,
    ) -> Result<Self> {
        if self.status != RegistrationStatus::Prepared || signature.is_empty() {
            return Err(Error::Invalid("registration signature required"));
        }
        let head = self.fresh(chain)?;
        self.verify_signature(chain, &signature, &head)?;
        self.signature = Some(signature);
        self.status = RegistrationStatus::Ready;
        Ok(self)
    }
    fn verify_signature<C: CanonicalHead>(
        &self,
        chain: &C,
        signature: &[u8],
        head: &CanonicalBlock,
    ) -> Result<()> {
        let digest = self.digest()?;
        let valid = (|| {
            if signature.len() != 65 || ![27, 28].contains(&signature[64]) {
                return None;
            }
            let sig = Signature::from_slice(&signature[..64]).ok()?;
            if sig.normalize_s().is_some() {
                return None;
            }
            let key = VerifyingKey::recover_from_prehash(
                digest.as_slice(),
                &sig,
                RecoveryId::try_from(signature[64] - 27).ok()?,
            )
            .ok()?;
            Some(
                Address::from_slice(&keccak256(&key.to_encoded_point(false).as_bytes()[1..])[12..])
                    == self.owner,
            )
        })()
        .unwrap_or(false);
        if !valid {
            if chain.code_at(self.owner, Some(head.number))?.is_empty() {
                return Err(Error::Invalid("invalid registration signature"));
            }
            let raw = chain.call(
                self.owner,
                &isValidSignatureCall {
                    hash: digest,
                    signature: signature.to_vec().into(),
                }
                .abi_encode(),
                head.number,
            )?;
            if isValidSignatureCall::abi_decode_returns_validate(&raw)
                .map_err(|_| Error::Invalid("invalid ERC1271 registration response"))?
                != [0x16, 0x26, 0xba, 0x7e]
            {
                return Err(Error::Invalid("invalid ERC1271 registration signature"));
            }
        }
        if chain.block(head.number)? != *head {
            return Err(Error::Invalid("registry canonical block changed"));
        }
        Ok(())
    }
    pub fn restore<C: CanonicalHead>(
        chain: &C,
        deployment: &ProtocolDeployment,
        snapshot: &str,
    ) -> Result<Self> {
        let operation: Self = serde_json::from_str(snapshot)
            .map_err(|_| Error::Invalid("invalid registration snapshot"))?;
        if &operation.deployment != deployment {
            return Err(Error::Invalid("registration snapshot deployment mismatch"));
        }
        let head = chain.head()?;
        Self::validate_deployment(chain, deployment, &head)?;
        if let Some(signature) = &operation.signature {
            if !signature.is_empty() {
                operation.verify_signature(chain, signature, &head)?;
            }
        }
        if chain.block(head.number)? != head {
            return Err(Error::Invalid("registry canonical block changed"));
        }
        Ok(operation)
    }
    fn encoded(&self) -> Result<TransactionCall> {
        let signature = self
            .signature
            .clone()
            .ok_or(Error::Invalid("registration signature missing"))?;
        let registration = IAddressRegistry::Registration {
            walletIdentity: self.owner.into_word(),
            keys: IAddressRegistry::ReceivingKeys {
                viewingPublicKey: self.keys.viewing_public_key.to_vec().into(),
                clueKey: self.keys.clue_key.into(),
            },
            nonce: self.nonce,
            deadline: self.deadline,
        };
        let data = if self.update {
            InvisiAddressRegistry::updateKeysCall {
                registration,
                signature: signature.into(),
            }
            .abi_encode()
        } else {
            InvisiAddressRegistry::registerKeysCall {
                registration,
                signature: signature.into(),
            }
            .abi_encode()
        };
        Ok(TransactionCall {
            to: self.registry_address(),
            data,
            value: U256::ZERO,
        })
    }
    pub fn export_transaction<C: CanonicalHead>(&self, chain: &C) -> Result<TransactionCall> {
        if !matches!(
            self.status,
            RegistrationStatus::Ready | RegistrationStatus::Uncertain
        ) {
            return Err(Error::Invalid("registration is not ready"));
        }
        let head = self.fresh(chain)?;
        if let Some(signature) = &self.signature {
            if !signature.is_empty() {
                self.verify_signature(chain, signature, &head)?;
            }
        }
        self.encoded()
    }
    pub fn track(mut self, hash: B256) -> Result<Self> {
        if hash == B256::ZERO
            || !matches!(
                self.status,
                RegistrationStatus::Ready | RegistrationStatus::Uncertain
            )
        {
            return Err(Error::Invalid("registration is not ready"));
        }
        if self
            .transaction_hash
            .is_some_and(|previous| previous != hash)
        {
            return Err(Error::Invalid("registration transaction already tracked"));
        }
        self.transaction_hash = Some(hash);
        self.status = RegistrationStatus::Uncertain;
        Ok(self)
    }
    pub fn reconcile<C: RegistrationReader>(mut self, chain: &C) -> Result<Self> {
        if self.signature.is_none() || self.transaction_hash.is_none() {
            return Err(Error::Invalid("registration transaction not tracked"));
        }
        let head = chain.head()?;
        Self::validate_deployment(chain, &self.deployment, &head)?;
        if self.anchor.as_ref().is_some_and(|a| {
            chain
                .block(a.number)
                .map(|b| b.hash != a.hash)
                .unwrap_or(true)
        }) {
            self.status = RegistrationStatus::Reorged;
            return Ok(self);
        }
        if let Some(hash) = self.transaction_hash {
            if let Some(receipt) = chain.receipt(hash)? {
                if receipt.transaction_hash != hash
                    || chain.block(receipt.block.number)? != receipt.block
                {
                    return Err(Error::Invalid("registry receipt not canonical"));
                }
                let transaction = chain
                    .transaction(hash)?
                    .ok_or(Error::Invalid("registry transaction missing"))?;
                let call = self.encoded()?;
                if transaction.hash != hash
                    || transaction.to != Some(call.to)
                    || transaction.input != call.data
                    || transaction.value != U256::ZERO
                    || transaction.chain_id != self.deployment.chain_id()?
                    || transaction.block.as_ref() != Some(&receipt.block)
                    || (self.signature.as_ref().is_some_and(Vec::is_empty)
                        && chain.registration_sender(hash)? != Some(self.owner))
                {
                    return Err(Error::Invalid(
                        "registry transaction differs from frozen request",
                    ));
                }
                if !receipt.success {
                    self.status = RegistrationStatus::Failed;
                    return Ok(self);
                }
                let matched = receipt
                    .logs
                    .iter()
                    .filter(|l| l.address == self.registry_address())
                    .any(|log| {
                        InvisiAddressRegistry::ReceivingKeysSet::decode_raw_log_validate(
                            log.topics.iter().copied(),
                            &log.data,
                        )
                        .ok()
                        .is_some_and(|e| {
                            e.walletIdentity == self.owner.into_word()
                                && e.viewingPublicKey.as_ref() == self.keys.viewing_public_key
                                && e.clueKey.as_slice() == self.keys.clue_key
                                && e.nextNonce == self.nonce + 1
                        })
                    });
                if !matched {
                    return Err(Error::Invalid(
                        "registry receipt missing matching key update",
                    ));
                }
                if chain.block(receipt.block.number)? != receipt.block {
                    return Err(Error::Invalid("registry canonical block changed"));
                }
                self.status = RegistrationStatus::Confirmed;
                self.anchor = Some(receipt.block);
                return Ok(self);
            }
        }
        let raw = chain.call(
            self.registry_address(),
            &InvisiAddressRegistry::receivingKeysOfCall {
                walletIdentity: self.owner.into_word(),
            }
            .abi_encode(),
            head.number,
        )?;
        let nonce = InvisiAddressRegistry::receivingKeysOfCall::abi_decode_returns_validate(&raw)
            .map_err(|_| Error::Invalid("invalid receiving registry response"))?
            .nonce;
        if chain.block(head.number)? != head {
            return Err(Error::Invalid("registry canonical block changed"));
        }
        self.status = if head.timestamp > self.deadline {
            RegistrationStatus::Expired
        } else if nonce != self.nonce {
            RegistrationStatus::Failed
        } else {
            RegistrationStatus::Uncertain
        };
        Ok(self)
    }
    pub fn preview(&self) -> Result<Value> {
        Ok(
            json!({"status":self.status,"chainId":self.deployment.chain_id()?.to_string(),"registryAddress":self.registry_address(),"ownerAddress":self.owner,"keys":self.keys,"nonce":self.nonce.to_string(),"deadline":self.deadline.to_string(),"update":self.update}),
        )
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationIntent {
    pub owner: Address,
    pub keys: ReceivingKeys,
    pub nonce: u64,
    pub deadline: u64,
    pub update: bool,
    pub signature: Vec<u8>,
}
pub fn decode_registration_call(data: &[u8]) -> Result<RegistrationIntent> {
    let (registration, signature, update, encoded) =
        if data.starts_with(&InvisiAddressRegistry::registerKeysCall::SELECTOR) {
            let call = InvisiAddressRegistry::registerKeysCall::abi_decode_validate(data)
                .map_err(|_| Error::Invalid("invalid registration calldata"))?;
            let encoded = call.abi_encode();
            (call.registration, call.signature, false, encoded)
        } else {
            let call = InvisiAddressRegistry::updateKeysCall::abi_decode_validate(data)
                .map_err(|_| Error::Invalid("invalid registration calldata"))?;
            let encoded = call.abi_encode();
            (call.registration, call.signature, true, encoded)
        };
    if encoded != data
        || registration.walletIdentity[..12].iter().any(|v| *v != 0)
        || registration.nonce == u64::MAX
        || update != (registration.nonce > 0)
    {
        return Err(Error::Invalid("invalid registration intent"));
    }
    let owner = Address::from_slice(&registration.walletIdentity[12..]);
    let keys = ReceivingKeys {
        viewing_public_key: registration
            .keys
            .viewingPublicKey
            .as_ref()
            .try_into()
            .map_err(|_| Error::Invalid("invalid viewing key"))?,
        clue_key: registration.keys.clueKey.into(),
    };
    ReceivingAddress::from_keys(U256::from_be_slice(owner.as_slice()), keys.clone())
        .map_err(|_| Error::Invalid("invalid registration keys"))?;
    Ok(RegistrationIntent {
        owner,
        keys,
        nonce: registration.nonce,
        deadline: registration.deadline,
        update,
        signature: signature.to_vec(),
    })
}
impl RegistrationOperation {
    pub fn recover<C: RegistrationReader>(
        chain: &C,
        deployment: ProtocolDeployment,
        hash: B256,
    ) -> Result<Self> {
        deployment.validate()?;
        let registry = deployment
            .registry
            .as_ref()
            .ok_or(Error::Invalid("receiving registry deployment required"))?;
        let transaction = chain
            .transaction(hash)?
            .ok_or(Error::Invalid("registration transaction missing"))?;
        if transaction.hash != hash
            || transaction.to != Some(registry.address)
            || transaction.value != U256::ZERO
            || transaction.chain_id != deployment.chain_id()?
        {
            return Err(Error::Invalid("registration transaction scope mismatch"));
        }
        let intent = decode_registration_call(&transaction.input)?;
        if intent.signature.is_empty() && chain.registration_sender(hash)? != Some(intent.owner) {
            return Err(Error::Invalid("registration direct caller mismatch"));
        }
        let operation = Self {
            deployment: deployment.clone(),
            owner: intent.owner,
            keys: intent.keys,
            nonce: intent.nonce,
            deadline: intent.deadline,
            update: intent.update,
            status: RegistrationStatus::Uncertain,
            signature: Some(intent.signature),
            transaction_hash: Some(hash),
            anchor: None,
        };
        Self::restore(
            chain,
            &deployment,
            &serde_json::to_string(&operation)
                .map_err(|_| Error::Invalid("invalid registration snapshot"))?,
        )
    }
}

pub fn decode_registration_error(data: &[u8]) -> Option<&'static str> {
    use alloy_sol_types::SolInterface;
    use InvisiAddressRegistry::InvisiAddressRegistryErrors as Errors;
    Some(match Errors::abi_decode_validate(data).ok()? {
        Errors::AlreadyRegistered(_) => "AlreadyRegistered",
        Errors::ChainIdMismatch(_) => "ChainIdMismatch",
        Errors::InvalidNonce(_) => "InvalidNonce",
        Errors::InvalidReceivingKeys(_) => "InvalidReceivingKeys",
        Errors::InvalidRegistrationSignature(_) => "InvalidRegistrationSignature",
        Errors::InvalidShortString(_) => "InvalidShortString",
        Errors::InvalidWalletIdentity(_) => "InvalidWalletIdentity",
        Errors::NonceExhausted(_) => "NonceExhausted",
        Errors::NotRegistered(_) => "NotRegistered",
        Errors::ReentrancyGuardReentrantCall(_) => "ReentrancyGuardReentrantCall",
        Errors::RegistrationExpired(_) => "RegistrationExpired",
        Errors::StringTooLong(_) => "StringTooLong",
    })
}
