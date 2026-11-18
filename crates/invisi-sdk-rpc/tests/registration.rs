use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use invisi_sdk_rpc::{
    address::{ReceivingAddress, ReceivingKeys},
    protocol::{IAddressRegistry, InvisiAddressRegistry},
    registration::{RegistrationOperation, RegistrationReader, RegistrationStatus},
    rpc::{
        CanonicalBlock, CanonicalChain, CanonicalHead, CanonicalLog, CanonicalReceipt,
        CanonicalTransaction, ChainReceipts, ChainTransactions, ContractDeployment, Error,
        ProtocolDeployment, Result,
    },
};
use k256::ecdsa::SigningKey;
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};
struct Chain {
    deployment: ProtocolDeployment,
    head: Mutex<CanonicalBlock>,
    nonce: AtomicU64,
    reorg: AtomicBool,
    receipt: Mutex<Option<CanonicalReceipt>>,
    transaction: Mutex<Option<CanonicalTransaction>>,
    sender: Mutex<Address>,
    contract: AtomicBool,
}
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(97)
    }
    fn block(&self, _: u64) -> Result<CanonicalBlock> {
        let mut head = self.head.lock().unwrap().clone();
        if self.reorg.load(Ordering::SeqCst) {
            head.hash = B256::repeat_byte(9)
        }
        Ok(head)
    }
    fn code_at(&self, address: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(
            if address == self.deployment.registry.as_ref().unwrap().address
                || self.contract.load(Ordering::SeqCst)
            {
                vec![0x60]
            } else {
                vec![]
            },
        )
    }
    fn call(&self, _: Address, data: &[u8], _: u64) -> Result<Vec<u8>> {
        if data.starts_with(&[0x16, 0x26, 0xba, 0x7e]) && self.contract.load(Ordering::SeqCst) {
            let mut bytes = vec![0; 32];
            bytes[..4].copy_from_slice(&[0x16, 0x26, 0xba, 0x7e]);
            return Ok(bytes);
        }
        if data[..4] != InvisiAddressRegistry::receivingKeysOfCall::SELECTOR {
            return Err(Error::Invalid("unexpected call"));
        }
        Ok(
            InvisiAddressRegistry::receivingKeysOfCall::abi_encode_returns(
                &InvisiAddressRegistry::receivingKeysOfReturn {
                    keys: IAddressRegistry::ReceivingKeys {
                        viewingPublicKey: Vec::new().into(),
                        clueKey: B256::ZERO,
                    },
                    nonce: self.nonce.load(Ordering::SeqCst),
                },
            ),
        )
    }
}
impl CanonicalHead for Chain {
    fn head(&self) -> Result<CanonicalBlock> {
        Ok(self.head.lock().unwrap().clone())
    }
}
impl ChainReceipts for Chain {
    fn receipt(&self, _: B256) -> Result<Option<CanonicalReceipt>> {
        Ok(self.receipt.lock().unwrap().clone())
    }
}
impl ChainTransactions for Chain {
    fn transaction(&self, _: B256) -> Result<Option<CanonicalTransaction>> {
        Ok(self.transaction.lock().unwrap().clone())
    }
}
impl RegistrationReader for Chain {
    fn registration_sender(&self, _: B256) -> Result<Option<Address>> {
        Ok(Some(*self.sender.lock().unwrap()))
    }
}
fn fixture() -> (Chain, String, SigningKey, ReceivingKeys) {
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
    let material=invisi_sdk_rpc::wallet::execute(&[1u8;32],&json!({"version":1,"id":"public","ownerAddress":owner,"method":"wallet.public","params":{}})).unwrap();
    let keys:ReceivingKeys=serde_json::from_value(json!({"viewingPublicKey":material["result"]["viewingPublicKey"],"clueKey":material["result"]["clueKey"]})).unwrap();
    let receiving =
        ReceivingAddress::from_keys(U256::from_be_slice(owner.as_slice()), keys.clone())
            .unwrap()
            .encode()
            .unwrap();
    let registry = ContractDeployment {
        address: Address::repeat_byte(2),
        runtime_code_hash: keccak256([0x60]),
        from_block: 1,
    };
    let deployment = ProtocolDeployment {
        chain_id: "97".into(),
        protocol: ContractDeployment {
            address: Address::repeat_byte(3),
            ..registry.clone()
        },
        registry: Some(registry),
        broadcaster_registry: None,
    };
    let chain = Chain {
        deployment,
        head: Mutex::new(CanonicalBlock {
            number: 10,
            hash: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(8),
            timestamp: 1000,
        }),
        nonce: AtomicU64::new(0),
        reorg: AtomicBool::new(false),
        receipt: Mutex::new(None),
        transaction: Mutex::new(None),
        sender: Mutex::new(owner),
        contract: AtomicBool::new(false),
    };
    (chain, receiving, key, keys)
}
fn prepare(c: &Chain, a: &str) -> RegistrationOperation {
    RegistrationOperation::prepare(c, c.deployment.clone(), a, false, None).unwrap()
}
#[test]
fn direct_registration_binds_chain_owner_keys_nonce_and_deadline() {
    let (c, a, _, _) = fixture();
    let op = prepare(&c, &a);
    assert_eq!(op.status(), RegistrationStatus::Prepared);
    assert_eq!(op.deadline(), 1300);
    assert!(op.export_transaction(&c).is_err());
    assert!(op
        .clone()
        .authorize_direct(&c, Address::repeat_byte(8))
        .is_err());
    let op = op.authorize_direct(&c, *c.sender.lock().unwrap()).unwrap();
    let call = op.export_transaction(&c).unwrap();
    let decoded = InvisiAddressRegistry::registerKeysCall::abi_decode_validate(&call.data).unwrap();
    assert_eq!(call.to, c.deployment.registry.as_ref().unwrap().address);
    assert_eq!(decoded.registration.walletIdentity, op.owner().into_word());
    assert_eq!(decoded.registration.nonce, 0);
    assert_eq!(decoded.registration.deadline, 1300);
    assert!(decoded.signature.is_empty());
}
#[test]
fn rejects_expiry_nonce_exhaustion_and_wrong_registration_mode() {
    let (c, a, _, _) = fixture();
    assert!(RegistrationOperation::prepare(&c, c.deployment.clone(), &a, true, None).is_err());
    assert!(
        RegistrationOperation::prepare(&c, c.deployment.clone(), &a, false, Some(999)).is_err()
    );
    for nonce in [1, u64::MAX] {
        c.nonce.store(nonce, Ordering::SeqCst);
        assert!(RegistrationOperation::prepare(&c, c.deployment.clone(), &a, false, None).is_err());
    }
    c.nonce.store(1, Ordering::SeqCst);
    let op = RegistrationOperation::prepare(&c, c.deployment.clone(), &a, true, None)
        .unwrap()
        .authorize_direct(&c, *c.sender.lock().unwrap())
        .unwrap();
    assert!(InvisiAddressRegistry::updateKeysCall::abi_decode_validate(
        &op.export_transaction(&c).unwrap().data
    )
    .is_ok());
}
#[test]
fn export_revalidates_nonce_deadline_and_deployment() {
    let (mut c, a, _, _) = fixture();
    let op = prepare(&c, &a)
        .authorize_direct(&c, *c.sender.lock().unwrap())
        .unwrap();
    c.nonce.store(1, Ordering::SeqCst);
    assert!(op.export_transaction(&c).is_err());
    c.nonce.store(0, Ordering::SeqCst);
    c.head.lock().unwrap().timestamp = 1301;
    assert!(op.export_transaction(&c).is_err());
    c.head.lock().unwrap().timestamp = 1000;
    c.deployment.registry.as_mut().unwrap().runtime_code_hash = B256::repeat_byte(9);
    assert!(RegistrationOperation::prepare(&c, c.deployment.clone(), &a, false, None).is_err());
}
#[test]
fn detached_signature_is_checked_and_tampered_snapshots_are_rejected() {
    let (c, a, key, _) = fixture();
    let op = prepare(&c, &a);
    let authorization = op.authorization(&c).unwrap();
    assert!(authorization["types"]["RegisterReceivingKeys"].is_array());
    let (sig, recovery) = key
        .sign_prehash_recoverable(op.digest().unwrap().as_slice())
        .unwrap();
    let mut signature = sig.to_bytes().to_vec();
    signature.push(27 + recovery.to_byte());
    let ready = op.clone().with_signature(&c, signature.clone()).unwrap();
    assert!(ready.export_transaction(&c).is_ok());
    signature[0] ^= 1;
    assert!(op.with_signature(&c, signature).is_err());
    let snapshot = serde_json::to_string(&ready).unwrap();
    assert!(RegistrationOperation::restore(&c, &c.deployment, &snapshot).is_ok());
    let mut tampered: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    tampered["nonce"] = json!(u64::MAX);
    assert!(RegistrationOperation::restore(&c, &c.deployment, &tampered.to_string()).is_err());
    tampered["nonce"] = json!(0);
    tampered["owner"] = json!(Address::repeat_byte(7));
    assert!(RegistrationOperation::restore(&c, &c.deployment, &tampered.to_string()).is_err());
}
fn confirmed_fixture() -> (Chain, RegistrationOperation) {
    let (c, a, _, keys) = fixture();
    let owner = *c.sender.lock().unwrap();
    let op = prepare(&c, &a).authorize_direct(&c, owner).unwrap();
    let call = op.export_transaction(&c).unwrap();
    let hash = B256::repeat_byte(4);
    let block = c.head.lock().unwrap().clone();
    let event = InvisiAddressRegistry::ReceivingKeysSet {
        walletIdentity: owner.into_word(),
        viewingPublicKey: keys.viewing_public_key.to_vec().into(),
        clueKey: keys.clue_key.into(),
        nextNonce: 1,
    }
    .encode_log_data();
    *c.receipt.lock().unwrap() = Some(CanonicalReceipt {
        transaction_hash: hash,
        block: block.clone(),
        success: true,
        logs: vec![CanonicalLog {
            address: call.to,
            topics: event.topics().to_vec(),
            data: event.data.to_vec(),
            log_index: 0,
        }],
    });
    *c.transaction.lock().unwrap() = Some(CanonicalTransaction {
        hash,
        to: Some(call.to),
        input: call.data,
        value: U256::ZERO,
        chain_id: 97,
        block: Some(block),
    });
    c.nonce.store(1, Ordering::SeqCst);
    (c, op.track(hash).unwrap())
}
#[test]
fn confirms_only_exact_canonical_transaction_and_matching_key_event() {
    let (c, op) = confirmed_fixture();
    let confirmed = op.reconcile(&c).unwrap();
    assert_eq!(confirmed.status(), RegistrationStatus::Confirmed);
    c.reorg.store(true, Ordering::SeqCst);
    assert_eq!(
        confirmed.reconcile(&c).unwrap().status(),
        RegistrationStatus::Reorged
    );
}
#[test]
fn rejects_transaction_event_and_sender_mismatch() {
    for case in 0..4 {
        let (c, op) = confirmed_fixture();
        match case {
            0 => c
                .transaction
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .input
                .push(0),
            1 => c.receipt.lock().unwrap().as_mut().unwrap().logs.clear(),
            2 => *c.sender.lock().unwrap() = Address::repeat_byte(7),
            _ => c.receipt.lock().unwrap().as_mut().unwrap().block.hash = B256::repeat_byte(8),
        }
        assert!(op.reconcile(&c).is_err());
    }
}
#[test]
fn pending_expired_consumed_and_reverted_states_are_explicit() {
    let (c, a, _, _) = fixture();
    let op = prepare(&c, &a)
        .authorize_direct(&c, *c.sender.lock().unwrap())
        .unwrap()
        .track(B256::repeat_byte(4))
        .unwrap();
    assert_eq!(
        op.clone().reconcile(&c).unwrap().status(),
        RegistrationStatus::Uncertain
    );
    c.head.lock().unwrap().timestamp = 1301;
    assert_eq!(
        op.clone().reconcile(&c).unwrap().status(),
        RegistrationStatus::Expired
    );
    c.head.lock().unwrap().timestamp = 1000;
    c.nonce.store(1, Ordering::SeqCst);
    assert_eq!(
        op.reconcile(&c).unwrap().status(),
        RegistrationStatus::Failed
    );
    let (c, op) = confirmed_fixture();
    c.receipt.lock().unwrap().as_mut().unwrap().success = false;
    assert_eq!(
        op.reconcile(&c).unwrap().status(),
        RegistrationStatus::Failed
    );
}
#[test]
fn preparation_rejects_reorg_and_missing_registry() {
    let (c, a, _, _) = fixture();
    c.reorg.store(true, Ordering::SeqCst);
    assert!(RegistrationOperation::prepare(&c, c.deployment.clone(), &a, false, None).is_err());
    let mut deployment = c.deployment.clone();
    deployment.registry = None;
    assert!(RegistrationOperation::prepare(&c, deployment, &a, false, None).is_err());
}

#[test]
fn recovery_reuses_frozen_transaction_and_rejects_different_deployment() {
    let (c, op) = confirmed_fixture();
    let hash = c.transaction.lock().unwrap().as_ref().unwrap().hash;
    let recovered = RegistrationOperation::recover(&c, c.deployment.clone(), hash).unwrap();
    assert_eq!(recovered.owner(), op.owner());
    assert_eq!(
        recovered.reconcile(&c).unwrap().status(),
        RegistrationStatus::Confirmed
    );
    let mut changed = c.deployment.clone();
    changed.registry.as_mut().unwrap().address = Address::repeat_byte(7);
    assert!(RegistrationOperation::recover(&c, changed, hash).is_err());
}
#[test]
fn calldata_decoder_rejects_trailing_bytes_and_unrelated_calls() {
    let (c, a, _, _) = fixture();
    let op = prepare(&c, &a)
        .authorize_direct(&c, *c.sender.lock().unwrap())
        .unwrap();
    let call = op.export_transaction(&c).unwrap();
    let intent = invisi_sdk_rpc::registration::decode_registration_call(&call.data).unwrap();
    assert_eq!(intent.owner, op.owner());
    assert_eq!(intent.deadline, op.deadline());
    let mut altered = call.data;
    altered.push(0);
    assert!(invisi_sdk_rpc::registration::decode_registration_call(&altered).is_err());
    assert!(invisi_sdk_rpc::registration::decode_registration_call(&[0, 1, 2, 3]).is_err());
}

#[test]
fn contract_registration_signatures_require_erc1271_acceptance() {
    let (c, a, _, _) = fixture();
    let op = prepare(&c, &a);
    assert!(op.clone().with_signature(&c, vec![1; 64]).is_err());
    c.contract.store(true, Ordering::SeqCst);
    let ready = op.with_signature(&c, vec![1; 64]).unwrap();
    assert!(ready.export_transaction(&c).is_ok());
    c.contract.store(false, Ordering::SeqCst);
    assert!(ready.export_transaction(&c).is_err());
}
