use alloy_primitives::{keccak256, Address, B256, U256};
use invisi_sdk::{
    rpc::*,
    sdk::{ChainState, RpcChainState},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Reader {
    clock_mode: AtomicUsize,
    clock_reads: AtomicUsize,
    head_reads: AtomicUsize,
    headers: AtomicUsize,
    calls: AtomicUsize,
    reorg_on_allowance: AtomicBool,
    reorg: AtomicBool,
}
fn anchor() -> CanonicalBlock {
    CanonicalBlock {
        number: 10,
        timestamp: 100,
        hash: B256::repeat_byte(10),
        parent_hash: B256::repeat_byte(9),
    }
}
impl CanonicalChain for Reader {
    fn block_by_tag(&self, tag: FinalityTag) -> Result<Option<CanonicalBlock>> {
        assert_eq!(tag, FinalityTag::Latest);
        self.clock_reads.fetch_add(1, Ordering::SeqCst);
        match self.clock_mode.load(Ordering::SeqCst) {
            0 => Ok(Some(anchor())),
            1 => Err(Error::FinalityUnsupported),
            2 => Err(Error::Invalid("bad clock header")),
            _ => Ok(None),
        }
    }
    fn chain_id(&self) -> Result<u64> {
        Ok(31337)
    }
    fn block(&self, _: u64) -> Result<CanonicalBlock> {
        self.headers.fetch_add(1, Ordering::SeqCst);
        let mut block = anchor();
        if self.reorg.load(Ordering::SeqCst) {
            block.hash = B256::ZERO;
        }
        Ok(block)
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        panic!("EOA verification must not read code")
    }
    fn call(&self, _: Address, _: &[u8], block: u64) -> Result<Vec<u8>> {
        assert_eq!(block, anchor().number);
        let count = self.calls.fetch_add(1, Ordering::SeqCst);
        if count == 1 && self.reorg_on_allowance.load(Ordering::SeqCst) {
            self.reorg.store(true, Ordering::SeqCst);
        }
        Ok(U256::from(100).to_be_bytes::<32>().to_vec())
    }
}
impl CanonicalHead for Reader {
    fn head(&self) -> Result<CanonicalBlock> {
        self.head_reads.fetch_add(1, Ordering::SeqCst);
        Ok(anchor())
    }
}
fn reader() -> RpcChainState<Reader> {
    RpcChainState {
        chain: Reader {
            clock_mode: 0.into(),
            clock_reads: 0.into(),
            head_reads: 0.into(),
            headers: 0.into(),
            calls: 0.into(),
            reorg_on_allowance: false.into(),
            reorg: false.into(),
        },
        deployment: ProtocolDeployment {
            chain_id: "31337".into(),
            protocol: ContractDeployment {
                address: Address::repeat_byte(1),
                runtime_code_hash: keccak256([1]),
                from_block: 1,
            },
            registry: None,
            broadcaster_registry: None,
        },
    }
}
#[test]
fn funding_pair_shares_one_return_fence_and_rejects_mid_read_reorg() {
    let state = reader();
    assert_eq!(
        state
            .token_balance_allowance(Address::repeat_byte(2), Address::repeat_byte(3), &anchor())
            .unwrap(),
        (U256::from(100), U256::from(100))
    );
    assert_eq!(state.chain.calls.load(Ordering::SeqCst), 2);
    assert_eq!(state.chain.headers.load(Ordering::SeqCst), 1);
    state.chain.calls.store(0, Ordering::SeqCst);
    state.chain.reorg_on_allowance.store(true, Ordering::SeqCst);
    assert!(state
        .token_balance_allowance(Address::repeat_byte(2), Address::repeat_byte(3), &anchor())
        .unwrap_err()
        .contains("reorganization"));
}
#[test]
fn eoa_signature_is_checked_locally_without_chain_queries() {
    let state = reader();
    let signing = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
    let public = signing.verifying_key().to_encoded_point(false);
    let hash = keccak256(&public.as_bytes()[1..]);
    let owner = Address::from_slice(&hash[12..]);
    let digest = keccak256(b"submission-local-signature");
    let (sig, recovery) = signing.sign_prehash_recoverable(digest.as_slice()).unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    assert!(state
        .public_signature_valid(owner, digest, &bytes, &anchor())
        .unwrap());
    assert_eq!(state.chain.headers.load(Ordering::SeqCst), 0);
}

#[test]
fn quote_clock_reads_only_latest_metadata_and_falls_back_only_when_unsupported() {
    let state = reader();
    assert_eq!(state.submission_timestamp().unwrap(), 100);
    assert_eq!(state.chain.clock_reads.load(Ordering::SeqCst), 1);
    assert_eq!(state.chain.head_reads.load(Ordering::SeqCst), 0);
    assert_eq!(state.chain.headers.load(Ordering::SeqCst), 0);
    assert_eq!(state.chain.calls.load(Ordering::SeqCst), 0);
    state.chain.clock_mode.store(1, Ordering::SeqCst);
    assert_eq!(state.submission_timestamp().unwrap(), 100);
    assert_eq!(state.chain.head_reads.load(Ordering::SeqCst), 1);
    state.chain.clock_mode.store(2, Ordering::SeqCst);
    assert!(state
        .submission_timestamp()
        .unwrap_err()
        .contains("bad clock header"));
    state.chain.clock_mode.store(3, Ordering::SeqCst);
    assert!(state.submission_timestamp().is_err());
    assert_eq!(state.chain.head_reads.load(Ordering::SeqCst), 1);
}

#[test]
fn custom_reader_has_no_implicit_fresh_nonce_or_execution_delegation() {
    let state = reader();
    // An arbitrary CanonicalHead can change endpoints or implement extra policy.
    // A source-compatible new capability must stay opt-in for those readers.
    assert!(state.fresh_funding_nonce(Address::repeat_byte(2)).is_none());
    assert!(state.self_contained_shield_capability().is_none());
    assert_eq!(state.chain.calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.chain.head_reads.load(Ordering::SeqCst), 0);
}
