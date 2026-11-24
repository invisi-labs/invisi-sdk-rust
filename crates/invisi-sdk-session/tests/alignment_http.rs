//! Opt-in read-only timing diagnostic and isolated fake-relay recovery regression.
//! Baseline driver: cargo rustc --test alignment_http -- --cfg invisi_alignment_before.
#![allow(unexpected_cfgs)]
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolCall;
use invisi_sdk_session::sdk::NoteOutput;
use invisi_sdk_session::{broadcaster, rpc::*, sdk::*, session::*};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct Trace {
    phase: Arc<Mutex<(usize, String)>>,
    rows: Arc<Mutex<Vec<Value>>>,
    hashes: Value,
}
struct Server {
    endpoint: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}
fn source_hashes() -> Value {
    #[allow(unused_mut)]
    let mut hashes = json!({
        "src/sdk.rs":hex::encode(Sha256::digest(include_bytes!("../../../src/sdk.rs"))),
        "src/sdk/prepared_broadcaster.rs":hex::encode(Sha256::digest(include_bytes!("../../../src/sdk/prepared_broadcaster.rs"))),
        "src/sdk/preparation.rs":hex::encode(Sha256::digest(include_bytes!("../../../src/sdk/preparation.rs"))),
        "src/sdk/journal.rs":hex::encode(Sha256::digest(include_bytes!("../../../src/sdk/journal.rs"))),
        "rpc/client.rs":hex::encode(Sha256::digest(include_bytes!("../../invisi-sdk-rpc/src/rpc/client.rs"))),
        "rpc/trusted_provider.rs":hex::encode(Sha256::digest(include_bytes!("../../invisi-sdk-rpc/src/rpc/trusted_provider.rs"))),
        "session/operation.rs":hex::encode(Sha256::digest(include_bytes!("../src/session/operation.rs"))),
        "driver":hex::encode(Sha256::digest(include_bytes!("alignment_http.rs")))
    });
    #[cfg(not(invisi_alignment_before))]
    {
        hashes["src/sdk/initialized.rs"] = json!(hex::encode(Sha256::digest(include_bytes!(
            "../../../src/sdk/initialized.rs"
        ))));
        hashes["src/sdk/initialized_broadcasters.rs"] = json!(hex::encode(Sha256::digest(
            include_bytes!("../../../src/sdk/initialized_broadcasters.rs")
        )));
    }
    hashes
}

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}
fn owner(seed: u8) -> Address {
    let key = signing(seed);
    let public = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..])
}
fn signature(seed: u8, digest: B256) -> Vec<u8> {
    let (sig, recovery) = signing(seed)
        .sign_prehash_recoverable(digest.as_slice())
        .unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    bytes
}
fn header(now: u64) -> Value {
    json!({"number":"0xa","timestamp":format!("0x{now:x}"),"hash":B256::repeat_byte(10),"parentHash":B256::repeat_byte(9)})
}
fn fixture_result(request: &Value, now: u64) -> Value {
    let protocol = Address::repeat_byte(1);
    let recipient = Address::repeat_byte(4);
    match request["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x7a69"),
        "eth_blockNumber" => json!("0xa"),
        "eth_getBlockByNumber" => header(now),
        "eth_getCode" => json!("0x01"),
        "eth_call" => {
            let data = request["params"][0]["data"].as_str().unwrap();
            let nonce = format!(
                "0x{}",
                hex::encode(&keccak256("nonces(address)").as_slice()[..4])
            );
            let value = if data.starts_with(&nonce) {
                let bytes = hex::decode(data.trim_start_matches("0x")).unwrap();
                let payer = Address::from_slice(&bytes[16..36]);
                if payer == owner(1) {
                    U256::from(7)
                } else if payer == owner(2) {
                    U256::from(14)
                } else {
                    panic!("unexpected synthetic nonce payer")
                }
            } else {
                U256::from(1_000_000)
            };
            json!(format!("0x{}", hex::encode(value.to_be_bytes::<32>())))
        }
        "broadcaster_getTokenSupport" | "broadcaster_getStatus" => {
            json!({"apiVersion":"v1","protocolVersion":"1","chainId":"31337","protocol":protocol,"sender":owner(17),"feeRecipient":recipient,"submissionHalted":false,"provenance":{"enabled":false},"tokenAddress":request["params"][0]["tokenAddress"],"supported":true})
        }
        "broadcaster_estimateQuote" => {
            json!({"feeRecipient":recipient,"feeAmount":"5","maxGas":"1000000"})
        }
        "broadcaster_getQuote" => {
            let data = hex::decode(
                request["params"][0]["data"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap();
            let intent = broadcaster::decode_intent(&data).unwrap();
            let quote = broadcaster::Quote {
                schedule: None,
                execution: broadcaster::Execution::Direct,
                token: intent.token,
                fee_recipient: intent.fee_recipient,
                fee_amount: intent.fee_amount.to_string(),
                deadline: intent.deadline.to_string(),
                max_gas: "1000000".into(),
                request_hash: broadcaster::request_hash(&data).unwrap(),
            };
            let trust = broadcaster::Trust {
                chain_id: 31337,
                protocol,
                signer: owner(17),
            };
            let digest = broadcaster::quote_digest(&quote, &trust).unwrap();
            json!(broadcaster::SignedQuote {
                quote,
                signature: format!("0x{}", hex::encode(signature(17, digest))),
                request_hash_format: None,
                provenance_required: None
            })
        }
        other => panic!("unexpected HTTP method {other}"),
    }
}
#[derive(Default)]
struct RecoveryRelay {
    submissions: Mutex<Vec<Value>>,
    status_reads: AtomicUsize,
    refusal: Mutex<Option<Value>>,
    before_submit: Mutex<Option<Box<dyn Fn(&Value) + Send>>>,
}
impl Server {
    fn start(trace: Trace, fixture: usize, now: u64, delay: u64, variant: String) -> Self {
        Self::start_with_recovery(trace, fixture, now, delay, variant, None)
    }
    fn start_with_recovery(
        trace: Trace,
        fixture: usize,
        now: u64,
        delay: u64,
        variant: String,
        recovery: Option<Arc<RecoveryRelay>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let join = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut temp = [0; 4096];
                let split = loop {
                    let n = stream.read(&mut temp).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&temp[..n]);
                    if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let text = String::from_utf8_lossy(&bytes[..split]);
                let length: usize = text
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                while bytes.len() < split + length {
                    let n = stream.read(&mut temp).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&temp[..n]);
                }
                let request: Value = serde_json::from_slice(&bytes[split..split + length]).unwrap();
                let start = Instant::now();
                let phase = trace.phase.lock().unwrap().clone();
                let method = request["method"].as_str().unwrap();
                let response = if method == "broadcaster_submitTransaction" {
                    let relay = recovery
                        .as_ref()
                        .expect("write reached normal read-only HTTP fixture");
                    relay
                        .submissions
                        .lock()
                        .unwrap()
                        .push(request["params"].clone());
                    if let Some(check) = relay.before_submit.lock().unwrap().take() {
                        check(&request["params"][0]);
                    }
                    if let Some(error) = relay.refusal.lock().unwrap().take() {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":error})
                    } else {
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"id":"fixture-accepted","state":"pending"}})
                    }
                } else if method == "broadcaster_getTransactionStatus" {
                    let relay = recovery
                        .as_ref()
                        .expect("status recovery requires dedicated fake relay");
                    relay.status_reads.fetch_add(1, Ordering::SeqCst);
                    json!({"jsonrpc":"2.0","id":request["id"],"result":{"id":"fixture-accepted","state":"pending"}})
                } else {
                    assert!(
                        !method.contains("submit") && !method.contains("send"),
                        "unsupported write reached HTTP"
                    );
                    json!({"jsonrpc":"2.0","id":request["id"],"result":fixture_result(&request,now)})
                };
                thread::sleep(Duration::from_millis(delay));
                let body = response.to_string();
                trace.rows.lock().unwrap().push(json!({"variant":variant,"language":"rust","fixture":fixture,"transactionIndex":phase.0,"phase":phase.1,"method":method,"service":if method.starts_with("eth_"){"chain"}else{"broadcaster"},"elapsedMs":start.elapsed().as_secs_f64()*1000.0,"ok":true,"actualHttpAttempts":1,"initializationCharged":phase.0==0,"deniedWrites":0,"sourceHashes":trace.hashes}));
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                stream.flush().unwrap();
            }
        });
        Self {
            endpoint,
            stop,
            join: Some(join),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
struct DenyWrites {
    transport: HttpTransport,
    denied: Arc<AtomicUsize>,
}
impl RpcTransport for DenyWrites {
    fn send(&self, request: &Value) -> invisi_sdk_session::rpc::Result<Value> {
        if request["method"]
            .as_str()
            .is_some_and(|m| m.contains("submit") || m.contains("send"))
        {
            self.denied.fetch_add(1, Ordering::SeqCst);
            return Err(Error::Transport("READ_ONLY_BROADCAST_DENIED".into()));
        }
        self.transport.send(request)
    }
}
struct UnusedSource;
impl SessionSource for UnusedSource {
    fn context(&self) -> invisi_sdk_session::note::ProtocolContext {
        invisi_sdk_session::note::ProtocolContext {
            chain_id: 31337,
            protocol_address: address_word(Address::repeat_byte(1)),
        }
    }
    fn deployment_start(&self) -> u64 {
        1
    }
    fn indexed_head(&self) -> invisi_sdk_session::session::Result<CanonicalBlock> {
        panic!("no inventory discovery for self-contained shield")
    }
    fn block(&self, _: u64) -> invisi_sdk_session::session::Result<CanonicalBlock> {
        panic!("unused source")
    }
    fn discover(&self, _: u64, _: u64) -> invisi_sdk_session::session::Result<Vec<B256>> {
        panic!("unused source")
    }
    fn receipt(&self, _: B256) -> invisi_sdk_session::session::Result<Option<CanonicalReceipt>> {
        panic!("unused source")
    }
    fn transaction(
        &self,
        _: B256,
    ) -> invisi_sdk_session::session::Result<Option<CanonicalTransaction>> {
        panic!("unused source")
    }
    fn membership(
        &self,
        _: &MembershipInput,
        _: &CanonicalBlock,
    ) -> invisi_sdk_session::session::Result<Membership> {
        panic!("unused source")
    }
}
fn assert_operation_nonce(session: &WalletSession, id: &str, expected: U256) {
    let state = session.snapshot().unwrap();
    let saved = serde_json::to_value(&state.operations[id].snapshot).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(saved["unsignedCall"].clone()).unwrap();
    let call =
        invisi_sdk_session::protocol::InvisiCore::shieldCall::abi_decode_validate(&bytes).unwrap();
    assert_eq!(
        call._3.sigNonce, expected,
        "explicit fresh nonce must be used in prepared/quoted intent"
    );
}
fn phase<T>(
    trace: &Trace,
    index: usize,
    name: &str,
    phases: &mut Vec<Value>,
    run: impl FnOnce() -> T,
) -> T {
    *trace.phase.lock().unwrap() = (index, name.into());
    let start = Instant::now();
    let before = trace.rows.lock().unwrap().len();
    let value = run();
    let attempts = trace.rows.lock().unwrap().len() - before;
    phases.push(json!({"transactionIndex":index,"phase":name,"elapsedMs":start.elapsed().as_secs_f64()*1000.0,"actualHttpAttempts":attempts}));
    value
}

#[test]
#[ignore = "opt-in controlled diagnostic; coordinate CPU quiet before measured run"]
fn ordinary_shield_http_alignment() {
    let variant = if cfg!(invisi_alignment_before) || cfg!(invisi_stage_before) {
        "before"
    } else {
        "after"
    };
    let delay = std::env::var("INVISI_ALIGNMENT_DELAY_MS")
        .unwrap_or_else(|_| "0".into())
        .parse::<u64>()
        .unwrap();
    let fixtures = std::env::var("INVISI_ALIGNMENT_FIXTURES")
        .unwrap_or_else(|_| "3".into())
        .parse::<usize>()
        .unwrap();
    let stage_contract = std::env::var("INVISI_ALIGNMENT_STAGE_CONTRACT").as_deref() == Ok("1");
    let mut results = Vec::new();
    for fixture in 1..=fixtures {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let trace = Trace {
            phase: Arc::new(Mutex::new((0, "cold".into()))),
            rows: Arc::new(Mutex::new(Vec::new())),
            hashes: source_hashes(),
        };
        let mut phases = Vec::new();
        let cold = Instant::now();
        let server = Server::start(trace.clone(), fixture, now, delay, variant.into());
        let address: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/current-address.json"))
                .unwrap();
        let recipient = Wallet::from_address(address["longAddress"].as_str().unwrap()).unwrap();
        let wallet = Wallet::from_keys(owner(1), recipient.receiving_keys().clone()).unwrap();
        let cold_ms = cold.elapsed().as_secs_f64() * 1000.0;
        let denied = Arc::new(AtomicUsize::new(0));
        let token = Address::repeat_byte(2);
        let (chain, client, session) = phase(&trace, 0, "initialization", &mut phases, || {
            let deployment = ProtocolDeployment {
                chain_id: "31337".into(),
                protocol: ContractDeployment {
                    address: Address::repeat_byte(1),
                    runtime_code_hash: keccak256([1]),
                    from_block: 1,
                },
                registry: None,
                broadcaster_registry: None,
            };
            let native = EthereumChain::new(HttpTransport::new(&server.endpoint).unwrap());
            #[cfg(invisi_alignment_before)]
            let chain: Arc<dyn ChainState> =
                Arc::new(RpcChainState::new(native, deployment).unwrap());
            #[cfg(not(invisi_alignment_before))]
            let chain: Arc<dyn ChainState> =
                Arc::new(InitializedRpcChainState::ethereum(native, deployment).unwrap());
            let config = broadcaster::Configuration {
                endpoint: "https://alignment.invalid".into(),
                quote_signer: owner(17),
                fee_recipient: Address::repeat_byte(4),
            };
            let rpc_client = invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
                config,
                DenyWrites {
                    transport: HttpTransport::new(&server.endpoint).unwrap(),
                    denied: denied.clone(),
                },
            )
            .unwrap();
            #[cfg(invisi_alignment_before)]
            let client = {
                assert!(rpc_client
                    .supports_token(token, 31337, Address::repeat_byte(1))
                    .unwrap());
                broadcaster::BroadcasterClient::from_rpc(rpc_client)
            };
            #[cfg(not(invisi_alignment_before))]
            let client =
                InitializedBroadcasters::configured(rpc_client, chain.clone(), token).unwrap();
            let session = WalletSession::connect(
                Invisi::new(chain.clone()),
                wallet.clone(),
                Arc::new(MemoryWalletStore::default()),
                Arc::new(UnusedSource),
                "alignment",
            )
            .unwrap();
            (chain, client, session)
        });
        let mut first_journal: Option<(String, Vec<u8>)> = None;
        for index in 1..=2 {
            let seed = index as u8;
            let deadline = now + 3600;
            let mut operation = phase(&trace, index, "prepare", &mut phases, || {
                if stage_contract {
                    let output = NoteOutput::for_recipient(
                        chain.context(),
                        token,
                        &recipient,
                        U256::from(30),
                        Vec::new(),
                    )
                    .unwrap();
                    let options = ShieldPreparation {
                        token,
                        outputs: vec![output],
                        funding: invisi_sdk_session::protocol::IInvisiCore::FundingParams {
                            amount: U256::from(30),
                            payer: owner(seed),
                            sigNonce: U256::ZERO,
                            deadline: U256::from(deadline),
                            ..empty_funding()
                        },
                        fee: Fee::default(),
                        deadline,
                    };
                    // API adapter only: both variants request a current signature
                    // nonce. The old API defers its selection to quote; the new
                    // explicit API selects it inside preparation.
                    #[cfg(not(any(invisi_alignment_before, invisi_stage_before)))]
                    return session
                        .prepare_shield_with_signature_funding(
                            options,
                            SignatureFundingNonce::Current,
                        )
                        .unwrap();
                    #[cfg(any(invisi_alignment_before, invisi_stage_before))]
                    return session.prepare_shield(options).unwrap();
                }
                // Includes current nonce prerequisite and full prepare I/O.
                #[cfg(invisi_alignment_before)]
                let nonce = {
                    let block = chain.snapshot().unwrap();
                    chain.funding_nonce(owner(seed), &block).unwrap()
                };
                #[cfg(not(invisi_alignment_before))]
                let fresh = chain.fresh_funding_nonce(owner(seed)).unwrap().unwrap();
                #[cfg(not(invisi_alignment_before))]
                let nonce = fresh.nonce();
                let output = NoteOutput::for_recipient(
                    chain.context(),
                    token,
                    &recipient,
                    U256::from(30),
                    Vec::new(),
                )
                .unwrap();
                let operation = session
                    .prepare_shield(ShieldPreparation {
                        token,
                        outputs: vec![output],
                        funding: invisi_sdk_session::protocol::IInvisiCore::FundingParams {
                            amount: U256::from(30),
                            payer: owner(seed),
                            sigNonce: nonce,
                            deadline: U256::from(deadline),
                            ..empty_funding()
                        },
                        fee: Fee::default(),
                        deadline,
                    })
                    .unwrap();
                #[cfg(not(invisi_alignment_before))]
                let operation = operation.with_fresh_funding_nonce(fresh, deadline).unwrap();
                operation
            });
            let id = operation.id().to_owned();
            if !stage_contract || !cfg!(any(invisi_alignment_before, invisi_stage_before)) {
                assert_operation_nonce(&session, &id, U256::from(if seed == 1 { 7 } else { 14 }));
            }
            phase(&trace, index, "quote", &mut phases, || {
                client
                    .quote(
                        &mut operation,
                        chain.clone(),
                        &BroadcasterOptions {
                            max_fee_amount: Some(U256::from(10)),
                            ..Default::default()
                        },
                    )
                    .unwrap()
            });
            assert_operation_nonce(&session, &id, U256::from(if seed == 1 { 7 } else { 14 }));
            phase(&trace, index, "funding-signature", &mut phases, || {
                let operation = session.resume(&id, None).unwrap();
                let request = operation.export_funding_authorization().unwrap();
                let signed = signature(seed, request.digest);
                let _ready = operation
                    .with_funding_signature(signed)
                    .unwrap()
                    .ready()
                    .unwrap();
            });
            phase(&trace, index, "submit", &mut phases, || {
                let mut operation = session.resume(&id, None).unwrap();
                let error = client.submit(&mut operation, chain.as_ref()).unwrap_err();
                assert!(error.contains("READ_ONLY_BROADCAST_DENIED"), "{error}");
            });
            let journal = session.snapshot().unwrap();
            assert_eq!(journal.operations.len(), index);
            if let Some((first_id, bytes)) = &first_journal {
                assert!(
                    serde_json::to_vec(&journal.operations[first_id]).unwrap() == *bytes,
                    "second operation changed intact first journal"
                );
            } else {
                first_journal = Some((
                    id.clone(),
                    serde_json::to_vec(&journal.operations[&id]).unwrap(),
                ));
            }
        }
        assert_eq!(denied.load(Ordering::SeqCst), 2);
        let rows = trace.rows.lock().unwrap().clone();
        results.push(json!({"variant":variant,"language":"rust","fixture":fixture,"coldSetupMs":cold_ms,"artificialResponseDelayMs":delay,"phases":phases,"trace":rows,"deniedWrites":denied.load(Ordering::SeqCst),"actualWriteHttpAttempts":0,"buildProfile":if cfg!(debug_assertions){"debug"}else{"release"},"journalRoundtrips":["after quote before authorization","after ready before first submit"],"fixtureNonces":{"payer1":"7","payer2":"14"},"firstJournalByteIdenticalAfterSecond":true,"sourceHashes":source_hashes(),"initializationCharged":true}));
    }
    if let Ok(path) = std::env::var("INVISI_ALIGNMENT_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&results).unwrap()).unwrap();
    }
    println!(
        "{}",
        json!({"variant":variant,"fixtures":results.len(),"deniedWrites":results.len()*2,"actualWriteHttpAttempts":0})
    );
}

#[cfg(not(invisi_alignment_before))]
#[derive(Default)]
struct FailNextJournal {
    inner: MemoryWalletStore,
    fail_next: AtomicBool,
}
#[cfg(not(invisi_alignment_before))]
impl WalletStore for FailNextJournal {
    fn snapshot(&self, scope: &str) -> invisi_sdk_session::session::Result<WalletState> {
        self.inner.snapshot(scope)
    }
    fn compare_and_swap(
        &self,
        scope: &str,
        revision: u64,
        next: WalletState,
    ) -> invisi_sdk_session::session::Result<()> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err("injected first journal write failure".into());
        }
        self.inner.compare_and_swap(scope, revision, next)
    }
    fn persistent(&self) -> bool {
        false
    }
}
#[cfg(not(invisi_alignment_before))]
struct LoseFirstResponse {
    http: HttpTransport,
    lose: AtomicBool,
}
#[cfg(not(invisi_alignment_before))]
impl RpcTransport for LoseFirstResponse {
    fn send(&self, request: &Value) -> invisi_sdk_session::rpc::Result<Value> {
        let response = self.http.send(request)?;
        if request["method"] == "broadcaster_submitTransaction"
            && self.lose.swap(false, Ordering::SeqCst)
        {
            return Err(Error::Transport(
                "simulated lost response after fake relay acceptance".into(),
            ));
        }
        Ok(response)
    }
}

#[cfg(not(invisi_alignment_before))]
#[test]
fn managed_long_shield_journal_failure_loss_replay_and_status_are_frozen() {
    for prior_wallet_export in [false, true] {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let trace = Trace {
            phase: Arc::new(Mutex::new((1, "failure-recovery".into()))),
            rows: Arc::new(Mutex::new(Vec::new())),
            hashes: source_hashes(),
        };
        let relay = Arc::new(RecoveryRelay::default());
        if prior_wallet_export {
            *relay.refusal.lock().unwrap() = Some(
                json!({"code":-32025,"message":"INSUFFICIENT_EXECUTION_SLACK: synthetic refusal"}),
            );
        }
        let server = Server::start_with_recovery(
            trace.clone(),
            1,
            now,
            0,
            "failure-only".into(),
            Some(relay.clone()),
        );
        let deployment = ProtocolDeployment {
            chain_id: "31337".into(),
            protocol: ContractDeployment {
                address: Address::repeat_byte(1),
                runtime_code_hash: keccak256([1]),
                from_block: 1,
            },
            registry: None,
            broadcaster_registry: None,
        };
        let native = Arc::new(
            InitializedRpcChainState::ethereum(
                EthereumChain::new(HttpTransport::new(&server.endpoint).unwrap()),
                deployment,
            )
            .unwrap(),
        );
        let chain: Arc<dyn ChainState> = native.clone();
        let token = Address::repeat_byte(2);
        let rpc = invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
            broadcaster::Configuration {
                endpoint: "https://alignment.invalid".into(),
                quote_signer: owner(17),
                fee_recipient: Address::repeat_byte(4),
            },
            LoseFirstResponse {
                http: HttpTransport::new(&server.endpoint).unwrap(),
                lose: AtomicBool::new(!prior_wallet_export),
            },
        )
        .unwrap();
        let pool = InitializedBroadcasters::configured(rpc, chain.clone(), token).unwrap();
        let address: Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/current-address.json"))
                .unwrap();
        let recipient = Wallet::from_address(address["longAddress"].as_str().unwrap()).unwrap();
        let wallet = Wallet::from_keys(owner(1), recipient.receiving_keys().clone()).unwrap();
        let store = Arc::new(FailNextJournal::default());
        let session = WalletSession::connect(
            Invisi::new(chain.clone()),
            wallet,
            store.clone(),
            Arc::new(UnusedSource),
            "alignment-recovery",
        )
        .unwrap();
        let seed = if prior_wallet_export { 2 } else { 1 };
        let expected_nonce = U256::from(if seed == 1 { 7 } else { 14 });
        let deadline = now + 3600;
        let fresh = chain.fresh_funding_nonce(owner(seed)).unwrap().unwrap();
        assert_eq!(fresh.nonce(), expected_nonce);
        let output = NoteOutput::for_recipient(
            chain.context(),
            token,
            &recipient,
            U256::from(30),
            Vec::new(),
        )
        .unwrap();
        let mut operation = session
            .prepare_shield(ShieldPreparation {
                token,
                outputs: vec![output],
                funding: invisi_sdk_session::protocol::IInvisiCore::FundingParams {
                    payer: owner(seed),
                    amount: U256::from(30),
                    ..empty_funding()
                },
                fee: Fee::default(),
                deadline,
            })
            .unwrap()
            .with_fresh_funding_nonce(fresh, deadline)
            .unwrap();
        pool.quote(
            &mut operation,
            chain.clone(),
            &BroadcasterOptions {
                max_fee_amount: Some(U256::from(10)),
                ..Default::default()
            },
        )
        .unwrap();
        let request = operation.export_funding_authorization().unwrap();
        operation = operation
            .with_funding_signature(signature(seed, request.digest))
            .unwrap()
            .ready()
            .unwrap();
        let id = operation.id().to_owned();
        assert_operation_nonce(&session, &id, expected_nonce);
        if prior_wallet_export {
            operation.calldata(Address::ZERO).unwrap();
        }
        let old = serde_json::to_vec(&session.snapshot().unwrap()).unwrap();
        let http_before = trace.rows.lock().unwrap().len();
        store.fail_next.store(true, Ordering::SeqCst);
        assert!(pool
            .submit(&mut operation, chain.as_ref())
            .unwrap_err()
            .contains("injected first journal write failure"));
        assert!(
            serde_json::to_vec(&session.snapshot().unwrap()).unwrap() == old,
            "failed first relay journal write changed the old snapshot"
        );
        assert_eq!(
            trace.rows.lock().unwrap().len(),
            http_before,
            "no HTTP transport before complete journal commit"
        );
        assert!(relay.submissions.lock().unwrap().is_empty());
        operation = session.resume(&id, None).unwrap();
        let committed = store.clone();
        let scope = session.scope().key();
        let checked_id = id.clone();
        *relay.before_submit.lock().unwrap() = Some(Box::new(move |wire| {
            let state = committed.snapshot(&scope).unwrap();
            let record = &state.operations[&checked_id];
            assert!(
                record.externalized
                    && record.broadcaster_id.as_deref() == Some(checked_id.as_str()),
                "fake relay reached before durable handoff"
            );
            let data =
                hex::decode(wire["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
            assert!(
                record.call.as_ref().unwrap().data == data,
                "frozen calldata differs from durable record"
            );
            let saved = serde_json::to_value(&record.snapshot).unwrap();
            assert!(
                saved["broadcaster"]["quote"]["quote"] == wire["quote"]
                    && saved["broadcaster"]["quote"]["signature"] == wire["signature"],
                "exact signed quote must be durable before fake relay acceptance"
            );
        }));
        let error = pool.submit(&mut operation, chain.as_ref()).unwrap_err();
        assert!(
            error.contains(if prior_wallet_export {
                "INSUFFICIENT_EXECUTION_SLACK"
            } else {
                "simulated lost response"
            }),
            "unexpected synthetic failure"
        );
        let state = session.snapshot().unwrap();
        let record = &state.operations[&id];
        assert!(record.externalized && record.broadcaster_id.is_some());
        assert!(record.snapshot.broadcaster_pre_send_refusal().is_none());
        assert!(session.abandon_operation(&id, None).is_err());
        let frozen = relay.submissions.lock().unwrap()[0].clone();
        pool.invalidate();
        assert!(!native.deployment_receipt_valid());
        drop(operation);
        let before = trace.rows.lock().unwrap().len();
        let mut resumed = session.resume(&id, None).unwrap();
        assert_eq!(
            trace.rows.lock().unwrap().len(),
            before,
            "resume must not read nonce or network"
        );
        assert_eq!(
            pool.submit(&mut resumed, chain.as_ref()).unwrap().id,
            "fixture-accepted"
        );
        let methods = trace.rows.lock().unwrap()[before..]
            .iter()
            .map(|row| row["method"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            vec!["broadcaster_submitTransaction"],
            "unknown replay must use only the identical frozen fake relay packet"
        );
        let submitted = relay.submissions.lock().unwrap();
        assert!(
            submitted.len() == 2 && submitted.iter().all(|wire| wire == &frozen),
            "unknown-ID retry changed frozen parameters"
        );
        drop(submitted);
        drop(resumed);
        let before = trace.rows.lock().unwrap().len();
        let mut known = session.resume(&id, None).unwrap();
        assert_eq!(
            pool.submit(&mut known, chain.as_ref()).unwrap().id,
            "fixture-accepted"
        );
        let methods = trace.rows.lock().unwrap()[before..]
            .iter()
            .map(|row| row["method"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(methods, vec!["broadcaster_getTransactionStatus"]);
        assert_eq!(relay.status_reads.load(Ordering::SeqCst), 1);
        assert_eq!(relay.submissions.lock().unwrap().len(), 2);
        assert_operation_nonce(&session, &id, expected_nonce);
    }
}
