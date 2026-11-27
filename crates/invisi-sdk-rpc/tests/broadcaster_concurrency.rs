use invisi_sdk_rpc::{
    broadcaster::{
        BroadcasterClient, Configuration, SignedFeeLock, SignedQuote, VerifiedFeeLock,
        VerifiedQuote,
    },
    rpc::{Error, Result, RpcTransport},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct PhaseState {
    arrival: Vec<u64>,
    next: usize,
}
struct ReversePhase {
    size: usize,
    state: Mutex<PhaseState>,
    changed: Condvar,
}
struct ReplyTurn<'a>(&'a ReversePhase);
impl Drop for ReplyTurn<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.next -= 1;
        self.0.changed.notify_all();
    }
}
impl ReversePhase {
    fn new(size: usize) -> Self {
        Self {
            size,
            state: Mutex::new(PhaseState::default()),
            changed: Condvar::new(),
        }
    }
    // Waiting includes the whole phase, and each response acknowledges its turn.
    // This forces overlap and reverse-order replies without sleeps or busy loops.
    fn enter(&self, id: u64) -> Option<ReplyTurn<'_>> {
        let mut state = self.state.lock().unwrap();
        if state.arrival.len() >= self.size {
            // A retry cannot overtake the batch whose response it is retrying.
            let (current, timeout) = self
                .changed
                .wait_timeout_while(state, Duration::from_secs(8), |state| state.next != 0)
                .unwrap();
            assert!(
                !timeout.timed_out() || current.next == 0,
                "response batch failed to drain"
            );
            return None;
        }
        let slot = state.arrival.len() + 1;
        state.arrival.push(id);
        if slot == self.size {
            state.next = self.size;
            self.changed.notify_all();
        }
        let end = Instant::now() + Duration::from_secs(8);
        while state.arrival.len() < self.size || state.next != slot {
            let remaining = end.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "concurrent phase failed to overlap");
            let (current, timeout) = self.changed.wait_timeout(state, remaining).unwrap();
            state = current;
            assert!(!timeout.timed_out(), "concurrent phase failed to finish");
        }
        Some(ReplyTurn(self))
    }
}
struct State {
    fixture: Value,
    phases: BTreeMap<&'static str, ReversePhase>,
    requests: Mutex<Vec<Value>>,
    completed: Mutex<BTreeMap<String, Vec<u64>>>,
    lose_first: AtomicBool,
    corrupt_status: AtomicBool,
}
struct Transport(Arc<State>);
impl RpcTransport for Transport {
    fn send(&self, request: &Value) -> Result<Value> {
        self.0.requests.lock().unwrap().push(request.clone());
        let method = request["method"].as_str().unwrap();
        let body = &request["params"][0];
        let fixture = &self.0.fixture;
        let rows = fixture["transactions"].as_array().unwrap();
        let index = rows.iter().position(|tx| {
            if method == "broadcaster_getTransactionStatus" {
                tx["status"]["id"] == body["id"]
            } else {
                tx["data"] == body["data"]
            }
        });
        let mut lose = false;
        let result = match method {
            "broadcaster_getStatus" => json!({
                "apiVersion":"v1","protocolVersion":"1","chainId":fixture["trust"]["chainId"],
                "protocol":fixture["trust"]["protocol"],"sender":fixture["trust"]["signer"],
                "feeRecipient":fixture["trust"]["signer"],"submissionHalted":false,
                "provenance":{"enabled":false},
                "feeLock":{"version":"1","model":"core-gas-v1.3.4","core":true,"router":false}
            }),
            "broadcaster_lockFee"
            | "broadcaster_estimateQuote"
            | "broadcaster_getQuote"
            | "broadcaster_submitTransaction" => {
                let i = index.expect("unknown calldata");
                let tx = &rows[i];
                let ticket = fixture["tickets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|ticket| ticket["lock"]["token"] == tx["token"])
                    .unwrap();
                match method {
                    "broadcaster_lockFee" => ticket.clone(),
                    "broadcaster_estimateQuote" | "broadcaster_getQuote" => {
                        assert_eq!(&body["feeLock"], ticket, "crossed pricing ticket");
                        if method == "broadcaster_getQuote" {
                            tx["signed"].clone()
                        } else {
                            json!({"feeRecipient":fixture["trust"]["signer"],"feeAmount":tx["feeAmount"],"maxGas":tx["signed"]["quote"]["maxGas"]})
                        }
                    }
                    _ => {
                        assert_eq!(
                            body["quote"], tx["signed"]["quote"],
                            "crossed submission quote"
                        );
                        assert_eq!(body["signature"], tx["signed"]["signature"]);
                        assert!(body.get("feeLock").is_none());
                        lose = i == 0
                            && self
                                .0
                                .lose_first
                                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok();
                        tx["status"].clone()
                    }
                }
            }
            "broadcaster_getTransactionStatus" => {
                let i = index.expect("unknown status ID");
                if self.0.corrupt_status.load(Ordering::SeqCst) {
                    rows[1]["status"].clone()
                } else {
                    rows[i]["status"].clone()
                }
            }
            other => panic!("unexpected RPC {other}"),
        };
        let id = request["id"].as_u64().unwrap();
        let _turn = self.0.phases.get(method).and_then(|phase| phase.enter(id));
        self.0
            .completed
            .lock()
            .unwrap()
            .entry(method.into())
            .or_default()
            .push(id);
        if lose {
            return Err(Error::Transport("response lost after acceptance".into()));
        }
        Ok(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

#[test]
fn one_client_isolates_concurrent_quotes_locks_retries_and_statuses() {
    let mut fixture: Value =
        serde_json::from_str(include_str!("fixtures/concurrent-broadcaster.json")).unwrap();
    // Alloy serializes addresses in lowercase. Compare decoded address values,
    // retaining the independent fixture's amounts, hashes and signatures.
    for ticket in fixture["tickets"].as_array_mut().unwrap() {
        *ticket =
            serde_json::to_value(serde_json::from_value::<SignedFeeLock>(ticket.clone()).unwrap())
                .unwrap();
    }
    for row in fixture["transactions"].as_array_mut().unwrap() {
        row["signed"] = serde_json::to_value(
            serde_json::from_value::<SignedQuote>(row["signed"].clone()).unwrap(),
        )
        .unwrap();
    }
    let protocol = fixture["trust"]["protocol"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let signer = fixture["trust"]["signer"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let state = Arc::new(State {
        fixture: fixture.clone(),
        phases: [
            ("broadcaster_lockFee", 4),
            ("broadcaster_estimateQuote", 4),
            ("broadcaster_getQuote", 4),
            ("broadcaster_submitTransaction", 8),
            ("broadcaster_getTransactionStatus", 4),
        ]
        .into_iter()
        .map(|(name, size)| (name, ReversePhase::new(size)))
        .collect(),
        requests: Mutex::new(vec![]),
        completed: Mutex::new(BTreeMap::new()),
        lose_first: AtomicBool::new(true),
        corrupt_status: AtomicBool::new(false),
    });
    let client = BroadcasterClient::new(
        Configuration {
            endpoint: "https://concurrent.test".into(),
            quote_signer: signer,
            fee_recipient: signer,
        },
        Transport(state.clone()),
    )
    .unwrap();
    assert!(client.initialize_fee_lock(31337, protocol).unwrap());
    let retries = AtomicUsize::new(0);
    let results: Vec<(VerifiedFeeLock, VerifiedQuote)> = std::thread::scope(|scope| {
        let workers: Vec<_> = fixture["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tx| {
                let client = &client;
                let retries = &retries;
                scope.spawn(move || {
                    let data =
                        hex::decode(tx["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                    let token = tx["token"].as_str().unwrap().parse().unwrap();
                    let lock = client
                        .lock_fee(&data, 31337, protocol, 1900000000)
                        .unwrap()
                        .unwrap();
                    let estimate = client
                        .fee_with_schedule_and_lock(token, Some(&data), None, Some(&lock))
                        .unwrap();
                    assert_eq!(estimate.fee_amount, tx["feeAmount"].as_str().unwrap());
                    let quote = client
                        .quote_with_schedule_and_lock(
                            &data,
                            31337,
                            protocol,
                            1900000000,
                            &[],
                            None,
                            Some(&lock),
                        )
                        .unwrap();
                    assert_eq!(serde_json::to_value(quote.signed()).unwrap(), tx["signed"]);
                    let attempts = std::thread::scope(|s| {
                        let a = s.spawn(|| client.submit_transaction(&data, &quote));
                        let b = s.spawn(|| client.submit_transaction(&data, &quote));
                        [a.join().unwrap(), b.join().unwrap()]
                    });
                    for attempt in attempts {
                        let status = match attempt {
                            Ok(status) => status,
                            Err(Error::Transport(message))
                                if message == "response lost after acceptance" =>
                            {
                                retries.fetch_add(1, Ordering::SeqCst);
                                client.submit_transaction(&data, &quote).unwrap()
                            }
                            Err(error) => panic!("unexpected submission error {error}"),
                        };
                        assert_eq!(serde_json::to_value(status).unwrap(), tx["status"]);
                    }
                    let status = client.status(tx["status"]["id"].as_str().unwrap()).unwrap();
                    assert_eq!(serde_json::to_value(status).unwrap(), tx["status"]);
                    (lock, quote)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    });
    assert_eq!(retries.load(Ordering::SeqCst), 1);
    let requests = state.requests.lock().unwrap().clone();
    let ids: BTreeSet<_> = requests.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    assert_eq!(ids.len(), requests.len(), "reused JSON-RPC request ID");
    for (method, phase) in &state.phases {
        let arrival = phase.state.lock().unwrap().arrival.clone();
        let completed = state.completed.lock().unwrap()[*method].clone();
        assert_eq!(arrival.len(), phase.size);
        assert_eq!(
            completed[..phase.size],
            arrival.into_iter().rev().collect::<Vec<_>>()
        );
    }
    let submissions: Vec<_> = requests
        .iter()
        .filter(|r| r["method"] == "broadcaster_submitTransaction")
        .collect();
    assert_eq!(submissions.len(), 9);
    for (i, tx) in fixture["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let packets: Vec<_> = submissions
            .iter()
            .filter(|r| r["params"][0]["data"] == tx["data"])
            .map(|r| &r["params"][0])
            .collect();
        assert_eq!(packets.len(), if i == 0 { 3 } else { 2 });
        assert!(
            packets.iter().all(|packet| *packet == packets[0]),
            "retry changed frozen packet"
        );
    }
    let data = hex::decode(
        fixture["transactions"][0]["data"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    assert!(client.submit_transaction(&data, &results[2].1).is_err());
    assert_eq!(
        state.requests.lock().unwrap().len(),
        requests.len(),
        "crossed quote reached transport"
    );
    let id = fixture["transactions"][0]["status"]["id"].as_str().unwrap();
    state.corrupt_status.store(true, Ordering::SeqCst);
    assert!(client.status(id).is_err());
    state.corrupt_status.store(false, Ordering::SeqCst);
    assert_eq!(
        serde_json::to_value(client.status(id).unwrap()).unwrap(),
        fixture["transactions"][0]["status"]
    );
    assert_eq!(results[0].0.signed(), results[2].0.signed());
    assert_ne!(results[0].0.signed(), results[1].0.signed());
}
