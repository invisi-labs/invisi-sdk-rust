//! Scoped official HTTPS trust bootstrap and instance identity pinning.
use crate::provenance_client::{ProvenanceClient, DEFAULT_ENDPOINT};
use alloy_primitives::U256;
use invisi_sdk_protocol::provenance::{parse_integer, Scope, TrustContext};
use invisi_sdk_protocol::provenance_rotation::{
    verify_rotation_chain, RotationCheckpoint, RotationRecord,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const OFFICIAL_MANIFEST_SHA256: &str =
    "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762";
const MAX_DEPLOYMENTS: usize = 128;
const MAX_BOOTSTRAP_BYTES: u64 = 256 * 1024;

#[derive(Default)]
pub struct OfficialProvenanceClients {
    clients: Mutex<BTreeMap<(u64, U256), Arc<ProvenanceClient>>>,
}
impl OfficialProvenanceClients {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, scope: &Scope) -> Result<Arc<ProvenanceClient>, String> {
        self.get_with_loader(scope, || bootstrap_at(DEFAULT_ENDPOINT, scope))
    }
    fn get_with_loader(
        &self,
        scope: &Scope,
        load: impl FnOnce() -> Result<ProvenanceClient, String>,
    ) -> Result<Arc<ProvenanceClient>, String> {
        if scope.chain_id == 0
            || scope.protocol_address == U256::ZERO
            || scope.protocol_address.bit_len() > 160
        {
            return Err("invalid Provenance deployment".into());
        }
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| "Provenance cache lock poisoned")?;
        let key = (scope.chain_id, scope.protocol_address);
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        if clients.len() >= MAX_DEPLOYMENTS {
            return Err("official Provenance deployment cache limit".into());
        }
        let client = Arc::new(load()?);
        clients.insert(key, client.clone());
        Ok(client)
    }
}
fn bootstrap_at(endpoint: &str, scope: &Scope) -> Result<ProvenanceClient, String> {
    let http = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let response = http
        .post(format!("{endpoint}/v1/chains/{}", scope.chain_id))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"provenance_getRules","params":[{}]}))
        .send()
        .map_err(|e| e.to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("Provenance bootstrap HTTP {}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_BOOTSTRAP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BOOTSTRAP_BYTES {
        return Err("Provenance bootstrap response too large".into());
    }
    let env: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if env["jsonrpc"] != "2.0"
        || env["id"] != 1
        || !env["error"].is_null()
        || !env["result"].is_object()
    {
        return Err("invalid Provenance bootstrap response".into());
    }
    let trust = trust_from_rules(&env["result"], scope)?;
    ProvenanceClient::new(DEFAULT_ENDPOINT, trust)
}
fn integer(value: &Value, bits: usize) -> Result<U256, String> {
    parse_integer(
        value
            .as_str()
            .ok_or("invalid Provenance bootstrap integer")?,
        bits,
    )
    .map_err(|e| e.to_string())
}
fn trust_from_rules(rules: &Value, scope: &Scope) -> Result<TrustContext, String> {
    let generation = integer(&rules["chainGeneration"], 64)?.to::<u64>();
    if integer(&rules["scope"]["chainId"], 64)? != U256::from(scope.chain_id)
        || integer(&rules["scope"]["protocolAddress"], 160)? != scope.protocol_address
        || rules["manifestSha256"] != OFFICIAL_MANIFEST_SHA256
        || generation == 0
    {
        return Err("Provenance bootstrap deployment or release mismatch".into());
    }
    let records = rules["keyRotations"]
        .as_array()
        .ok_or("missing Provenance key rotations")?;
    if records.len() > 128 {
        return Err("too many Provenance key rotations".into());
    }
    let records: Vec<RotationRecord> = records
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let initial = rules["initialSigningPublicKey"]
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or("invalid initial Provenance signing key")?;
    let initial: [u8; 32] = hex::decode(initial)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid initial Provenance signing key")?;
    let key_id = U256::from_be_slice(&Sha256::digest(initial));
    let provider_id = integer(&rules["providerId"], 256)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let ring = verify_rotation_chain(
        RotationCheckpoint {
            provider_id,
            keys: BTreeMap::from([(key_id, initial)]),
            validity: BTreeMap::new(),
            previous_rotation_hash: [0; 32],
            last_activated_at: 0,
            now,
        },
        &records,
    )
    .map_err(|e| e.to_string())?;
    let current = integer(&rules["signingKeyId"], 256)?;
    if !ring.keys.contains_key(&current)
        || ring
            .validity
            .get(&current)
            .is_none_or(|v| v.retired_at.is_some())
    {
        return Err("untrusted active Provenance signing key".into());
    }
    Ok(TrustContext {
        scope: scope.clone(),
        chain_generation: generation,
        provider_id,
        signing_keys: ring.keys,
        signing_key_validity: ring.validity,
        manifest_sha256: OFFICIAL_MANIFEST_SHA256.into(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    fn scope() -> Scope {
        Scope {
            chain_id: 1,
            protocol_address: U256::from(2),
        }
    }
    fn rules() -> Value {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/official-rotation.json")).unwrap();
        json!({"scope":{"chainId":"1","protocolAddress":"2"},"manifestSha256":OFFICIAL_MANIFEST_SHA256,"chainGeneration":"1","providerId":fixture["providerId"],"initialSigningPublicKey":fixture["initialPublicKey"],"signingKeyId":fixture["rotation"]["newKeyId"],"keyRotations":[fixture["rotation"]]})
    }
    fn fixture(body: String, status: &str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let status = status.to_owned();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert_eq!(line, "POST /v1/chains/1 HTTP/1.1\r\n");
            let mut size = 0;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                };
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    size = v.trim().parse::<usize>().unwrap();
                }
            }
            let mut request = vec![0; size];
            reader.read_exact(&mut request).unwrap();
            let request: Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["method"], "provenance_getRules");
            assert_eq!(request["params"], json!([{}]));
            write!(stream,"HTTP/1.1 {status}\r\nContent-Length: {}\r\nLocation: https://untrusted.invalid/\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        (endpoint, handle)
    }
    fn bootstrap_fixture(rules: Value) -> Result<ProvenanceClient, String> {
        let (endpoint, handle) = fixture(
            json!({"jsonrpc":"2.0","id":1,"result":rules}).to_string(),
            "200 OK",
        );
        let result = bootstrap_at(&endpoint, &scope());
        handle.join().unwrap();
        result
    }
    #[test]
    fn invalid_deployment_is_rejected_before_transport() {
        let clients = OfficialProvenanceClients::new();
        for s in [
            Scope {
                chain_id: 0,
                protocol_address: U256::from(1),
            },
            Scope {
                chain_id: 1,
                protocol_address: U256::ZERO,
            },
            Scope {
                chain_id: 1,
                protocol_address: U256::from(1) << 160,
            },
        ] {
            assert!(clients.get(&s).is_err());
        }
    }
    #[test]
    fn verified_rotation_identity_is_pinned_and_failures_retry() {
        let clients = OfficialProvenanceClients::new();
        let mut bad = rules();
        bad["scope"]["chainId"] = json!("2");
        assert!(clients
            .get_with_loader(&scope(), || bootstrap_fixture(bad))
            .is_err());
        let first = clients
            .get_with_loader(&scope(), || bootstrap_fixture(rules()))
            .unwrap();
        assert_eq!(first.trust.chain_generation, 1);
        assert_eq!(first.trust.signing_keys.len(), 2);
        assert!(first
            .trust
            .signing_key_validity
            .values()
            .any(|v| v.retired_at.is_some()));
        let second = clients
            .get_with_loader(&scope(), || panic!("identity bootstrapped twice"))
            .unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(OfficialProvenanceClients::new()
            .clients
            .lock()
            .unwrap()
            .is_empty());
    }
    #[test]
    fn bootstrap_rejects_untrusted_deployment_release_and_keys() {
        let base = rules();
        let mut variants = Vec::new();
        for (key, value) in [
            ("manifestSha256", json!("wrong")),
            ("chainGeneration", json!("0")),
            ("initialSigningPublicKey", json!("0x01")),
            ("keyRotations", Value::Null),
            ("keyRotations", json!(vec![json!({}); 129])),
            ("signingKeyId", json!("1")),
        ] {
            let mut r = base.clone();
            r[key] = value;
            variants.push(r);
        }
        let mut retired = base.clone();
        retired["signingKeyId"] = retired["keyRotations"][0]["oldKeyId"].clone();
        variants.push(retired);
        let mut forged = base.clone();
        forged["keyRotations"][0]["signature"] = json!(format!("0x{}", "00".repeat(64)));
        variants.push(forged);
        let mut scope = base.clone();
        scope["scope"]["protocolAddress"] = json!("3");
        variants.push(scope);
        for r in variants {
            assert!(bootstrap_fixture(r).is_err());
        }
    }
    #[test]
    fn bootstrap_rejects_redirect_oversize_and_wrong_envelope() {
        for (body, status) in [
            (String::new(), "302 Found"),
            (" ".repeat(MAX_BOOTSTRAP_BYTES as usize + 1), "200 OK"),
            (
                json!({"jsonrpc":"2.0","id":2,"result":rules()}).to_string(),
                "200 OK",
            ),
        ] {
            let (endpoint, handle) = fixture(body, status);
            assert!(bootstrap_at(&endpoint, &scope()).is_err());
            handle.join().unwrap();
        }
    }
    #[test]
    fn deployment_cache_is_bounded_and_concurrent_identity_is_shared() {
        let clients = Arc::new(OfficialProvenanceClients::new());
        let client = Arc::new(bootstrap_fixture(rules()).unwrap());
        {
            let mut cache = clients.clients.lock().unwrap();
            for chain in 1..=MAX_DEPLOYMENTS as u64 {
                cache.insert((chain, U256::from(2)), client.clone());
            }
        }
        let fresh = Scope {
            chain_id: MAX_DEPLOYMENTS as u64 + 1,
            protocol_address: U256::from(2),
        };
        assert!(clients
            .get_with_loader(&fresh, || panic!("cache limit should prevent transport"))
            .is_err());
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let cache = clients.clone();
                std::thread::spawn(move || {
                    cache
                        .get_with_loader(&scope(), || {
                            panic!("cached identity should avoid transport")
                        })
                        .unwrap()
                })
            })
            .collect();
        for worker in workers {
            assert!(Arc::ptr_eq(&client, &worker.join().unwrap()));
        }
    }
}
