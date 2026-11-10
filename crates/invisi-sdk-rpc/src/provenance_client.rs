//! Public Source JSON-RPC transport, independent of payment execution.
use alloy_primitives::U256;
use invisi_sdk_protocol::provenance::{
    assert_certificate_trust, parse_integer, ProofBundle, ProofSidecar, RootCertificate,
    TrustContext,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
pub const DEFAULT_ENDPOINT: &str = "https://provenance.invisipay.fi";
pub struct ProvenanceClient {
    endpoint: String,
    pub trust: TrustContext,
    client: reqwest::blocking::Client,
    sequence: AtomicU64,
}
impl ProvenanceClient {
    pub fn new(endpoint: &str, trust: TrustContext) -> Result<Self, String> {
        let endpoint = if endpoint.is_empty() {
            DEFAULT_ENDPOINT
        } else {
            endpoint
        };
        let url = reqwest::Url::parse(endpoint).map_err(|e| e.to_string())?;
        if !["https", "http"].contains(&url.scheme())
            || url.host_str().is_none()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("invalid provenance endpoint".into());
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').into(),
            trust,
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| e.to_string())?,
            sequence: AtomicU64::new(0),
        })
    }
    fn call(&self, method: &str, query: Option<Value>) -> Result<Value, String> {
        if let Some(q) = &query {
            invisi_sdk_protocol::provenance::assert_public_submission(q)
                .map_err(|e| e.to_string())?;
        }
        let id = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let response=self.client.post(format!("{}/v1/chains/{}",self.endpoint,self.trust.scope.chain_id)).json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":query.map(|q|vec![q]).unwrap_or_default()})).send().map_err(|e|e.to_string())?.error_for_status().map_err(|e|e.to_string())?;
        if response.content_length().unwrap_or(0) > 4 * 1024 * 1024 {
            return Err("provenance response exceeds limit".into());
        }
        let env: Value = response.json().map_err(|e| e.to_string())?;
        if env["jsonrpc"] != "2.0" || env["id"] != id {
            return Err("invalid JSON-RPC response".into());
        }
        if !env["error"].is_null() {
            return Err(format!(
                "provenance error: {}",
                env["error"]["data"]["code"]
            ));
        }
        let r = env["result"].clone();
        if [
            "provenance_evaluateTransaction",
            "provenance_submitSourceProof",
            "provenance_submitProof",
            "provenance_getProofJob",
            "provenance_getTracking",
        ]
        .contains(&method)
            && [
                "chainGeneration",
                "providerId",
                "signingKeyId",
                "manifestSha256",
            ]
            .iter()
            .any(|key| r.get(*key).is_none())
        {
            return Err("missing response trust identity".into());
        }
        let scope = &r["scope"];
        for (k, n) in [
            ("chainId", U256::from(self.trust.scope.chain_id)),
            ("protocolAddress", self.trust.scope.protocol_address),
        ] {
            let value = scope[k].as_str().ok_or("missing provenance scope")?;
            if parse_integer(value, 256).map_err(|e| e.to_string())? != n {
                return Err("deployment mismatch".into());
            }
        }
        for (k, n) in [
            ("chainGeneration", U256::from(self.trust.chain_generation)),
            ("providerId", self.trust.provider_id),
        ] {
            if let Some(v) = r.get(k) {
                if parse_integer(v.as_str().ok_or("invalid identity")?, 256)
                    .map_err(|e| e.to_string())?
                    != n
                {
                    return Err(format!("{k} mismatch"));
                }
            }
        }
        if let Some(v) = r.get("manifestSha256") {
            if v.as_str() != Some(&self.trust.manifest_sha256) {
                return Err("manifest mismatch".into());
            }
        }
        if let Some(v) = r.get("signingKeyId") {
            let key = parse_integer(v.as_str().ok_or("invalid key id")?, 256)
                .map_err(|e| e.to_string())?;
            if method != "provenance_getRules" && !self.trust.signing_keys.contains_key(&key) {
                return Err("untrusted signing key".into());
            }
        }
        Ok(r)
    }
    fn query(&self, q: Value) -> Value {
        q
    }
    pub fn get_version(&self) -> Result<Value, String> {
        self.call("provenance_getVersion", Some(self.query(json!({}))))
    }
    pub fn get_status(&self) -> Result<Value, String> {
        self.call("provenance_getStatus", Some(self.query(json!({}))))
    }
    pub fn get_rules(&self) -> Result<Value, String> {
        self.call("provenance_getRules", Some(self.query(json!({}))))
    }
    pub fn get_roots(&self, q: Value) -> Result<Value, String> {
        let r = self.call("provenance_getRoots", Some(self.query(q)))?;
        let items = r["items"].as_array().ok_or("missing certificates")?;
        for item in items {
            let c: RootCertificate =
                serde_json::from_value(item.clone()).map_err(|e| e.to_string())?;
            assert_certificate_trust(&c, &self.trust).map_err(|e| e.to_string())?;
        }
        Ok(r)
    }
    pub fn get_root(&self, root_id: &str) -> Result<Value, String> {
        let r = self.call(
            "provenance_getRoot",
            Some(self.query(json!({"rootId":root_id}))),
        )?;
        if let Some(c) = r.get("certificate") {
            let c: RootCertificate =
                serde_json::from_value(c.clone()).map_err(|e| e.to_string())?;
            assert_certificate_trust(&c, &self.trust).map_err(|e| e.to_string())?;
        }
        Ok(r)
    }
    pub fn get_leaves(&self, root_id: &str, from: u64, limit: u32) -> Result<Value, String> {
        if limit == 0 || limit > 200 {
            return Err("page limit".into());
        }
        self.call(
            "provenance_getLeaves",
            Some(self.query(json!({"rootId":root_id,"fromIndex":from.to_string(),"limit":limit}))),
        )
    }
    pub fn get_note_recognition(&self, commitment: U256) -> Result<Value, String> {
        invisi_sdk_primitives::note::field(commitment, "commitment").map_err(|e| e.to_string())?;
        let encoded = format!("0x{}", hex::encode(commitment.to_be_bytes::<32>()));
        self.call(
            "provenance_getNoteRecognition",
            Some(self.query(json!({"commitment":encoded}))),
        )
    }
    pub fn get_operation_recognition(&self, locator: Value) -> Result<Value, String> {
        self.call(
            "provenance_getOperationRecognition",
            Some(self.query(locator)),
        )
    }
    pub fn get_transaction_recognition(&self, tx_hash: &str) -> Result<Value, String> {
        parse_integer(tx_hash, 256).map_err(|e| e.to_string())?;
        self.call(
            "provenance_getTransactionRecognition",
            Some(self.query(json!({"txHash":tx_hash}))),
        )
    }
    pub fn evaluate_transaction(
        &self,
        data: Value,
        proof_sidecars: &[ProofSidecar],
    ) -> Result<Value, String> {
        invisi_sdk_protocol::provenance::assert_public_submission(&data)
            .map_err(|e| e.to_string())?;
        for sidecar in proof_sidecars {
            parse_integer(&sidecar.operation_index, 32).map_err(|e| e.to_string())?;
            invisi_sdk_protocol::provenance::validate_proof_bundle(
                &sidecar.proof_bundle,
                &self.trust,
            )
            .map_err(|e| e.to_string())?;
        }
        let wire_sidecars = proof_sidecars
            .iter()
            .map(invisi_sdk_protocol::provenance::proof_sidecar_to_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        self.call(
            "provenance_evaluateTransaction",
            Some(self.query(json!({"data":data,"proofSidecars":wire_sidecars}))),
        )
    }
    pub fn submit_source_proof(
        &self,
        data: Value,
        proof_sidecars: &[ProofSidecar],
    ) -> Result<Value, String> {
        invisi_sdk_protocol::provenance::assert_public_submission(&data)
            .map_err(|e| e.to_string())?;
        for sidecar in proof_sidecars {
            parse_integer(&sidecar.operation_index, 32).map_err(|e| e.to_string())?;
            invisi_sdk_protocol::provenance::validate_proof_bundle(
                &sidecar.proof_bundle,
                &self.trust,
            )
            .map_err(|e| e.to_string())?;
        }
        let wire = proof_sidecars
            .iter()
            .map(invisi_sdk_protocol::provenance::proof_sidecar_to_wire)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        self.call(
            "provenance_submitSourceProof",
            Some(self.query(json!({"data":data,"proofSidecars":wire}))),
        )
    }
    pub fn submit_proof(
        &self,
        mut locator: Value,
        bundle: &ProofBundle,
        idempotency_key: &str,
    ) -> Result<Value, String> {
        if idempotency_key.starts_with("internal/") {
            return Err("reserved idempotency key prefix".into());
        }
        if idempotency_key.is_empty() {
            return Err("idempotency key required".into());
        }
        invisi_sdk_protocol::provenance::validate_proof_bundle(bundle, &self.trust)
            .map_err(|e| e.to_string())?;
        locator["proofBundle"] = json!(invisi_sdk_protocol::provenance::proof_bundle_to_wire(
            bundle
        )
        .map_err(|e| e.to_string())?);
        locator["idempotencyKey"] = json!(idempotency_key);
        self.call("provenance_submitProof", Some(self.query(locator)))
    }
    pub fn get_tracking(&self, id: &str) -> Result<Value, String> {
        if id.len() != 48
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid tracking id".into());
        }
        let result = self.call(
            "provenance_getTracking",
            Some(self.query(json!({"trackingId":id}))),
        )?;
        crate::provenance_tracking::tracking_from_result(&result, Some(id))?;
        Ok(result)
    }
    pub fn wait_tracking(
        &self,
        id: &str,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Value, String> {
        if interval.is_zero() || interval > Duration::from_secs(60) || timeout.is_zero() {
            return Err("tracking polling limits".into());
        }
        let deadline = Instant::now() + timeout;
        loop {
            let result = self.get_tracking(id)?;
            let tracking = crate::provenance_tracking::tracking_from_result(&result, Some(id))?;
            if ["recognized", "expired", "superseded"].contains(&tracking.status.as_str()) {
                return Ok(result);
            }
            if Instant::now() >= deadline {
                return Err("tracking wait timeout".into());
            }
            std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
    pub fn get_proof_job(&self, job_id: &str) -> Result<Value, String> {
        self.call("provenance_getProofJob", Some(json!({"jobId":job_id})))
    }
    pub fn wait_proof_job(
        &self,
        job_id: &str,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Value, String> {
        if interval.is_zero() || interval > Duration::from_secs(60) {
            return Err("poll interval".into());
        }
        let deadline = Instant::now() + timeout;
        loop {
            let r = self.get_proof_job(job_id)?;
            if ["valid", "invalid", "retryable_error", "stale_generation"]
                .contains(&r["status"].as_str().unwrap_or(""))
            {
                return Ok(r);
            }
            if !["queued", "verifying"].contains(&r["status"].as_str().unwrap_or("")) {
                return Err("unsupported proof job status".into());
            }
            if Instant::now() >= deadline {
                return Err("proof job wait timeout".into());
            }
            std::thread::sleep(interval.min(deadline.saturating_duration_since(Instant::now())));
        }
    }
}

impl ProvenanceClient {
    pub fn sync_recognized_tree(
        &self,
        root_id: &str,
        certificate: &RootCertificate,
        max_leaves: u64,
    ) -> Result<invisi_sdk_protocol::provenance::RecognizedTree, String> {
        use invisi_sdk_protocol::provenance::{
            checkpoint_hash, recognized_leaf, scope_hash, RecognizedTree,
        };
        assert_certificate_trust(certificate, &self.trust).map_err(|e| e.to_string())?;
        let count = parse_integer(&certificate.leaf_count, 64)
            .map_err(|e| e.to_string())?
            .to::<u64>();
        if max_leaves == 0 || count > max_leaves {
            return Err("local replay exceeds configured leaf budget".into());
        }
        let checkpoint = checkpoint_hash(certificate).map_err(|e| e.to_string())?;
        let scope = scope_hash(&self.trust.scope).map_err(|e| e.to_string())?;
        let mut tree = RecognizedTree::default();
        while tree.leaf_count() < count {
            let page = self.get_leaves(root_id, tree.leaf_count(), 200)?;
            if page["rootId"].as_str() != Some(root_id) {
                return Err("root snapshot changed".into());
            }
            let cert: RootCertificate =
                serde_json::from_value(page["certificate"].clone()).map_err(|e| e.to_string())?;
            assert_certificate_trust(&cert, &self.trust).map_err(|e| e.to_string())?;
            if checkpoint_hash(&cert).map_err(|e| e.to_string())? != checkpoint {
                return Err("root snapshot changed".into());
            }
            let items = page["items"].as_array().ok_or("missing leaf items")?;
            if items.is_empty() {
                return Err("incomplete leaf page".into());
            }
            for item in items {
                let read = |v: &Value| {
                    parse_integer(v.as_str().ok_or("invalid leaf field")?, 256)
                        .map_err(|e| e.to_string())
                };
                for (k, n) in [
                    ("chainId", U256::from(self.trust.scope.chain_id)),
                    ("protocolAddress", self.trust.scope.protocol_address),
                ] {
                    if read(&item["scope"][k])? != n {
                        return Err("leaf scope mismatch".into());
                    }
                }
                if read(&item["chainGeneration"])? != U256::from(self.trust.chain_generation)
                    || read(&item["treeId"])?
                        != parse_integer(&certificate.tree_id, 64).map_err(|e| e.to_string())?
                    || read(&item["leafIndex"])? != U256::from(tree.leaf_count())
                    || tree.leaf_count() >= count
                    || read(&item["checkpointSequence"])?
                        > parse_integer(&certificate.root_sequence, 64)
                            .map_err(|e| e.to_string())?
                {
                    return Err("invalid recognized leaf position".into());
                }
                let leaf = read(&item["leaf"])?;
                if recognized_leaf(scope, read(&item["noteCommitment"])?)
                    .map_err(|e| e.to_string())?
                    != leaf
                {
                    return Err("recognized leaf hash mismatch".into());
                }
                tree.append(leaf).map_err(|e| e.to_string())?;
            }
            if page["nextIndex"].as_str() != Some(&tree.leaf_count().to_string()) {
                return Err("noncontiguous leaf cursor".into());
            }
        }
        let root = tree.root().map_err(|e| e.to_string())?;
        if root != parse_integer(&certificate.root, 256).map_err(|e| e.to_string())? {
            return Err("rebuilt root mismatch".into());
        }
        Ok(tree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use invisi_sdk_protocol::provenance::Scope;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    fn trust() -> TrustContext {
        TrustContext {
            scope: Scope {
                chain_id: 1,
                protocol_address: U256::from(2),
            },
            chain_generation: 4,
            provider_id: U256::from(5),
            signing_keys: BTreeMap::from([(U256::from(6), [0u8; 32])]),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: "a".repeat(64),
        }
    }
    fn server(result: Value) -> (String, std::thread::JoinHandle<()>) {
        server_checked(result, None)
    }
    fn server_checked(
        result: Value,
        expected_scope: Option<U256>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 8192];
            let size = stream.read(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..size]);
            assert!(request.starts_with("POST /v1/chains/1 HTTP/1.1"));
            assert!(!request.contains("witness"));
            if result.get("tracking").is_some() {
                let body = request.split("\r\n\r\n").nth(1).unwrap();
                let query: Value = serde_json::from_str(body).unwrap();
                assert_eq!(query["method"], "provenance_getTracking");
                assert_eq!(
                    query["params"],
                    json!([{"trackingId":result["tracking"]["id"]}])
                );
            }
            if expected_scope.is_some() {
                let body = request.split("\r\n\r\n").nth(1).unwrap();
                let query: Value = serde_json::from_str(body).unwrap();
                assert_eq!(query["params"], json!([{}]));
            }
            let body = json!({"jsonrpc":"2.0","id":1,"result":result}).to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        });
        (endpoint, task)
    }
    #[test]
    fn metadata_rejects_another_scope() {
        for policy in [3u64, 7] {
            for method in ["provenance_getVersion", "provenance_getStatus"] {
                for wrong in [false, true] {
                    let context = trust();
                    let response_chain = if wrong { "9" } else { "1" };
                    let (endpoint, task) = server_checked(
                        json!({"scope":{"chainId":response_chain,"protocolAddress":"2"},"chainGeneration":"4"}),
                        Some(U256::from(policy)),
                    );
                    let client = ProvenanceClient::new(&endpoint, context).unwrap();
                    let result = if method == "provenance_getVersion" {
                        client.get_version()
                    } else {
                        client.get_status()
                    };
                    assert_eq!(result.is_ok(), !wrong);
                    task.join().unwrap();
                }
            }
        }
    }
    #[test]
    fn wait_job_stale_generation_terminates_and_unknown_status_fails_immediately() {
        for status in ["stale_generation", "unknown_status"] {
            let mut context = trust();
            context.chain_generation = 2;
            let (endpoint, task) = server(
                json!({"scope":{"chainId":"1","protocolAddress":"2"},"chainGeneration":"2","providerId":"5","signingKeyId":"6","manifestSha256":"a".repeat(64),"status":status}),
            );
            let client = ProvenanceClient::new(&endpoint, context).unwrap();
            let result =
                client.wait_proof_job("job", Duration::from_millis(1), Duration::from_millis(20));
            if status == "stale_generation" {
                assert_eq!(result.unwrap()["status"], status)
            } else {
                assert!(result.unwrap_err().contains("status"));
            }
            task.join().unwrap();
        }
    }
    #[test]
    fn tracking_terminal_wire_is_scoped_and_rejects_stale_unknown() {
        for status in [
            "recognized",
            "expired",
            "superseded",
            "stale_generation",
            "unknown",
        ] {
            let context = trust();
            let id = "a".repeat(48);
            let mut tracking = json!({"id":id,"status":status,"expiresAt":"1","operationDigest":format!("0x{:064x}",9)});
            if status == "recognized" {
                tracking["matched"] = json!({"txHash":format!("0x{:064x}",1),"blockHash":format!("0x{:064x}",2),"operationIndex":"0"});
            }
            let (endpoint, task) = server_checked(
                json!({"scope":{"chainId":"1","protocolAddress":"2"},"chainGeneration":"4","providerId":"5","signingKeyId":"6","manifestSha256":"a".repeat(64),"tracking":tracking}),
                None,
            );
            let c = ProvenanceClient::new(&endpoint, context).unwrap();
            let result = c.wait_tracking(&id, Duration::from_millis(1), Duration::from_millis(20));
            if ["unknown", "stale_generation"].contains(&status) {
                assert!(result.is_err())
            } else {
                assert_eq!(result.unwrap()["tracking"]["status"], status)
            }
            task.join().unwrap();
        }
    }
    #[test]
    fn public_transport_and_scope_fence() {
        for generation in ["4", "9"] {
            let (endpoint, task) = server(
                json!({"scope":{"chainId":"1","protocolAddress":"2"},"chainGeneration":generation}),
            );
            let c = ProvenanceClient::new(&endpoint, trust()).unwrap();
            assert_eq!(c.get_status().is_ok(), generation == "4");
            task.join().unwrap();
        }
    }
    #[test]
    fn membership_queries_require_explicit_interest_disclosure() {
        let c = ProvenanceClient::new("https://example.test", trust()).unwrap();
        assert!(c
            .get_membership(U256::from(1), "1:1", false)
            .unwrap_err()
            .contains("interest"));
        assert_eq!(c.sequence.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn policy_history_does_not_trust_reported_current_key() {
        for method in ["policy", "status"] {
            let (endpoint, task) = server(
                json!({"scope":{"chainId":"1","protocolAddress":"2"},"chainGeneration":"4","providerId":"5","signingKeyId":"7","manifestSha256":"a".repeat(64),"keyRotations":[]}),
            );
            let c = ProvenanceClient::new(&endpoint, trust()).unwrap();
            if method == "policy" {
                assert!(c.get_rules().is_ok());
                assert!(!c.trust.signing_keys.contains_key(&U256::from(7)));
            } else {
                assert!(c.get_status().is_err());
            }
            task.join().unwrap();
        }
    }
    #[test]
    fn missing_preflight_identity_fails_closed() {
        let (endpoint, task) = server(
            json!({"scope":{"chainId":"1","protocolAddress":"2"},"chainGeneration":"4","broadcastDecision":"allow"}),
        );
        let c = ProvenanceClient::new(&endpoint, trust()).unwrap();
        assert!(c
            .evaluate_transaction(json!({"calldata":"0x12"}), &[])
            .is_err());
        task.join().unwrap();
    }
}

impl ProvenanceClient {
    pub fn get_membership(
        &self,
        commitment: U256,
        root_id: &str,
        allow_interest_disclosure: bool,
    ) -> Result<Value, String> {
        use invisi_sdk_protocol::provenance::{recognized_leaf, scope_hash};
        if !allow_interest_disclosure {
            return Err("membership lookup requires explicit interest disclosure".into());
        }
        invisi_sdk_primitives::note::field(commitment, "commitment").map_err(|e| e.to_string())?;
        let result=self.call("provenance_getMembership",Some(self.query(json!({"rootId":root_id,"commitment":format!("0x{}",hex::encode(commitment.to_be_bytes::<32>()))}))))?;
        let cert: RootCertificate =
            serde_json::from_value(result["certificate"].clone()).map_err(|e| e.to_string())?;
        assert_certificate_trust(&cert, &self.trust).map_err(|e| e.to_string())?;
        let read = |value: &Value, bits| {
            parse_integer(value.as_str().ok_or("invalid membership field")?, bits)
                .map_err(|e| e.to_string())
        };
        let path = result["path"].as_array().ok_or("missing membership path")?;
        if path.len() != 32 || read(&result["commitment"], 256)? != commitment {
            return Err("invalid membership response".into());
        }
        let index = read(&result["leafIndex"], 32)?.to::<u32>();
        if U256::from(index) >= parse_integer(&cert.leaf_count, 64).map_err(|e| e.to_string())? {
            return Err("membership index outside certified prefix".into());
        }
        let mut leaf = recognized_leaf(
            scope_hash(&self.trust.scope).map_err(|e| e.to_string())?,
            commitment,
        )
        .map_err(|e| e.to_string())?;
        for (level, value) in path.iter().enumerate() {
            let sibling = read(value, 256)?;
            let nodes = if (index >> level) & 1 == 0 {
                [leaf, sibling]
            } else {
                [sibling, leaf]
            };
            leaf = invisi_sdk_primitives::note::hash_fields(&nodes).map_err(|e| e.to_string())?;
        }
        if leaf != parse_integer(&cert.root, 256).map_err(|e| e.to_string())? {
            return Err("membership root mismatch".into());
        }
        Ok(result)
    }
}
