//! Relay configuration is attached before authorization; failed candidates leave the original usable.
use super::*;
use invisi_sdk_core::provenance::{
    self as source, ManifestIdentity, OfflineProver, Opening, ProofSidecar, RootCertificate,
    Source, WitnessInput, WitnessRequest,
};
#[cfg(test)]
use invisi_sdk_rpc::provenance_tracking::Tracking;
use invisi_sdk_rpc::rpc::RpcTransport;
use invisi_sdk_rpc::{
    broadcaster::{
        request_hash, BroadcasterClient, Configuration, Fee as RelayFee, SignedQuote,
        Status as RelayStatus, Trust, VerifiedQuote,
    },
    provenance_client::ProvenanceClient,
};

#[derive(Clone)]
pub struct PreparedProvenance {
    pub client: Arc<ProvenanceClient>,
    pub manifest: ManifestIdentity,
    pub prover: Arc<dyn OfflineProver + Send + Sync>,
    pub budgets: SourceReplayBudgets,
}
/// This file-backed configuration contains public pins and local executable/asset paths only.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalProvenanceConfiguration {
    #[serde(default = "default_source_endpoint")]
    pub endpoint: String,
    pub chain_id: String,
    pub protocol_address: String,
    pub generation: String,
    pub provider_id: String,
    pub signing_key_id: String,
    pub signing_public_key: String,
    pub manifest_sha256: String,
    pub asset_root: std::path::PathBuf,
    pub bb_binary: std::path::PathBuf,
    pub noir_executor: std::path::PathBuf,
    pub timeout_seconds: u64,
    pub threads: usize,
    pub budgets: SourceReplayBudgets,
}
fn default_source_endpoint() -> String {
    invisi_sdk_rpc::provenance_client::DEFAULT_ENDPOINT.into()
}
impl PreparedProvenance {
    pub fn from_local_configuration(c: LocalProvenanceConfiguration) -> Result<Self> {
        if c.timeout_seconds == 0 || c.threads == 0 {
            return Err("positive local prover options required".into());
        }
        let manifest = source::authenticate_manifest(
            &std::fs::read(c.asset_root.join("manifest.json"))
                .map_err(|_| "local source manifest unavailable")?,
            &c.manifest_sha256,
        )
        .map_err(|e| e.to_string())?;
        let public_key: [u8; 32] = hex_bytes(&c.signing_public_key, Some(32))?
            .try_into()
            .map_err(|_| "signing key width")?;
        use sha2::Digest;
        let key_id = source_word(&c.signing_key_id)?;
        if U256::from_be_slice(&sha2::Sha256::digest(public_key)) != key_id {
            return Err("source signing key ID mismatch".into());
        }
        let trust = source::TrustContext {
            scope: source::Scope {
                chain_id: source_number(&c.chain_id)?,
                protocol_address: source_word(&c.protocol_address)?,
            },
            chain_generation: source_number(&c.generation)?,
            provider_id: source_word(&c.provider_id)?,
            signing_keys: BTreeMap::from([(key_id, public_key)]),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: c.manifest_sha256.clone(),
        };
        let timeout = std::time::Duration::from_secs(c.timeout_seconds);
        Ok(Self {
            client: Arc::new(ProvenanceClient::new(&c.endpoint, trust)?),
            manifest,
            prover: Arc::new(prover::NativeSourceProver {
                directory: c.asset_root,
                manifest_sha256: c.manifest_sha256,
                bb_binary: c.bb_binary,
                timeout,
                threads: c.threads,
                witness_executor: Arc::new(prover::NoirCli {
                    binary: c.noir_executor,
                    timeout,
                }),
            }),
            budgets: c.budgets,
        })
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReplayBudgets {
    pub max_root_pages: usize,
    pub max_certificates: usize,
    pub max_total_leaves: u64,
}
impl Default for SourceReplayBudgets {
    fn default() -> Self {
        Self {
            max_root_pages: 16,
            max_certificates: 3200,
            max_total_leaves: 1_000_000,
        }
    }
}
#[derive(Clone, Debug)]
pub struct BroadcasterOptions {
    pub max_fee_rounds: usize,
    pub max_fee_amount: Option<U256>,
}
impl Default for BroadcasterOptions {
    fn default() -> Self {
        Self {
            max_fee_rounds: 8,
            max_fee_amount: None,
        }
    }
}
#[derive(Clone)]
pub(crate) enum RepriceTemplate {
    Transfer(TransferPreparation),
    Shield(ShieldPreparation),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedBroadcasterState {
    pub endpoint: String,
    pub signer: Address,
    pub fee_recipient: Address,
    pub quote: SignedQuote,
    pub intent_hash: B256,
    pub sidecars: Vec<ProofSidecar>,
    #[serde(default)]
    pub attempted: bool,
    #[serde(default)]
    pub submission_id: Option<String>,
    #[serde(default)]
    pub submitted_data: Vec<u8>,
}
impl PreparedBroadcasterState {
    pub fn provenance_mode(&self) -> Option<()> {
        (self.quote.provenance_required == Some(true)).then_some(())
    }
}
pub trait PreparedBroadcaster: Send + Sync {
    fn lookup_status(&self, _id: &str) -> Result<Option<RelayStatus>> {
        Err("broadcaster status lookup capability required".into())
    }
    fn configuration(&self) -> Configuration;
    fn provenance_mode(&self) -> Option<()>;
    fn submission_requirements(&self, quote: &VerifiedQuote) -> Result<bool>;
    fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<RelayFee>;
    fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> Result<VerifiedQuote>;
    fn submit(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> Result<RelayStatus>;
}
impl<T: RpcTransport + Send + Sync> PreparedBroadcaster for BroadcasterClient<T> {
    fn lookup_status(&self, id: &str) -> Result<Option<RelayStatus>> {
        BroadcasterClient::lookup_status(self, id).map_err(|e| e.to_string())
    }
    fn submission_requirements(&self, quote: &VerifiedQuote) -> Result<bool> {
        BroadcasterClient::submission_requirements(self, quote).map_err(|e| e.to_string())
    }
    fn configuration(&self) -> Configuration {
        BroadcasterClient::configuration(self).clone()
    }
    fn provenance_mode(&self) -> Option<()> {
        BroadcasterClient::provenance_mode(self)
    }
    fn fee(&self, t: Address, d: Option<&[u8]>) -> Result<RelayFee> {
        BroadcasterClient::fee(self, t, d).map_err(|e| e.to_string())
    }
    fn quote(
        &self,
        d: &[u8],
        c: u64,
        p: Address,
        n: u64,
        s: &[ProofSidecar],
    ) -> Result<VerifiedQuote> {
        self.quote_with_sidecars(d, c, p, n, s)
            .map_err(|e| e.to_string())
    }
    fn submit(&self, d: &[u8], q: &VerifiedQuote, s: &[ProofSidecar]) -> Result<RelayStatus> {
        self.submit_with_sidecars(d, q, s)
            .map_err(|e| e.to_string())
    }
}
impl Invisi {
    pub fn with_provenance(mut self, capability: Arc<PreparedProvenance>) -> Result<Self> {
        capability.validate(self.chain.context(), None)?;
        self.provenance = Some(capability);
        Ok(self)
    }
}
impl PreparedProvenance {
    pub(crate) fn validate(&self, context: ProtocolContext, _provenance: Option<()>) -> Result<()> {
        let t = &self.client.trust;
        if t.scope.chain_id != context.chain_id
            || t.scope.protocol_address != context.protocol_address
            || t.manifest_sha256 != self.manifest.sha256
        {
            return Err("provenance capability deployment/provenance/manifest mismatch".into());
        }
        if self.budgets.max_root_pages == 0
            || self.budgets.max_certificates == 0
            || self.budgets.max_total_leaves == 0
        {
            return Err("positive source replay budgets required".into());
        }
        Ok(())
    }
}
impl PreparedTransaction {
    pub fn broadcaster_state(&self) -> Option<&PreparedBroadcasterState> {
        self.broadcaster.as_ref()
    }
    pub fn reattach_provenance(mut self, capability: Arc<PreparedProvenance>) -> Result<Self> {
        capability.validate(
            self.context,
            self.broadcaster.as_ref().and_then(|s| s.provenance_mode()),
        )?;
        self.provenance = Some(capability);
        Ok(self)
    }
    pub fn with_broadcaster(
        &self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> Result<Self> {
        if options.max_fee_amount.is_none_or(|cap| cap == U256::ZERO) {
            return Err("positive maximum broadcaster fee required".into());
        }
        if self.phase != Phase::Prepared
            || self.target != "evm"
            || chain.context() != self.context
            || options.max_fee_rounds == 0
        {
            return Err("broadcaster requires unsigned EVM preparation and matching chain".into());
        }
        let config = relay.configuration();
        config.validate().map_err(|e| e.to_string())?;
        let provenance = relay.provenance_mode();
        if provenance.is_some() && !self.inputs().is_empty() {
            self.provenance
                .as_ref()
                .ok_or("provenance capability required")?
                .validate(self.context, provenance)?;
        }
        let template = self
            .reprice
            .as_ref()
            .ok_or("original business preparation required for explicit repricing")?;
        let runtime = Invisi {
            chain: chain.clone(),
            provenance: self.provenance.clone(),
        };
        let mut fee = RelayFee {
            fee_recipient: config.fee_recipient,
            fee_amount: "1".into(),
            max_gas: "1".into(),
        };
        let mut final_candidate = None;
        for round in 0..options.max_fee_rounds {
            let amount = decimal(&json!(fee.fee_amount))?;
            if options.max_fee_amount.is_some_and(|cap| amount > cap) {
                return Err("broadcaster fee exceeds maximum".into());
            }
            if fee.fee_recipient != config.fee_recipient || amount == U256::ZERO {
                return Err("broadcaster fee recipient/bounds mismatch".into());
            }
            let f = Fee {
                recipient: fee.fee_recipient,
                amount,
            };
            let mut candidate = match template {
                RepriceTemplate::Transfer(p) => {
                    let mut p = p.clone();
                    p.fee = f;
                    runtime.prepare_transfer(&self.wallet, p)?
                }
                RepriceTemplate::Shield(p) => {
                    let mut p = p.clone();
                    p.fee = f;
                    p.funding.amount = sum(p.outputs.iter().map(|o| o.amount))?
                        .checked_add(amount)
                        .ok_or("funding overflow")?;
                    runtime.prepare_shield(&self.wallet, p)?
                }
            };
            if candidate.funding().amount != U256::ZERO {
                let deadline = match &candidate.plan {
                    Plan::Transfer { params, .. } => params.deadline,
                    Plan::Shield { params, .. } => params.deadline,
                };
                candidate = candidate.with_funding_terms(chain.as_ref(), deadline.to::<u64>())?;
            }
            let data = candidate.broadcaster_intent()?.data;
            let next = relay.fee(self.token, Some(&data))?;
            if round > 0
                && next.fee_amount == fee.fee_amount
                && next.fee_recipient == fee.fee_recipient
            {
                final_candidate = Some(candidate);
                break;
            }
            fee = next;
        }
        let mut candidate = final_candidate.ok_or("broadcaster fee convergence budget exceeded")?;
        let data = candidate.broadcaster_intent()?.data;
        let sidecars = Vec::new();
        let block = chain.snapshot()?;
        let quote = relay.quote(
            &data,
            candidate.context.chain_id,
            word_address(candidate.context.protocol_address)?,
            block.timestamp,
            &sidecars,
        )?;
        invisi_sdk_rpc::broadcaster::verify_quote_for_provenance(
            quote.signed(),
            &Trust {
                chain_id: candidate.context.chain_id,
                protocol: word_address(candidate.context.protocol_address)?,
                signer: config.quote_signer,
            },
            &data,
            block.timestamp,
            provenance,
        )
        .map_err(|e| e.to_string())?;
        chain.canonical(&block)?;
        candidate.broadcaster = Some(PreparedBroadcasterState {
            endpoint: config.endpoint,
            signer: config.quote_signer,
            fee_recipient: config.fee_recipient,
            quote: quote.signed().clone(),
            intent_hash: request_hash(&data).map_err(|e| e.to_string())?,
            sidecars,
            attempted: false,
            submission_id: None,
            submitted_data: Vec::new(),
        });
        Ok(candidate)
    }
    pub fn freeze_broadcaster_evidence(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<()> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        let data = self.calldata(chain, Address::ZERO)?.data;
        let verified = VerifiedQuote::authenticate(
            saved.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: saved.signer,
            },
            &data,
            chain.snapshot()?.timestamp,
            saved.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        let required = relay.submission_requirements(&verified)?;
        if required != (verified.signed().provenance_required == Some(true)) {
            return Err("broadcaster provenance requirements changed".into());
        }
        let cache_valid = self.provenance.as_ref().is_some_and(|cap| {
            !saved.sidecars.is_empty()
                && saved.sidecars.iter().all(|s| {
                    source::validate_proof_bundle(&s.proof_bundle, &cap.client.trust).is_ok()
                })
        });
        if required && !self.inputs().is_empty() && !cache_valid {
            let cap = self
                .provenance
                .as_ref()
                .ok_or("trusted provenance capability required")?;
            let sidecar = self.build_source_sidecar(chain, cap)?.0;
            self.broadcaster.as_mut().unwrap().sidecars = vec![sidecar];
        }
        if required && !self.inputs().is_empty() {
            let cap = self
                .provenance
                .as_ref()
                .ok_or("trusted provenance capability required")?;
            let capacity = match &self.plan {
                Plan::Transfer { capacity, .. } => *capacity,
                _ => return Err("private Note transfer required".into()),
            };
            let public = self.public_inputs()?;
            let digest = U256::from_be_bytes(model(source::operation_digest(
                &cap.client.trust.scope,
                capacity,
                &public,
            ))?);
            let nfs = self
                .inputs()
                .iter()
                .map(|i| model(i.note.nullifier()))
                .collect::<Result<Vec<_>>>()?;
            let saved = self.broadcaster.as_ref().unwrap();
            if saved.sidecars.len() != 1 {
                return Err("one Source sidecar required".into());
            }
            let sidecar = &saved.sidecars[0];
            let pi = &sidecar.proof_bundle.public_inputs;
            if sidecar.operation_index != "0"
                || pi.len() != 11
                || ((source_word(&pi[7])? << 128) | source_word(&pi[8])?) != digest
                || source_word(&pi[9])? != model(source::input_digest(&nfs))?
            {
                return Err("saved Source statement mismatch".into());
            }
        }
        Ok(())
    }
    pub fn submit_broadcaster(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<RelayStatus> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        let config = relay.configuration();
        if saved.endpoint != config.endpoint
            || saved.signer != config.quote_signer
            || saved.fee_recipient != config.fee_recipient
        {
            return Err("broadcaster saved configuration mismatch".into());
        }
        if let Some(saved) = self.broadcaster.as_ref().filter(|s| s.attempted).cloned() {
            if let Some(id) = &saved.submission_id {
                if let Some(status) = relay.lookup_status(id)? {
                    if &status.id != id {
                        return Err("broadcaster submission ID mismatch".into());
                    }
                    return Ok(status);
                }
            }
            let verified = VerifiedQuote::authenticate(
                saved.quote.clone(),
                Trust {
                    chain_id: self.context.chain_id,
                    protocol: word_address(self.context.protocol_address)?,
                    signer: saved.signer,
                },
                &saved.submitted_data,
                0,
                saved.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            let result = relay.submit(&saved.submitted_data, &verified, &saved.sidecars)?;
            if saved
                .submission_id
                .as_ref()
                .is_some_and(|id| id != &result.id)
            {
                return Err("broadcaster submission ID mismatch".into());
            }
            self.broadcaster.as_mut().unwrap().submission_id = Some(result.id.clone());
            return Ok(result);
        }
        self.freeze_broadcaster_evidence(chain, relay)?;
        let s = self
            .broadcaster
            .as_ref()
            .ok_or("prepared broadcaster context required")?;
        let c = relay.configuration();
        if c.endpoint != s.endpoint
            || c.quote_signer != s.signer
            || c.fee_recipient != s.fee_recipient
        {
            return Err("broadcaster saved configuration mismatch".into());
        }
        let block = chain.snapshot()?;
        let data = self.calldata(chain, Address::ZERO)?.data;
        if request_hash(&data).map_err(|e| e.to_string())? != s.intent_hash {
            return Err("frozen broadcaster intent mismatch".into());
        }
        let generated;
        let sidecars = if s.provenance_mode().is_some()
            && !self.inputs().is_empty()
            && s.sidecars.is_empty()
        {
            generated = vec![
                self.build_source_sidecar(
                    chain,
                    self.provenance
                        .as_ref()
                        .ok_or("trusted provenance capability required")?,
                )?
                .0,
            ];
            &generated
        } else {
            &s.sidecars
        };
        if !sidecars.is_empty() {
            let cap = self
                .provenance
                .as_ref()
                .ok_or("reattach trusted provenance capability before submission")?;
            cap.validate(self.context, s.provenance_mode())?;
            for sidecar in sidecars {
                source::validate_proof_bundle(&sidecar.proof_bundle, &cap.client.trust)
                    .map_err(|e| e.to_string())?;
                let capacity = match &self.plan {
                    Plan::Transfer { capacity, .. } => *capacity,
                    _ => return Err("unexpected shield source proof".into()),
                };
                let digest = model(source::operation_digest(
                    &cap.client.trust.scope,
                    capacity,
                    &self.public_inputs()?,
                ))?;
                let pi = &sidecar.proof_bundle.public_inputs;
                let actual = (source_word(&pi[7])? << 128) | source_word(&pi[8])?;
                let nfs = self
                    .inputs()
                    .iter()
                    .map(|i| model(i.note.nullifier()))
                    .collect::<Result<Vec<_>>>()?;
                if sidecar.operation_index != "0"
                    || actual != U256::from_be_bytes(digest)
                    || source_word(&pi[9])? != model(source::input_digest(&nfs))?
                {
                    return Err("saved sidecar statement mismatch".into());
                }
            }
        }
        let quote = VerifiedQuote::authenticate(
            s.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: s.signer,
            },
            &data,
            block.timestamp,
            s.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        chain.canonical(&block)?;
        let frozen_sidecars = sidecars.to_vec();
        let saved = self.broadcaster.as_mut().unwrap();
        saved.sidecars = frozen_sidecars.clone();
        saved.submitted_data = data.clone();
        saved.attempted = true;
        let result = relay.submit(&data, &quote, &frozen_sidecars)?;
        self.broadcaster.as_mut().unwrap().submission_id = Some(result.id.clone());
        Ok(result)
    }
    pub fn prove_provenance(&self, chain: &dyn ChainState) -> Result<source::ProvenanceProof> {
        let cap = self
            .provenance
            .as_ref()
            .ok_or("trusted provenance capability required")?;
        let data = self.provenance_calldata()?;
        let (sidecar, digest) = self.build_source_sidecar(chain, cap)?;
        let capacity = match &self.plan {
            Plan::Transfer { capacity, .. } => *capacity,
            _ => return Err("private Note transaction required".into()),
        };
        let packet = source::ProvenanceProof {
            format: "invisi-provenance-submission-v1".into(),
            data: hex(&data),
            context: source::ProofContext {
                chain_id: self.context.chain_id.to_string(),
                protocol_address: hex(word_address(self.context.protocol_address)?.as_slice()),
                token_address: hex(self.token.as_slice()),
            },
            main_circuit_capacity: capacity,
            public_inputs: self
                .public_inputs()?
                .iter()
                .map(|v| hex(&v.to_be_bytes::<32>()))
                .collect(),
            operation_digest: digest,
            sidecars: vec![sidecar],
        };
        invisi_sdk_rpc::provenance_packet::validate_provenance_proof(&packet, &cap.client.trust)?;
        Ok(packet)
    }
    fn provenance_calldata(&self) -> Result<Vec<u8>> {
        if self.target != "evm" {
            return Err("ready EVM transaction required for provenance".into());
        }
        let proof = self
            .proof
            .as_ref()
            .ok_or("ready transaction proof required for provenance")?;
        let Plan::Transfer {
            params,
            outputs,
            funding,
            ..
        } = &self.plan
        else {
            return Err("private Note transaction required".into());
        };
        let statement = prover::statement(
            &proof.circuit_name,
            "evm",
            self.public_inputs()?.into_iter().map(field_word).collect(),
        )?;
        prover::assert_bundle(proof, &statement)?;
        Ok(InvisiProtocol::transact_0Call {
            _0: proof.proof.clone().into(),
            r: abi::TransactRequest {
                params: params.clone(),
                deliveries: outputs.iter().map(|v| v.delivery.clone()).collect(),
                funding: funding.clone(),
            },
        }
        .abi_encode())
    }
    fn build_source_sidecar(
        &self,
        chain: &dyn ChainState,
        cap: &PreparedProvenance,
    ) -> Result<(ProofSidecar, String)> {
        cap.validate(
            self.context,
            self.broadcaster.as_ref().and_then(|s| s.provenance_mode()),
        )?;
        let (main_capacity, nfs) = match &self.plan {
            Plan::Transfer {
                capacity, params, ..
            } => (*capacity, &params.nullifiers),
            _ => return Err("private Note transaction required".into()),
        };
        let scope = &cap.client.trust.scope;
        if nfs.len() != self.inputs().len() {
            return Err("main input count mismatch".into());
        }
        for (input, nf) in self.inputs().iter().zip(nfs) {
            if field_word(model(input.note.nullifier())?) != *nf {
                return Err("main nullifier order mismatch".into());
            }
        }
        let public = self.public_inputs()?;
        let digest = model(source::operation_digest(scope, main_capacity, &public))?;
        let status = cap.client.get_status()?;
        let sequence = status["checkpointSequence"]
            .as_str()
            .ok_or("missing latest checkpoint sequence")?;
        if source::parse_integer(sequence, 64).map_err(|e| e.to_string())? == U256::ZERO {
            return Err("no recognized source checkpoint".into());
        }
        let root_id = format!("{}:{}", cap.client.trust.chain_generation, sequence);
        let latest = cap.client.get_root(&root_id)?;
        if latest["allowedForNewProof"] != true {
            return Err("latest source root not acceptable".into());
        }
        let cert: RootCertificate =
            serde_json::from_value(latest["certificate"].clone()).map_err(|e| e.to_string())?;
        let mut certificates = BTreeMap::<u64, RootCertificate>::new();
        let tree_id = source_number(&cert.tree_id)?;
        certificates.insert(tree_id, cert);
        let mut trees = BTreeMap::new();
        let mut consumed = 0u64;
        replay_sources(chain, cap, &certificates, &mut trees, &mut consumed)?;
        if !all_source_inputs(self, scope, &trees)? {
            let mut cursor = status["treeDirectoryCursor"].as_str().map(str::to_owned);
            let mut seen = 1usize;
            for _ in 0..cap.budgets.max_root_pages {
                let mut query = json!({"limit":200});
                if let Some(c) = &cursor {
                    query["cursor"] = json!(c);
                }
                let page = cap.client.get_roots(query)?;
                for value in page["items"].as_array().ok_or("missing root items")? {
                    seen += 1;
                    if seen > cap.budgets.max_certificates {
                        return Err("source certificate replay budget exceeded".into());
                    }
                    let cert: RootCertificate =
                        serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                    let current = cap
                        .client
                        .get_root(&format!("{}:{}", cert.chain_generation, cert.root_sequence))?;
                    if current["allowedForNewProof"] != true {
                        continue;
                    }
                    let tree = source_number(&cert.tree_id)?;
                    if source_number(&cert.chain_generation)? != cap.client.trust.chain_generation {
                        continue;
                    }
                    let newer = certificates
                        .get(&tree)
                        .map(|old| {
                            source_number(&cert.root_sequence).unwrap_or(0)
                                > source_number(&old.root_sequence).unwrap_or(0)
                        })
                        .unwrap_or(true);
                    if newer {
                        certificates.insert(tree, cert);
                    }
                }
                cursor = page["nextCursor"].as_str().map(str::to_owned);
                if cursor.is_none() {
                    break;
                }
            }
            if cursor.is_some() {
                return Err("source root history page budget exceeded".into());
            }
            replay_sources(chain, cap, &certificates, &mut trees, &mut consumed)?;
        }
        if !all_source_inputs(self, scope, &trees)? {
            return Err("prepared inputs are not locally source recognized".into());
        }
        let mut used = BTreeSet::new();
        let mut selected = Vec::new();
        for input in self.inputs() {
            let commitment = model(input.note.commitment())?;
            let mut found = None;
            for (id, tree) in &trees {
                if let Some(m) = model(tree.membership_for_commitment(scope, commitment))? {
                    found = Some((*id, m));
                    break;
                }
            }
            let pair = found.ok_or("source membership missing")?;
            used.insert(pair.0);
            selected.push(pair);
        }
        let ids: Vec<u64> = used.into_iter().collect();
        let certs: Vec<RootCertificate> = ids.iter().map(|id| certificates[id].clone()).collect();
        let sources = certs
            .iter()
            .map(|c| {
                Ok(Source {
                    tree_id: source_number(&c.tree_id)?,
                    root: source_word(&c.root)?,
                    leaf_count: source_number(&c.leaf_count)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let inputs = self
            .inputs()
            .iter()
            .zip(selected)
            .map(|(i, (id, m))| WitnessInput {
                opening: Opening {
                    owner: i.note.owner_address,
                    nonce: i.note.nonce,
                    amount: i.note.amount,
                },
                source_index: ids.iter().position(|v| *v == id).unwrap(),
                leaf_index: m.leaf_index,
                path: m.path,
            })
            .collect();
        let capacity = cap
            .manifest
            .manifest
            .circuits
            .iter()
            .map(|c| c.capacity)
            .filter(|c| *c >= self.inputs().len())
            .min()
            .ok_or("source capacity unavailable")?;
        let request = WitnessRequest {
            scope: scope.clone(),
            capacity,
            token_address: address_word(self.token),
            chain_generation: cap.client.trust.chain_generation,
            operation_digest: U256::from_be_bytes(digest),
            inputs,
            sources,
        };
        let sidecar = model(source::export_sidecar(
            &request,
            &certs,
            &cap.client.trust,
            &cap.manifest,
            cap.prover.as_ref(),
            0,
        ))?;
        Ok((sidecar, hex(&digest)))
    }
}
#[cfg(test)]
fn trusted_quote_tracking(
    received: Option<Tracking>,
    digest: &str,
    client: &ProvenanceClient,
) -> Result<Tracking> {
    let received = received.ok_or("Broadcaster source tracking required")?;
    let ack = json!({"broadcastDecision":"allow","operationDigest":digest,"tracking":received});
    let received = invisi_sdk_rpc::provenance_tracking::preflight_tracking(&ack, "0", digest)?;
    let current = client.get_tracking(&received.id)?;
    let current =
        invisi_sdk_rpc::provenance_tracking::tracking_from_result(&current, Some(&received.id))?;
    let checked = json!({"broadcastDecision":"allow","operationDigest":digest,"tracking":current});
    invisi_sdk_rpc::provenance_tracking::preflight_tracking(&checked, "0", digest)
}
fn source_word(raw: &str) -> Result<U256> {
    source::parse_integer(raw, 256).map_err(|e| e.to_string())
}
fn source_number(raw: &str) -> Result<u64> {
    source::parse_integer(raw, 64)
        .map(|n| n.to::<u64>())
        .map_err(|e| e.to_string())
}
fn all_source_inputs(
    p: &PreparedTransaction,
    scope: &source::Scope,
    trees: &BTreeMap<u64, source::RecognizedTree>,
) -> Result<bool> {
    for i in p.inputs() {
        let c = model(i.note.commitment())?;
        let mut found = false;
        for tree in trees.values() {
            if model(tree.membership_for_commitment(scope, c))?.is_some() {
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}
fn replay_sources(
    chain: &dyn ChainState,
    cap: &PreparedProvenance,
    certs: &BTreeMap<u64, RootCertificate>,
    trees: &mut BTreeMap<u64, source::RecognizedTree>,
    consumed: &mut u64,
) -> Result<()> {
    for (id, c) in certs {
        model(source::assert_certificate_trust(c, &cap.client.trust))?;
        if trees
            .get(id)
            .is_some_and(|t| t.root().ok() == source_word(&c.root).ok())
        {
            continue;
        }
        let count = source_number(&c.leaf_count)?;
        *consumed = consumed
            .checked_add(count)
            .ok_or("source leaf budget overflow")?;
        if *consumed > cap.budgets.max_total_leaves {
            return Err("source total replay leaf budget exceeded".into());
        }
        let anchor = CanonicalBlock {
            number: source_number(&c.confirmed_block_number)?,
            hash: B256::from(source_word(&c.confirmed_block_hash)?.to_be_bytes::<32>()),
            parent_hash: B256::ZERO,
            timestamp: 0,
        };
        chain.canonical(&anchor)?;
        let id_root = format!("{}:{}", c.chain_generation, c.root_sequence);
        let tree = cap.client.sync_recognized_tree(&id_root, c, count.max(1))?;
        chain.canonical(&anchor)?;
        trees.insert(*id, tree);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{test_support::note_fixture, *};
    use super::*;
    #[test]
    fn original_preparation_survives_missing_provenance_capability() {
        let (chain, wallet, p, _) = note_fixture();
        let prepared = Invisi::new(chain.clone())
            .prepare_transfer(&wallet, p)
            .unwrap();
        let relay = Arc::new(MissingCapabilityRelay);
        assert!(prepared
            .with_broadcaster(
                chain,
                relay,
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                }
            )
            .is_err());
        assert_eq!(prepared.phase(), Phase::Prepared);
        assert!(prepared.broadcaster_state().is_none());
    }
    #[test]
    fn fee_convergence_attaches_only_final_signed_intent_and_freezes_funding() {
        let (chain, wallet, p, _) = note_fixture();
        let output =
            NoteOutput::identity(chain.context, p.token, U256::from(123), U256::from(20)).unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
            )
            .unwrap();
        let relay = Arc::new(SignedRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            quotes: std::sync::atomic::AtomicUsize::new(0),
        });
        let capped = Arc::new(SignedRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            quotes: std::sync::atomic::AtomicUsize::new(0),
        });
        assert!(prepared
            .with_broadcaster(
                chain.clone(),
                capped.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(1)),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .contains("maximum"));
        assert!(prepared.broadcaster_state().is_none());
        assert_eq!(capped.quotes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(prepared
            .with_broadcaster(chain.clone(), relay.clone(), &BroadcasterOptions::default())
            .unwrap_err()
            .contains("maximum"));
        let quoted = prepared
            .with_broadcaster(
                chain.clone(),
                relay.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(relay.fees.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(relay.quotes.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(prepared.broadcaster_state().is_none());
        assert_eq!(prepared.funding().amount, U256::from(20));
        assert_eq!(quoted.funding().amount, U256::from(22));
        assert_eq!(
            quoted.broadcaster_state().unwrap().quote.quote.fee_amount,
            "2"
        );
        assert!(quoted
            .clone()
            .with_funding_terms(chain.as_ref(), 99)
            .is_err());
        let mut attempted = quoted.clone();
        let data = attempted.broadcaster_intent().unwrap().data;
        let retained = attempted.broadcaster.as_mut().unwrap();
        retained.attempted = true;
        retained.submitted_data = data.clone();
        retained.sidecars = vec![ProofSidecar {
            operation_index: "0".into(),
            proof_bundle: source::ProofBundle {
                format: "retained".into(),
                circuit_id: "provenance_k10".into(),
                manifest_sha256: "pin".into(),
                target: "evm".into(),
                public_inputs: vec![],
                proof: "0xab".into(),
                root_certificates: vec![],
            },
        }];
        let mut source_state = retained.clone();
        source_state.quote.provenance_required = Some(true);
        let encoded = serde_json::to_vec(&source_state).unwrap();
        let restored: PreparedBroadcasterState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored.provenance_mode(), Some(()));
        assert_eq!(
            serde_json::to_value(&restored.sidecars).unwrap(),
            serde_json::to_value(&source_state.sidecars).unwrap()
        );
        assert_eq!(restored.submitted_data, source_state.submitted_data);
        assert!(restored.attempted);
        let replay = RetryRelay {
            config: relay.configuration(),
            data,
            sidecars: serde_json::to_value(&retained.sidecars).unwrap(),
            lookup: None,
            response: "server-id".into(),
        };
        assert_eq!(
            attempted
                .submit_broadcaster(chain.as_ref(), &replay)
                .unwrap()
                .id,
            "server-id"
        );
        assert_eq!(
            attempted
                .broadcaster
                .as_ref()
                .unwrap()
                .submission_id
                .as_deref(),
            Some("server-id")
        );
        let wrong = RetryRelay {
            lookup: Some("different".into()),
            ..replay.clone()
        };
        assert!(attempted
            .submit_broadcaster(chain.as_ref(), &wrong)
            .unwrap_err()
            .contains("ID mismatch"));
        let wrong = RetryRelay {
            response: "different".into(),
            ..replay.clone()
        };
        assert!(attempted
            .submit_broadcaster(chain.as_ref(), &wrong)
            .unwrap_err()
            .contains("ID mismatch"));
        assert_eq!(
            attempted
                .broadcaster
                .as_ref()
                .unwrap()
                .submission_id
                .as_deref(),
            Some("server-id")
        );
        let mut wrong = replay.clone();
        wrong.config.endpoint = "https://other.example".into();
        assert!(attempted
            .submit_broadcaster(chain.as_ref(), &wrong)
            .unwrap_err()
            .contains("configuration"));
        let saved = journal::ManagedPrepared::snapshot_funds(&quoted)
            .snapshot()
            .unwrap();
        let json = serde_json::to_string(&saved).unwrap();
        assert!(!json.contains("reprice"));
        assert!(!json.contains("prover"));
        let restored: journal::PreparedSnapshot = serde_json::from_str(&json).unwrap();
        let restored = restored.restore(&wallet, None).unwrap();
        match restored {
            journal::ManagedPrepared::Funds(v) => assert_eq!(
                v.broadcaster_state().unwrap().intent_hash,
                quoted.broadcaster_state().unwrap().intent_hash
            ),
            _ => panic!("funds"),
        }
    }
    #[test]
    fn failed_fee_convergence_does_not_attach_or_consume_original() {
        let (chain, wallet, p, _) = note_fixture();
        let output =
            NoteOutput::identity(chain.context, p.token, U256::from(123), U256::from(20)).unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
            )
            .unwrap();
        let relay = Arc::new(SignedRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            quotes: std::sync::atomic::AtomicUsize::new(0),
        });
        assert!(prepared
            .with_broadcaster(
                chain,
                relay.clone(),
                &BroadcasterOptions {
                    max_fee_rounds: 1,
                    max_fee_amount: Some(U256::from(100))
                }
            )
            .unwrap_err()
            .contains("convergence"));
        assert_eq!(relay.quotes.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(prepared.funding().amount, U256::from(20));
        assert!(prepared.broadcaster_state().is_none());
    }
    #[test]
    fn configured_source_provenance_mismatch_fails_before_relay_request() {
        let (chain, _, _, _) = note_fixture();
        let manifest = source::authenticate_manifest(
            include_bytes!("../../../invisi-sdk-core/provenance/manifest.json"),
            "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762",
        )
        .unwrap();
        let trust = source::TrustContext {
            scope: source::Scope {
                chain_id: chain.context.chain_id + 1,
                protocol_address: chain.context.protocol_address,
            },
            chain_generation: 1,
            provider_id: U256::from(1),
            signing_keys: BTreeMap::new(),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: manifest.sha256.clone(),
        };
        let capability = Arc::new(PreparedProvenance {
            client: Arc::new(ProvenanceClient::new("http://127.0.0.1:1", trust).unwrap()),
            manifest,
            prover: Arc::new(NoProver),
            budgets: SourceReplayBudgets::default(),
        });
        assert!(Invisi::new(chain).with_provenance(capability).is_err());
    }
    #[test]
    fn local_source_configuration_rejects_private_fields_and_wrong_key_identity() {
        let mut config = json!({"endpoint":"http://127.0.0.1:1","chainId":"31337","protocolAddress":"0x1234","generation":"1","providerId":"0x01","signingKeyId":"0x01","signingPublicKey":format!("0x{}","00".repeat(32)),"manifestSha256":"6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762","assetRoot":std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../invisi-sdk-core/provenance"),"bbBinary":"unused","noirExecutor":"unused","timeoutSeconds":120,"threads":4,"budgets":{"maxRootPages":1,"maxCertificates":1,"maxTotalLeaves":1}});
        config["opening"] = json!({"nonce":"1"});
        assert!(serde_json::from_value::<LocalProvenanceConfiguration>(config.clone()).is_err());
        config.as_object_mut().unwrap().remove("opening");
        let invalid_config = serde_json::from_value(config.clone()).unwrap();
        assert!(PreparedProvenance::from_local_configuration(invalid_config)
            .err()
            .unwrap()
            .contains("key ID mismatch"));
        use sha2::Digest;
        config["signingKeyId"] = json!(format!(
            "0x{}",
            hex::encode(sha2::Sha256::digest([0u8; 32]))
        ));
        let loaded =
            PreparedProvenance::from_local_configuration(serde_json::from_value(config).unwrap())
                .unwrap();
        assert_eq!(loaded.client.trust.scope.chain_id, 31337);
        assert_eq!(loaded.manifest.sha256, loaded.client.trust.manifest_sha256);
    }
    struct NoProver;
    impl OfflineProver for NoProver {
        fn prove(
            &self,
            _: &str,
            _: usize,
            _: &source::Witness,
            _: &[String],
        ) -> crate::note::ModelResult<(Vec<String>, Vec<u8>)> {
            panic!("must not prove before provenance validation")
        }
    }
    #[derive(Clone)]
    struct RetryRelay {
        config: Configuration,
        data: Vec<u8>,
        sidecars: serde_json::Value,
        lookup: Option<String>,
        response: String,
    }
    impl PreparedBroadcaster for RetryRelay {
        fn configuration(&self) -> Configuration {
            self.config.clone()
        }
        fn provenance_mode(&self) -> Option<()> {
            None
        }
        fn submission_requirements(&self, _: &VerifiedQuote) -> Result<bool> {
            panic!("retry must not recheck service")
        }
        fn lookup_status(&self, _: &str) -> Result<Option<RelayStatus>> {
            Ok(self.lookup.as_ref().map(|id| RelayStatus {
                id: id.clone(),
                state: invisi_sdk_rpc::broadcaster::StatusState::Pending,
                transaction_hash: None,
            }))
        }
        fn fee(&self, _: Address, _: Option<&[u8]>) -> Result<RelayFee> {
            panic!("retry must not estimate")
        }
        fn quote(
            &self,
            _: &[u8],
            _: u64,
            _: Address,
            _: u64,
            _: &[ProofSidecar],
        ) -> Result<VerifiedQuote> {
            panic!("retry must not quote")
        }
        fn submit(
            &self,
            data: &[u8],
            _: &VerifiedQuote,
            sidecars: &[ProofSidecar],
        ) -> Result<RelayStatus> {
            assert_eq!(data, self.data);
            assert_eq!(serde_json::to_value(sidecars).unwrap(), self.sidecars);
            Ok(RelayStatus {
                id: self.response.clone(),
                state: invisi_sdk_rpc::broadcaster::StatusState::Pending,
                transaction_hash: None,
            })
        }
    }
    struct SignedRelay {
        fees: std::sync::atomic::AtomicUsize,
        quotes: std::sync::atomic::AtomicUsize,
    }
    impl PreparedBroadcaster for SignedRelay {
        fn configuration(&self) -> Configuration {
            let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
            let public = key.verifying_key().to_encoded_point(false);
            Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
                fee_recipient: Address::repeat_byte(4),
            }
        }
        fn submission_requirements(
            &self,
            q: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
        ) -> Result<bool> {
            Ok(q.signed().provenance_required == Some(true))
        }
        fn provenance_mode(&self) -> Option<()> {
            None
        }
        fn fee(&self, _: Address, _: Option<&[u8]>) -> Result<RelayFee> {
            let n = self.fees.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(RelayFee {
                fee_amount: if n == 0 { "1" } else { "2" }.into(),
                fee_recipient: self.configuration().fee_recipient,
                max_gas: "100000".into(),
            })
        }
        fn quote(
            &self,
            data: &[u8],
            chain_id: u64,
            protocol: Address,
            now: u64,
            sidecars: &[ProofSidecar],
        ) -> Result<VerifiedQuote> {
            assert!(sidecars.is_empty());
            self.quotes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let i = invisi_sdk_rpc::broadcaster::decode_intent(data).unwrap();
            let q = invisi_sdk_rpc::broadcaster::Quote {
                token: i.token,
                fee_recipient: i.fee_recipient,
                fee_amount: i.fee_amount.to_string(),
                deadline: i.deadline.to_string(),
                max_gas: "100000".into(),
                request_hash: request_hash(data).unwrap(),
            };
            let trust = Trust {
                chain_id,
                protocol,
                signer: self.configuration().quote_signer,
            };
            let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
            let (sig, r) = key
                .sign_prehash_recoverable(
                    invisi_sdk_rpc::broadcaster::quote_digest(&q, &trust)
                        .unwrap()
                        .as_slice(),
                )
                .unwrap();
            let mut bytes = sig.to_bytes().to_vec();
            bytes.push(r.to_byte());
            VerifiedQuote::authenticate(
                SignedQuote {
                    quote: q,
                    signature: hex(&bytes),

                    request_hash_format: None,
                    provenance_required: None,
                },
                trust,
                data,
                now,
                None,
            )
            .map_err(|e| e.to_string())
        }
        fn submit(&self, _: &[u8], _: &VerifiedQuote, _: &[ProofSidecar]) -> Result<RelayStatus> {
            panic!("no submit")
        }
    }
    #[test]
    fn quote_tracking_is_independently_read_with_pinned_source_identity() {
        use std::io::{Read, Write};
        for wrong_scope in [false, true] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let digest = format!("0x{}", "11".repeat(32));
            let tracking:Tracking=serde_json::from_value(json!({"id":"ab".repeat(24),"status":"pending_confirmation","expiresAt":"10","operationDigest":digest})).unwrap();
            let response_tracking = tracking.clone();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0u8; 4096];
                let request = loop {
                    let n = socket.read(&mut buf).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                        let len: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= end + 4 + len {
                            break serde_json::from_slice::<Value>(&bytes[end + 4..end + 4 + len])
                                .unwrap();
                        }
                    }
                };
                assert_eq!(request["method"], "provenance_getTracking");
                let result = json!({"scope":{"chainId":if wrong_scope{"2"}else{"1"},"protocolAddress":"0x01"},"chainGeneration":"1","providerId":"0x03","signingKeyId":"0x04","manifestSha256":"pin","tracking":response_tracking});
                let body = serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                )
                .unwrap();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                socket.write_all(&body).unwrap();
            });
            let trust = source::TrustContext {
                scope: source::Scope {
                    chain_id: 1,
                    protocol_address: U256::from(1),
                },
                chain_generation: 1,
                provider_id: U256::from(3),
                signing_keys: BTreeMap::from([(U256::from(4), [1; 32])]),
                signing_key_validity: BTreeMap::new(),
                manifest_sha256: "pin".into(),
            };
            let client = ProvenanceClient::new(&endpoint, trust).unwrap();
            let result = trusted_quote_tracking(Some(tracking.clone()), &digest, &client);
            if wrong_scope {
                assert!(result.unwrap_err().contains("deployment mismatch"));
            } else {
                assert_eq!(result.unwrap(), tracking);
            }
            server.join().unwrap();
        }
    }
    #[test]
    fn missing_or_terminal_quote_tracking_fails_before_source_read() {
        let trust = source::TrustContext {
            scope: source::Scope {
                chain_id: 1,
                protocol_address: U256::from(1),
            },
            chain_generation: 1,
            provider_id: U256::from(3),
            signing_keys: BTreeMap::new(),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: "pin".into(),
        };
        let client = ProvenanceClient::new("http://127.0.0.1:1", trust).unwrap();
        let digest = format!("0x{}", "11".repeat(32));
        assert!(trusted_quote_tracking(None, &digest, &client)
            .unwrap_err()
            .contains("tracking required"));
        for status in ["expired", "superseded", "stale_generation", "unknown"] {
            let tracking:Tracking=serde_json::from_value(json!({"id":"ab".repeat(24),"status":status,"expiresAt":"10","operationDigest":digest})).unwrap();
            assert!(trusted_quote_tracking(Some(tracking), &digest, &client).is_err());
        }
    }
    struct MissingCapabilityRelay;
    impl PreparedBroadcaster for MissingCapabilityRelay {
        fn configuration(&self) -> Configuration {
            Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::repeat_byte(3),
                fee_recipient: Address::repeat_byte(4),
            }
        }
        fn submission_requirements(
            &self,
            q: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
        ) -> Result<bool> {
            Ok(q.signed().provenance_required == Some(true))
        }
        fn provenance_mode(&self) -> Option<()> {
            Some(())
        }
        fn fee(&self, _: Address, _: Option<&[u8]>) -> Result<RelayFee> {
            panic!("missing capability must fail before relay request")
        }
        fn quote(
            &self,
            _: &[u8],
            _: u64,
            _: Address,
            _: u64,
            _: &[ProofSidecar],
        ) -> Result<VerifiedQuote> {
            panic!("no quote")
        }
        fn submit(&self, _: &[u8], _: &VerifiedQuote, _: &[ProofSidecar]) -> Result<RelayStatus> {
            panic!("no submit")
        }
    }
}
