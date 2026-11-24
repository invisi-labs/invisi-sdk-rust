//! Relay configuration is attached before authorization; failed candidates leave the original usable.
use super::*;
use crate::provenance::{
    self as source, ManifestIdentity, OfflineProver, Opening, ProofSidecar, RootCertificate,
    Source, WitnessInput, WitnessRequest,
};
#[cfg(test)]
use invisi_sdk_rpc::provenance_tracking::Tracking;
use invisi_sdk_rpc::rpc::RpcTransport;
use invisi_sdk_rpc::{
    broadcaster::{
        request_hash, BroadcasterClient, Configuration, Fee as RelayFee, MemberProof, SignedQuote,
        Status as RelayStatus, Trust, VerifiedQuote,
    },
    provenance_client::ProvenanceClient,
};

fn submission_quote(
    saved: &PreparedBroadcasterState,
    context: ProtocolContext,
    relay: &dyn PreparedBroadcaster,
    data: &[u8],
    now: u64,
) -> Result<VerifiedQuote> {
    let trust = Trust {
        chain_id: context.chain_id,
        protocol: word_address(context.protocol_address)?,
        signer: saved.signer,
    };
    let original = VerifiedQuote::authenticate(
        saved.quote.clone(),
        trust.clone(),
        data,
        0,
        saved.provenance_mode(),
    )
    .map_err(|e| e.to_string())?;
    let deadline = decimal(&json!(saved.quote.quote.deadline))?;
    if deadline >= U256::from(now) {
        return Ok(original);
    }
    if saved.attempted || !saved.submitted_data.is_empty() {
        return Err("broadcaster quote expired after submission evidence was frozen".into());
    }
    let intent = invisi_sdk_rpc::broadcaster::decode_intent(data).map_err(|e| e.to_string())?;
    if intent.deadline <= U256::from(now) {
        return Err("broadcaster transaction intent expired".into());
    }
    let config = relay.configuration();
    if config.endpoint != saved.endpoint
        || config.quote_signer != saved.signer
        || config.fee_recipient != saved.fee_recipient
    {
        return Err("saved broadcaster configuration mismatch".into());
    }
    let renewed = relay.scheduled_quote(
        data,
        context.chain_id,
        trust.protocol,
        now,
        &saved.sidecars,
        saved.quote.quote.schedule.as_ref(),
    )?;
    if renewed.signed().quote.execution != original.signed().quote.execution
        || renewed.signed().quote.schedule != original.signed().quote.schedule
        || renewed.signed().provenance_required != original.signed().provenance_required
        || renewed.signed().request_hash_format != original.signed().request_hash_format
    {
        return Err("renewed broadcaster quote changed execution or provenance".into());
    }
    VerifiedQuote::authenticate(
        renewed.signed().clone(),
        trust,
        data,
        now,
        saved.provenance_mode(),
    )
    .map_err(|e| e.to_string())
}

pub type ProvenanceFactory =
    Arc<dyn Fn(ProtocolContext) -> Result<Arc<PreparedProvenance>> + Send + Sync>;
#[derive(Clone)]
pub struct PreparedProvenance {
    pub client: Arc<ProvenanceClient>,
    pub manifest: ManifestIdentity,
    pub prover: Arc<dyn OfflineProver + Send + Sync>,
    pub budgets: SourceReplayBudgets,
}
struct ClientOnlyProver;
impl OfflineProver for ClientOnlyProver {
    fn prove(
        &self,
        _: &str,
        _: usize,
        _: &source::Witness,
        _: &[String],
    ) -> crate::note::ModelResult<(Vec<String>, Vec<u8>)> {
        Err(crate::note::ModelError::Invalid(
            "local provenance proving resources required",
        ))
    }
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
    /// Attaches public trust pins for cached proof recovery without local proving assets.
    pub fn client_only(client: Arc<ProvenanceClient>) -> Self {
        Self {
            client,
            manifest: ManifestIdentity {
                sha256: String::new(),
                manifest: source::Manifest {
                    family: String::new(),
                    target: String::new(),
                    noir_version: String::new(),
                    bb_version: String::new(),
                    depth: 0,
                    public_inputs: Vec::new(),
                    circuits: Vec::new(),
                },
            },
            prover: Arc::new(ClientOnlyProver),
            budgets: SourceReplayBudgets::default(),
        }
    }
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
            max_root_pages: 10,
            max_certificates: 3200,
            max_total_leaves: 100_000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcasterFeeSource {
    PublicFunding,
    PrivateInputs,
    /// Deduct the relay fee from a pure full-sum withdrawal.
    Payout,
}
#[derive(Clone, Debug)]
pub struct FundingPermitRequest {
    pub payer: Address,
    pub amount: U256,
    pub token_address: Address,
    pub protocol_address: Address,
}
pub type FundingPermitCallback = Arc<
    dyn Fn(FundingPermitRequest) -> Result<crate::protocol::IMetaTx::TokenPermit> + Send + Sync,
>;
/// Persist only in the encrypted operation journal; Debug never reveals the preimage.
#[derive(Clone, Serialize, Deserialize)]
pub struct CancellationToken(B256);
impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CancellationToken([REDACTED])")
    }
}
impl CancellationToken {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(B256::from(bytes))
    }
    pub fn commitment(&self) -> B256 {
        alloy_primitives::keccak256(self.0)
    }
}
#[derive(Clone, Debug)]
pub struct BroadcasterSchedule {
    pub publish_after: u64,
    pub execute_before: u64,
}
#[derive(Clone)]
pub struct BroadcasterOptions {
    pub schedule: Option<BroadcasterSchedule>,
    pub fee_source: Option<BroadcasterFeeSource>,
    pub funding_permit: Option<FundingPermitCallback>,
    pub max_attempts: usize,
    pub max_fee_amount: Option<U256>,
}
impl Default for BroadcasterOptions {
    fn default() -> Self {
        Self {
            schedule: None,
            fee_source: None,
            funding_permit: None,
            max_attempts: 4,
            max_fee_amount: None,
        }
    }
}
#[derive(Clone)]
pub(crate) enum RepriceTemplate {
    Transfer(TransferPreparation),
    Shield(ShieldPreparation),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BroadcasterSubmission {
    #[serde(with = "crate::note::bytes_hex")]
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_proof: Option<MemberProof>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedBroadcasterState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<CancellationToken>,
    pub endpoint: String,
    pub signer: Address,
    pub fee_recipient: Address,
    pub quote: SignedQuote,
    pub intent_hash: B256,
    pub sidecars: Vec<ProofSidecar>,
    #[serde(default)]
    pub attempted: bool,
    /// A first structured pre-send refusal permanently retires this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_send_refusal: Option<String>,
    #[serde(default)]
    pub submission_id: Option<String>,
    #[serde(default)]
    pub submitted_data: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_proof: Option<MemberProof>,
}
impl PreparedBroadcasterState {
    /// Request cancellation against the exact saved relay; callers still reconcile canonically before releasing inputs.
    pub fn cancel(
        &self,
        relay: &dyn PreparedBroadcaster,
        submission_id: &str,
    ) -> Result<RelayStatus> {
        let config = relay.configuration();
        if config.endpoint != self.endpoint
            || config.quote_signer != self.signer
            || config.fee_recipient != self.fee_recipient
        {
            return Err("saved cancellation relay scope mismatch".into());
        }
        let accepted_id = self.submission_id.as_deref().ok_or("submission ID unknown; recover the previously attempted submission before cancellation")?;
        if accepted_id != submission_id {
            return Err("cancellation submission scope mismatch".into());
        }
        let token = self
            .cancellation_token
            .as_ref()
            .ok_or("scheduled cancellation token required")?;
        if self
            .quote
            .quote
            .schedule
            .as_ref()
            .is_none_or(|s| s.cancel_token_hash != token.commitment())
        {
            return Err("cancellation commitment mismatch".into());
        }
        let status = relay.cancel(submission_id, token)?;
        if status.id != submission_id {
            return Err("cancellation status identity mismatch".into());
        }
        Ok(status)
    }
    pub fn provenance_mode(&self) -> Option<()> {
        (self.quote.provenance_required == Some(true)).then_some(())
    }
}
/// Submission errors retain structured RPC evidence without changing the SDK's
/// existing String-based Result or custom Broadcaster implementations.
#[derive(Debug)]
pub enum BroadcasterSubmitError {
    Unknown(String),
    Rpc(invisi_sdk_rpc::rpc::Error),
}
impl BroadcasterSubmitError {
    /// Only these exact structured responses acknowledge a fresh request was
    /// refused before acceptance. Text from custom transports never proves it.
    pub fn pre_send_refusal(&self) -> Option<&'static str> {
        let Self::Rpc(invisi_sdk_rpc::rpc::Error::Remote { code, message, .. }) = self else {
            return None;
        };
        let (token, _) = message.split_once(':')?;
        match (*code, token) {
            (-32024, "CREDIT_PERIOD_CHANGED") => Some("CREDIT_PERIOD_CHANGED"),
            (-32025, "INSUFFICIENT_EXECUTION_SLACK") => Some("INSUFFICIENT_EXECUTION_SLACK"),
            (-32026, "CREDIT_PERIOD_ENDING") => Some("CREDIT_PERIOD_ENDING"),
            _ => None,
        }
    }
}
impl std::fmt::Display for BroadcasterSubmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(message) => f.write_str(message),
            Self::Rpc(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for BroadcasterSubmitError {}

/// Sealed stock RPC policy, bound to the configured endpoint.
#[derive(Clone, Debug)]
pub struct StockBroadcasterCapability {
    endpoint: String,
}
impl StockBroadcasterCapability {
    pub(super) fn restore(
        saved: &PreparedBroadcasterState,
        context: ProtocolContext,
        data: &[u8],
    ) -> Result<Self> {
        Configuration {
            endpoint: saved.endpoint.clone(),
            quote_signer: saved.signer,
            fee_recipient: saved.fee_recipient,
        }
        .validate()
        .map_err(|e| e.to_string())?;
        VerifiedQuote::authenticate(
            saved.quote.clone(),
            Trust {
                chain_id: context.chain_id,
                protocol: word_address(context.protocol_address)?,
                signer: saved.signer,
            },
            data,
            0,
            saved.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            endpoint: saved.endpoint.clone(),
        })
    }
}
pub trait PreparedBroadcaster: Send + Sync {
    fn stock_capability(&self) -> Option<StockBroadcasterCapability> {
        None
    }
    fn quote_classified(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<VerifiedQuote, BroadcasterSubmitError> {
        self.quote(data, chain_id, protocol, now, sidecars)
            .map_err(BroadcasterSubmitError::Unknown)
    }

    /// Override only when the transport retains authenticated structured RPC
    /// errors. The default treats every legacy String error as uncertain.
    fn submit_classified(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<RelayStatus, BroadcasterSubmitError> {
        self.submit(data, quote, sidecars)
            .map_err(BroadcasterSubmitError::Unknown)
    }
    fn cancel(&self, _id: &str, _token: &CancellationToken) -> Result<RelayStatus> {
        Err("broadcaster cancellation capability required".into())
    }
    fn scheduled_fee(
        &self,
        token: Address,
        data: Option<&[u8]>,
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<RelayFee> {
        if schedule.is_some() {
            return Err("broadcaster scheduling capability required".into());
        }
        self.fee(token, data)
    }
    #[allow(clippy::too_many_arguments)]
    fn scheduled_quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<VerifiedQuote> {
        if schedule.is_some() {
            return Err("broadcaster scheduling capability required".into());
        }
        self.quote(data, chain_id, protocol, now, sidecars)
    }

    fn lookup_status(&self, _id: &str) -> Result<Option<RelayStatus>> {
        Err("broadcaster status lookup capability required".into())
    }
    fn submit_member(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
        member: Option<&MemberProof>,
    ) -> Result<RelayStatus> {
        if member.is_some() {
            return Err("broadcaster recursive member capability required".into());
        }
        self.submit(data, quote, sidecars)
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
    fn stock_capability(&self) -> Option<StockBroadcasterCapability> {
        Some(StockBroadcasterCapability {
            endpoint: self.configuration().endpoint.clone(),
        })
    }
    fn quote_classified(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<VerifiedQuote, BroadcasterSubmitError> {
        self.quote_with_sidecars(data, chain_id, protocol, now, sidecars)
            .map_err(BroadcasterSubmitError::Rpc)
    }

    fn submit_classified(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<RelayStatus, BroadcasterSubmitError> {
        self.submit_with_sidecars(data, quote, sidecars)
            .map_err(BroadcasterSubmitError::Rpc)
    }
    fn cancel(&self, id: &str, token: &CancellationToken) -> Result<RelayStatus> {
        BroadcasterClient::cancel_transaction(self, id, token.0).map_err(|e| e.to_string())
    }
    fn scheduled_fee(
        &self,
        token: Address,
        data: Option<&[u8]>,
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<RelayFee> {
        self.fee_with_schedule(token, data, schedule)
            .map_err(|e| e.to_string())
    }
    #[allow(clippy::too_many_arguments)]
    fn scheduled_quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<VerifiedQuote> {
        self.quote_with_schedule(data, chain_id, protocol, now, sidecars, schedule)
            .map_err(|e| e.to_string())
    }

    fn submit_member(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
        member: Option<&MemberProof>,
    ) -> Result<RelayStatus> {
        self.submit_with_member_proof(data, quote, sidecars, member)
            .map_err(|e| e.to_string())
    }
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
impl<T: RpcTransport + Send + Sync + 'static> PreparedBroadcaster
    for crate::broadcaster::BroadcasterClient<T>
{
    fn stock_capability(&self) -> Option<StockBroadcasterCapability> {
        PreparedBroadcaster::stock_capability(self.rpc())
    }
    fn quote_classified(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<VerifiedQuote, BroadcasterSubmitError> {
        PreparedBroadcaster::quote_classified(self.rpc(), data, chain_id, protocol, now, sidecars)
    }

    fn submit_classified(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> std::result::Result<RelayStatus, BroadcasterSubmitError> {
        PreparedBroadcaster::submit_classified(self.rpc(), data, quote, sidecars)
    }
    fn cancel(&self, id: &str, token: &CancellationToken) -> Result<RelayStatus> {
        PreparedBroadcaster::cancel(self.rpc(), id, token)
    }
    fn scheduled_fee(
        &self,
        token: Address,
        data: Option<&[u8]>,
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<RelayFee> {
        PreparedBroadcaster::scheduled_fee(self.rpc(), token, data, schedule)
    }
    fn scheduled_quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
        schedule: Option<&invisi_sdk_rpc::broadcaster::Schedule>,
    ) -> Result<VerifiedQuote> {
        PreparedBroadcaster::scheduled_quote(
            self.rpc(),
            data,
            chain_id,
            protocol,
            now,
            sidecars,
            schedule,
        )
    }
    fn submit_member(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
        member: Option<&MemberProof>,
    ) -> Result<RelayStatus> {
        PreparedBroadcaster::submit_member(self.rpc(), data, quote, sidecars, member)
    }
    fn lookup_status(&self, id: &str) -> Result<Option<RelayStatus>> {
        PreparedBroadcaster::lookup_status(self.rpc(), id)
    }
    fn submission_requirements(&self, quote: &VerifiedQuote) -> Result<bool> {
        PreparedBroadcaster::submission_requirements(self.rpc(), quote)
    }
    fn configuration(&self) -> Configuration {
        PreparedBroadcaster::configuration(self.rpc())
    }
    fn provenance_mode(&self) -> Option<()> {
        PreparedBroadcaster::provenance_mode(self.rpc())
    }
    fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<RelayFee> {
        PreparedBroadcaster::fee(self.rpc(), token, data)
    }
    fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> Result<VerifiedQuote> {
        PreparedBroadcaster::quote(self.rpc(), data, chain_id, protocol, now, sidecars)
    }
    fn submit(
        &self,
        data: &[u8],
        quote: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> Result<RelayStatus> {
        PreparedBroadcaster::submit(self.rpc(), data, quote, sidecars)
    }
}

pub(crate) fn provenance_factory_for_prover(
    prover: &dyn Prover,
) -> Result<Option<ProvenanceFactory>> {
    let Some(capability) = prover.get_provenance_capability()? else {
        return Ok(None);
    };
    let clients = Arc::new(invisi_sdk_rpc::provenance_official::OfficialProvenanceClients::new());
    Ok(Some(Arc::new(move |context| {
        let client = clients.get(&source::Scope {
            chain_id: context.chain_id,
            protocol_address: context.protocol_address,
        })?;
        Ok(Arc::new(PreparedProvenance {
            client,
            manifest: capability.manifest.clone(),
            prover: capability.prover.clone(),
            budgets: SourceReplayBudgets::default(),
        }))
    })))
}
impl PreparedProvenance {
    pub fn from_prover(context: ProtocolContext, prover: &dyn Prover) -> Result<Arc<Self>> {
        provenance_factory_for_prover(prover)?
            .ok_or("local provenance prover capability required")?(context)
    }
}
impl Invisi {
    /// Register local capabilities without contacting the network during preparation.
    pub fn with_prover(mut self, prover: Arc<dyn Prover>) -> PreparationResult<Self> {
        self.provenance_factory =
            provenance_factory_for_prover(prover.as_ref()).map_err(|cause| {
                InvisiError::new(
                    InvisiErrorCode::MissingCapability,
                    cause,
                    json!({"capability":"local provenance prover"}),
                )
            })?;
        Ok(self)
    }
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
            || (!self.manifest.sha256.is_empty() && t.manifest_sha256 != self.manifest.sha256)
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
    /// Export only public relay fields without a chain read or proof generation.
    pub fn export_broadcaster_submission(&self) -> Result<BroadcasterSubmission> {
        if self
            .broadcaster
            .as_ref()
            .is_some_and(|s| !s.attempted && s.submission_id.is_none())
        {
            self.validate_broadcaster_evidence()?;
        }
        journal::ManagedPrepared::snapshot_funds(self)
            .snapshot()?
            .export_broadcaster_submission()
    }
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
    pub(crate) fn quote_for_broadcaster(
        &self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> Result<Self> {
        if self.funding().amount != U256::ZERO && !self.selected_funding_terms {
            return Err("NEEDS_REPREPARATION: select signature funding during preparation".into());
        }
        if !self.funding().signature.is_empty()
            || self.proof.is_some()
            || self.broadcaster.as_ref().is_some_and(|s| {
                s.attempted || s.submission_id.is_some() || !s.submitted_data.is_empty()
            })
        {
            return Err("cannot reprice an authorized or finalized operation".into());
        }
        if options
            .max_fee_amount
            .is_none_or(|cap| cap == U256::ZERO || cap >= U256::from(1) << 128)
        {
            return Err("positive maximum broadcaster fee required".into());
        }
        if self.phase != Phase::Prepared
            || self.target != "evm"
            || chain.context() != self.context
            || !(1..=16).contains(&options.max_attempts)
        {
            return Err("broadcaster requires unsigned EVM preparation and matching chain".into());
        }
        let initialized_binding = chain.self_contained_shield_capability();
        let config = relay.configuration();
        config.validate().map_err(|e| e.to_string())?;
        let provenance = relay.provenance_mode();
        if provenance.is_some() && !self.inputs().is_empty() {
            if let Some(cap) = &self.provenance {
                cap.validate(self.context, provenance)?;
            } else if self.provenance_factory.is_none() {
                return Err("provenance capability required".into());
            }
        }
        let template = self.reprice.as_ref().ok_or(
            "NEEDS_REPREPARATION: original business preparation required for explicit repricing",
        )?;
        let now = self
            .quote_clock
            .ok_or("NEEDS_REPREPARATION: prepared quote clock required")?
            .now()?;
        let cancellation_token = options
            .schedule
            .as_ref()
            .map(|_| CancellationToken::generate());
        let schedule = options
            .schedule
            .as_ref()
            .map(|s| invisi_sdk_rpc::broadcaster::Schedule {
                publish_after: s.publish_after.to_string(),
                execute_before: s.execute_before.to_string(),
                cancel_token_hash: cancellation_token.as_ref().unwrap().commitment(),
            });
        if let Some(schedule) = &schedule {
            schedule.validate().map_err(|e| e.to_string())?;
        }
        let ordinary_shield = matches!(template, RepriceTemplate::Shield(p) if p.funding.permit.deadline == U256::ZERO)
            && schedule.is_none()
            && options.funding_permit.is_none()
            && relay
                .stock_capability()
                .is_some_and(|cap| cap.endpoint == config.endpoint);
        let mut estimate = self.clone();
        if ordinary_shield {
            if let Plan::Shield {
                params, funding, ..
            } = &mut estimate.plan
            {
                params.feeRecipient = config.fee_recipient;
                params.feeAmount = U256::from(1);
                if funding.amount > U256::ZERO && funding.deadline == U256::ZERO {
                    funding.deadline = params.deadline;
                }
            }
        }
        let mut fee = relay.scheduled_fee(
            self.token,
            Some(&estimate.broadcaster_intent()?.data),
            schedule.as_ref(),
        )?;
        let mut final_candidate = None;
        let mut ordinary_quote = None;
        for round in 0..options.max_attempts {
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
            let candidate = match template {
                RepriceTemplate::Transfer(p) => {
                    let original_fee = p.fee.amount;
                    let mut p = p.clone();
                    p.fee = f;
                    let has_funding = p.funding.amount != U256::ZERO;
                    let business = sum(p.outputs.iter().map(|o| o.amount))?
                        .checked_add(p.withdrawal.map_or(U256::ZERO, |w| w.1))
                        .ok_or("amount overflow")?;
                    let available = sum(p.inputs.iter().map(|i| i.note.amount))?
                        .checked_add(p.funding.amount)
                        .ok_or("amount overflow")?;
                    let source = options.fee_source.unwrap_or(
                        if has_funding
                            && (p.inputs.is_empty() || available.saturating_sub(business) < amount)
                        {
                            BroadcasterFeeSource::PublicFunding
                        } else {
                            BroadcasterFeeSource::PrivateInputs
                        },
                    );
                    match source {
                        BroadcasterFeeSource::Payout => {
                            let original_fee = match template {
                                RepriceTemplate::Transfer(original) => original.fee.amount,
                                _ => unreachable!(),
                            };
                            let (recipient, withdrawal) =
                                p.withdrawal.ok_or("payout fee requires pure withdrawal")?;
                            let gross = withdrawal
                                .checked_add(original_fee)
                                .ok_or("payout overflow")?;
                            if p.inputs.is_empty()
                                || !p.outputs.is_empty()
                                || has_funding
                                || recipient == Address::ZERO
                                || gross != available
                                || amount >= gross
                                || amount >= U256::from(1) << 128
                            {
                                return Err("payout fee requires pure full-sum withdrawal with positive net".into());
                            }
                            p.withdrawal = Some((recipient, gross - amount));
                            p.automatic_change = false;
                        }
                        BroadcasterFeeSource::PublicFunding => {
                            if !has_funding {
                                return Err("public funding fee requires explicit payer".into());
                            }
                            if p.funding.permit.deadline != U256::ZERO
                                && options.funding_permit.is_none()
                            {
                                return Err("increased funding requires final gross funding permit callback".into());
                            }
                            p.funding.amount = p
                                .funding
                                .amount
                                .checked_add(amount)
                                .and_then(|n| n.checked_sub(original_fee))
                                .filter(|n| *n != U256::ZERO)
                                .ok_or("NEEDS_REPREPARATION: selected public funding cannot cover this fee adjustment")?;
                        }
                        BroadcasterFeeSource::PrivateInputs => {
                            if p.inputs.is_empty() {
                                return Err("private-inputs fee requires private funds".into());
                            }
                        }
                    }
                    self.reprice_transfer(p)?
                }
                RepriceTemplate::Shield(p) => {
                    let mut p = p.clone();
                    if matches!(
                        options.fee_source,
                        Some(BroadcasterFeeSource::PrivateInputs | BroadcasterFeeSource::Payout)
                    ) {
                        return Err("shield fee requires public funding".into());
                    }
                    if p.funding.permit.deadline != U256::ZERO && options.funding_permit.is_none() {
                        return Err(
                            "increased funding requires final gross funding permit callback".into(),
                        );
                    }
                    p.fee = f;
                    p.funding.amount = sum(p.outputs.iter().map(|o| o.amount))?
                        .checked_add(amount)
                        .ok_or("funding overflow")?;
                    model(crate::note::uint(p.funding.amount, 128, "funding amount"))?;
                    let mut candidate = self.clone();
                    let Plan::Shield {
                        params, funding, ..
                    } = &mut candidate.plan
                    else {
                        return Err("shield repricing shape mismatch".into());
                    };
                    params.feeAmount = amount;
                    params.feeRecipient = fee.fee_recipient;
                    funding.amount = p.funding.amount;
                    candidate
                }
            };
            if self.funding().permit.deadline != U256::ZERO
                && self.funding().amount != candidate.funding().amount
                && options.funding_permit.is_none()
            {
                return Err(
                    "increased funding requires final gross funding permit callback".into(),
                );
            }
            let data = candidate.broadcaster_intent()?.data;
            if ordinary_shield {
                match relay.quote_classified(
                    &data,
                    candidate.context.chain_id,
                    word_address(candidate.context.protocol_address)?,
                    now,
                    &[],
                ) {
                    Ok(quote) => {
                        ordinary_quote = Some((quote, now));
                        final_candidate = Some(candidate);
                        break;
                    }
                    Err(error) => {
                        if !matches!(
                            &error,
                            BroadcasterSubmitError::Rpc(invisi_sdk_rpc::rpc::Error::Remote {
                                code: -32000,
                                ..
                            })
                        ) || round + 1 >= options.max_attempts
                        {
                            return Err(error.to_string());
                        }
                        let refreshed = relay.fee(self.token, Some(&data))?;
                        let required = decimal(&json!(refreshed.fee_amount))?;
                        if refreshed.fee_recipient != config.fee_recipient
                            || options.max_fee_amount.is_some_and(|cap| required > cap)
                        {
                            return Err(
                                "broadcaster fee exceeds maximum or recipient changed".into()
                            );
                        }
                        if required <= amount {
                            return Err(error.to_string());
                        }
                        fee = refreshed;
                        continue;
                    }
                }
            }
            let next = relay.scheduled_fee(self.token, Some(&data), schedule.as_ref())?;
            let next_amount = decimal(&json!(next.fee_amount))?;
            if next.fee_recipient != config.fee_recipient
                || next_amount == U256::ZERO
                || options.max_fee_amount.is_some_and(|cap| next_amount > cap)
            {
                return Err("broadcaster fee exceeds maximum or recipient changed".into());
            }
            if amount >= next_amount {
                final_candidate = Some(candidate);
                break;
            }
            fee = next;
        }
        let mut candidate = final_candidate.ok_or("broadcaster fee convergence budget exceeded")?;
        if let Some(sign) = &options.funding_permit {
            if candidate.funding().amount == U256::ZERO {
                return Err("funding permit requires public funding".into());
            }
            let permit = sign(FundingPermitRequest {
                payer: candidate.funding().payer,
                amount: candidate.funding().amount,
                token_address: candidate.token,
                protocol_address: word_address(candidate.context.protocol_address)?,
            })?;
            candidate.funding_mut().permit = permit;
        }
        let data = candidate.broadcaster_intent()?.data;
        let sidecars = Vec::new();
        let (quote, now) = match ordinary_quote {
            Some((quote, now)) => (quote, now),
            None => {
                let quote = relay.scheduled_quote(
                    &data,
                    candidate.context.chain_id,
                    word_address(candidate.context.protocol_address)?,
                    now,
                    &sidecars,
                    schedule.as_ref(),
                )?;
                (quote, now)
            }
        };
        if quote.signed().quote.schedule.as_ref() != schedule.as_ref() {
            return Err("broadcaster quote schedule mismatch".into());
        }
        invisi_sdk_rpc::broadcaster::verify_quote_for_provenance(
            quote.signed(),
            &Trust {
                chain_id: candidate.context.chain_id,
                protocol: word_address(candidate.context.protocol_address)?,
                signer: config.quote_signer,
            },
            &data,
            now,
            provenance,
        )
        .map_err(|e| e.to_string())?;
        candidate.reprice = self.reprice.clone();
        if initialized_binding.is_some() && chain.self_contained_shield_capability().is_none() {
            return Err("deployment receipt invalidated during quote".into());
        }
        candidate.stock_broadcaster = relay.stock_capability();
        candidate.broadcaster = Some(PreparedBroadcasterState {
            cancellation_token: cancellation_token.clone(),
            endpoint: config.endpoint,
            signer: config.quote_signer,
            fee_recipient: config.fee_recipient,
            quote: quote.signed().clone(),
            intent_hash: request_hash(&data).map_err(|e| e.to_string())?,
            sidecars,
            attempted: false,
            pre_send_refusal: None,
            submission_id: None,
            submitted_data: Vec::new(),
            member_proof: None,
        });
        Ok(candidate)
    }
    fn reprice_transfer(&self, p: TransferPreparation) -> Result<Self> {
        let mut candidate = self.clone();
        let Plan::Transfer {
            params,
            inputs,
            outputs,
            funding,
            capacity: slots,
        } = &mut candidate.plan
        else {
            return Err("transfer repricing shape mismatch".into());
        };
        let (recipient, withdrawal) = p.withdrawal.unwrap_or((Address::ZERO, U256::ZERO));
        model(crate::note::uint(withdrawal, 128, "withdrawal"))?;
        model(crate::note::uint(p.funding.amount, 128, "funding amount"))?;
        let available = sum(inputs.iter().map(|i| i.note.amount))?
            .checked_add(p.funding.amount)
            .ok_or("amount overflow")?;
        let requested = sum(p.outputs.iter().map(|o| o.amount))?
            .checked_add(withdrawal)
            .and_then(|n| n.checked_add(p.fee.amount))
            .ok_or("amount overflow")?;
        let change = available
            .checked_sub(requested)
            .ok_or("NEEDS_REPREPARATION: insufficient prepared Note balance")?;
        let mut repriced_outputs = p.outputs;
        if change != U256::ZERO {
            if !p.automatic_change {
                return Err(
                    "NEEDS_REPREPARATION: explicit outputs must balance funding and fees".into(),
                );
            }
            let mut output = if let Some(prior) = outputs
                .iter()
                .find(|out| out.change && out.amount == change)
            {
                prior.clone()
            } else {
                let wallet = self
                    .wallet
                    .as_ref()
                    .ok_or("NEEDS_REPREPARATION: receiving keys required for change")?;
                NoteOutput::for_recipient(self.context, self.token, wallet, change, Vec::new())?
            };
            output.change = true;
            repriced_outputs.push(output);
        }
        validate_outputs(&repriced_outputs, self.context, self.token)?;
        *slots = capacity(inputs.len(), repriced_outputs.len())?;
        candidate.needs_authorization = !inputs.is_empty()
            && !(recipient == self.owner_address
                && withdrawal == available
                && repriced_outputs.is_empty()
                && p.funding.amount == U256::ZERO
                && p.fee.amount == U256::ZERO);
        params.noteCommitments = repriced_outputs.iter().map(|o| o.commitment).collect();
        params.withdrawalAddress = recipient;
        params.withdrawalAmount = withdrawal;
        params.feeRecipient = p.fee.recipient;
        params.feeAmount = p.fee.amount;
        *outputs = repriced_outputs;
        funding.amount = p.funding.amount;
        Ok(candidate)
    }
    fn broadcaster_member_proof(&self) -> Result<Option<MemberProof>> {
        let member = if self.target == "noir-recursive" {
            let proof = self.export_aggregate_member()?.bundle;
            Some(MemberProof {
                format_version: proof.format_version,
                circuit_name: proof.circuit_name,
                target: proof.target,
                bb_version: proof.bb_version,
                artifact_sha256: proof.artifact_sha256,
                vk_sha256: proof.vk_sha256,
                proof_hex: hex(&proof.proof),
                proof_sha256: proof.proof_sha256,
                public_inputs: proof.public_inputs,
            })
        } else {
            None
        };
        Ok(member)
    }
    fn source_required(&self) -> bool {
        !self.inputs().is_empty()
            && self
                .broadcaster
                .as_ref()
                .is_some_and(|s| s.provenance_mode().is_some())
    }
    fn authenticate_final_call(&self, data: &[u8], now: u64) -> Result<VerifiedQuote> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        if request_hash(data).map_err(|e| e.to_string())? != saved.intent_hash {
            return Err("frozen broadcaster intent mismatch".into());
        }
        VerifiedQuote::authenticate(
            saved.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: saved.signer,
            },
            data,
            now,
            saved.provenance_mode(),
        )
        .map_err(|e| e.to_string())
    }
    /// Publish the complete local packet for operations without required Source evidence.
    pub(super) fn finalize_local_broadcaster(&mut self) -> Result<()> {
        if self.broadcaster.is_none() || self.source_required() {
            return Ok(());
        }
        let data = self.broadcaster_submission_call(0)?.data;
        self.authenticate_final_call(&data, 0)?;
        let member = self.broadcaster_member_proof()?;
        let saved = self.broadcaster.as_mut().unwrap();
        if !saved.submitted_data.is_empty()
            && (saved.submitted_data != data || saved.member_proof != member)
        {
            return Err("prepared broadcaster submission changed".into());
        }
        if !saved.sidecars.is_empty() {
            return Err("unexpected Source sidecar".into());
        }
        saved.submitted_data = data;
        saved.member_proof = member;
        Ok(())
    }
    /// Complete required evidence after the native proof and any funding signature exist.
    /// On failure the caller retains the original operation and its verified main proof.
    pub fn finalize_broadcaster(&mut self, chain: &dyn ChainState) -> Result<()> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        if saved.attempted || saved.submission_id.is_some() {
            return Err("cannot finalize an attempted packet".into());
        }
        if chain.context() != self.context {
            return Err("finalization deployment mismatch".into());
        }
        if !saved.submitted_data.is_empty() {
            if !self.source_required() {
                return self.validate_broadcaster_evidence();
            }
            if !saved.sidecars.is_empty() {
                // An explicit Source reproof may have renewed the trusted packet before first send.
                let packet = self
                    .export_provenance_proof()?
                    .ok_or("FINALIZATION_REQUIRED: verified Source packet required")?;
                let mut candidate = self.clone();
                candidate.broadcaster.as_mut().unwrap().sidecars = packet.sidecars;
                candidate.validate_broadcaster_evidence()?;
                *self = candidate;
                return Ok(());
            }
            if saved.submitted_data != self.broadcaster_submission_call(0)?.data
                || saved.member_proof != self.broadcaster_member_proof()?
            {
                return Err("prepared broadcaster submission changed".into());
            }
        }
        let mut candidate = self.clone();
        candidate.provenance_packet = Arc::new(std::sync::Mutex::new(
            self.provenance_packet
                .lock()
                .map_err(|_| "provenance cache lock poisoned")?
                .clone(),
        ));
        if matches!(candidate.plan, Plan::Shield { .. }) && candidate.phase == Phase::Prepared {
            candidate.phase = Phase::Ready;
        }
        if candidate.source_required() {
            let data = candidate.broadcaster_submission_call(0)?.data;
            candidate.authenticate_final_call(&data, 0)?;
            if candidate.provenance.is_none() {
                let factory = candidate
                    .provenance_factory
                    .as_ref()
                    .ok_or("trusted provenance capability required")?;
                let cap = factory(candidate.context)?;
                cap.validate(candidate.context, saved.provenance_mode())?;
                candidate.provenance = Some(cap);
            }
            let packet = candidate.prove_provenance(chain)?;
            let member = candidate.broadcaster_member_proof()?;
            let saved = candidate.broadcaster.as_mut().unwrap();
            saved.submitted_data = data;
            saved.sidecars = packet.sidecars;
            saved.member_proof = member;
        } else {
            candidate.finalize_local_broadcaster()?;
        }
        candidate.validate_broadcaster_evidence()?;
        *self = candidate;
        Ok(())
    }
    /// Explicit pre-submission finalization with relay-bound quote renewal when needed.
    pub fn freeze_broadcaster_evidence(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<()> {
        let saved = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        let config = relay.configuration();
        if config.endpoint != saved.endpoint
            || config.quote_signer != saved.signer
            || config.fee_recipient != saved.fee_recipient
        {
            return Err("saved broadcaster configuration mismatch".into());
        }
        if !saved.submitted_data.is_empty() {
            return self.validate_broadcaster_evidence();
        }
        let now = chain.submission_timestamp()?;
        let data = self.broadcaster_submission_call(now)?.data;
        let quote = submission_quote(saved, self.context, relay, &data, now)?;
        let mut candidate = self.clone();
        candidate.broadcaster.as_mut().unwrap().quote = quote.signed().clone();
        candidate.finalize_broadcaster(chain)?;
        *self = candidate;
        Ok(())
    }
    /// Validate completed immutable artifacts before reserving a first relay handoff.
    pub fn validate_broadcaster_evidence(&self) -> Result<()> {
        let s = self
            .broadcaster
            .as_ref()
            .ok_or("saved broadcaster context required")?;
        if s.submitted_data.is_empty() {
            return Err(
                "FINALIZATION_REQUIRED: finalize broadcaster evidence before submission".into(),
            );
        }
        let data = self.broadcaster_submission_call(0)?.data;
        if s.submitted_data != data || s.member_proof != self.broadcaster_member_proof()? {
            return Err("prepared broadcaster submission changed".into());
        }
        self.authenticate_final_call(&data, 0)?;
        if self.source_required() {
            if s.sidecars.len() != 1 {
                return Err("FINALIZATION_REQUIRED: one Source sidecar required".into());
            }
            let packet = self
                .export_provenance_proof()?
                .ok_or("FINALIZATION_REQUIRED: verified Source packet required")?;
            if packet.data != hex(&data)
                || serde_json::to_vec(&packet.sidecars).map_err(|e| e.to_string())?
                    != serde_json::to_vec(&s.sidecars).map_err(|e| e.to_string())?
            {
                return Err("finalized Source packet differs from native submission".into());
            }
        } else if !s.sidecars.is_empty() {
            return Err("unexpected Source sidecar".into());
        }
        Ok(())
    }
    fn delegates_broadcaster_execution(
        &self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
        saved: &PreparedBroadcasterState,
    ) -> bool {
        self.self_contained_shield()
            && chain
                .self_contained_shield_capability()
                .is_some_and(|cap| cap.context == self.context)
            && relay
                .stock_capability()
                .is_some_and(|cap| cap.endpoint == saved.endpoint)
            && saved.quote.quote.execution == invisi_sdk_rpc::broadcaster::Execution::Direct
            && saved.sidecars.is_empty()
            && !self.funding().signature.is_empty()
    }
    pub(crate) fn submit_for_broadcaster(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> Result<RelayStatus> {
        self.submit_broadcaster_with_fence(chain, relay, &|network| network())
    }
    #[doc(hidden)]
    pub fn submit_broadcaster_with_fence(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
        fence: &SubmissionFence<'_>,
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
            journal::ManagedPrepared::snapshot_funds(self)
                .snapshot()?
                .validate_broadcaster_submission(&saved.submitted_data)?;
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
            if let Some(id) = &saved.submission_id {
                let status = relay
                    .lookup_status(id)?
                    .ok_or("broadcaster submission not found; retain reservation")?;
                if &status.id != id {
                    return Err("broadcaster submission ID mismatch".into());
                }
                return Ok(status);
            }
            let result = relay.submit_member(
                &saved.submitted_data,
                &verified,
                &saved.sidecars,
                saved.member_proof.as_ref(),
            )?;
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
        if chain.historical_preparation() {
            return Err("live chain required for broadcaster submission validation".into());
        }
        let delegation_entered =
            self.delegates_broadcaster_execution(chain, relay, self.broadcaster.as_ref().unwrap());
        if delegation_entered {
            chain
                .delegated_network_fence()
                .ok_or("deployment receipt invalidated before submission entry")??;
        }
        // Managed sessions freeze before committing their journal. Reuse only the
        // immutable evidence; requirements and all live state are checked below
        // after that commit, never cached across the persistence boundary.
        self.validate_broadcaster_evidence()?;
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
        if s.provenance_mode().is_some() && !self.inputs().is_empty() && s.sidecars.len() != 1 {
            return Err("one Source sidecar required".into());
        }
        let frozen_quote = VerifiedQuote::authenticate(
            s.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: s.signer,
            },
            &s.submitted_data,
            0,
            s.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        if relay.submission_requirements(&frozen_quote)?
            != (s.quote.provenance_required == Some(true))
        {
            return Err("broadcaster provenance requirements changed".into());
        }
        let data = s.submitted_data.clone();
        // All immutable proofs and service requirements are resolved first.
        // Capture live state once after the journal commit, just before transport.
        let (current, now) = if delegation_entered {
            if !self.delegates_broadcaster_execution(chain, relay, s) {
                return Err("deployment receipt invalidated during submission".into());
            }
            self.validate_broadcaster_execution()?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock before epoch")?
                .as_secs();
            (self.encode_operation_call(Address::ZERO, true, now)?, now)
        } else {
            let block = chain.snapshot()?;
            (
                self.broadcaster_submission_call_at(chain, &block)?,
                block.timestamp,
            )
        };
        if current.data != data {
            return Err("prepared broadcaster submission changed".into());
        }
        let quote = VerifiedQuote::authenticate(
            s.quote.clone(),
            Trust {
                chain_id: self.context.chain_id,
                protocol: word_address(self.context.protocol_address)?,
                signer: s.signer,
            },
            &data,
            now,
            s.provenance_mode(),
        )
        .map_err(|e| e.to_string())?;
        fence(&|| {
            if delegation_entered {
                chain
                    .delegated_network_fence()
                    .ok_or("deployment receipt invalidated before final submission fence")?
            } else {
                chain.validate_submission_network()
            }
        })?;
        let saved = self.broadcaster.as_mut().unwrap();
        saved.attempted = true;
        let result =
            relay.submit_member(&data, &quote, &saved.sidecars, saved.member_proof.as_ref())?;
        saved.submission_id = Some(result.id.clone());
        Ok(result)
    }
    /// Exports the public packet without reading the chain or invoking a prover.
    pub fn export_provenance_proof(&self) -> Result<Option<source::ProvenanceProof>> {
        let packet = self
            .provenance_packet
            .lock()
            .map_err(|_| "provenance cache lock poisoned")?
            .clone();
        if let Some(packet) = &packet {
            self.validate_cached_provenance(packet)?;
        }
        Ok(packet)
    }
    pub fn prove_provenance(&self, chain: &dyn ChainState) -> Result<source::ProvenanceProof> {
        if self.provenance.is_none() {
            if let Some(factory) = &self.provenance_factory {
                let mut prepared = self.clone();
                prepared.provenance = Some(factory(self.context)?);
                return prepared.prove_provenance(chain);
            }
        }
        if let Some(packet) = self.export_provenance_proof()? {
            self.validate_cached_provenance(&packet)?;
            return Ok(packet);
        }
        self.reprove_provenance(chain)
    }
    fn validate_cached_provenance(&self, packet: &source::ProvenanceProof) -> Result<()> {
        let cap = self
            .provenance
            .as_ref()
            .ok_or("trusted provenance capability required")?;
        invisi_sdk_rpc::provenance_packet::validate_provenance_proof(packet, &cap.client.trust)?;
        self.validate_cached_native_statement(packet)
    }
    pub(super) fn validate_cached_native_statement(
        &self,
        packet: &source::ProvenanceProof,
    ) -> Result<()> {
        if self
            .provenance_data
            .as_ref()
            .is_some_and(|data| packet.data != hex(data))
        {
            return Err("cached provenance final calldata mismatch".into());
        }
        if self.proof.is_some() && packet.data != hex(&self.provenance_calldata()?) {
            return Err("cached provenance final proof bytes mismatch".into());
        }
        let data = hex::decode(
            packet
                .data
                .strip_prefix("0x")
                .ok_or("0x calldata required")?,
        )
        .map_err(|e| e.to_string())?;
        let call =
            InvisiCore::transact_0Call::abi_decode_validate(&data).map_err(|e| e.to_string())?;
        let Plan::Transfer {
            params,
            outputs,
            funding,
            capacity,
            ..
        } = &self.plan
        else {
            return Err("private Note transaction required".into());
        };
        let expected = abi::TransactRequest {
            params: params.clone(),
            deliveries: outputs.iter().map(|v| v.delivery.clone()).collect(),
            funding: funding.clone(),
        };
        let public = self
            .public_inputs()?
            .iter()
            .map(|v| hex(&v.to_be_bytes::<32>()))
            .collect::<Vec<_>>();
        if call.abi_encode() != data
            || call.r.abi_encode() != expected.abi_encode()
            || packet.public_inputs != public
            || packet.main_circuit_capacity != *capacity
        {
            return Err("cached provenance native statement mismatch".into());
        }
        Ok(())
    }
    /// Replaces cached evidence only after fresh proving and local validation succeed.
    pub fn reprove_provenance(&self, chain: &dyn ChainState) -> Result<source::ProvenanceProof> {
        if self.source_required()
            && self.funding().amount != U256::ZERO
            && self.funding().signature.is_empty()
        {
            return Err("final funding signature required before Source finalization".into());
        }

        if self.provenance.is_none() {
            if let Some(factory) = &self.provenance_factory {
                let mut prepared = self.clone();
                prepared.provenance = Some(factory(self.context)?);
                return prepared.reprove_provenance(chain);
            }
        }
        let cap = self
            .provenance
            .as_ref()
            .ok_or("trusted provenance capability required")?;
        let data = if let Some(data) = &self.provenance_data {
            data.clone()
        } else if self.proof.is_some() {
            self.provenance_calldata()?
        } else {
            let packet = self
                .provenance_packet
                .lock()
                .map_err(|_| "provenance cache lock poisoned")?
                .clone()
                .ok_or("ready transaction proof required for provenance")?;
            // Fresh Source rules may intentionally invalidate the old evidence, but never its retained native statement.
            self.validate_cached_native_statement(&packet)?;
            hex::decode(packet.data.trim_start_matches("0x")).map_err(|e| e.to_string())?
        };
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
        *self
            .provenance_packet
            .lock()
            .map_err(|_| "provenance cache lock poisoned")? = Some(packet.clone());
        Ok(packet)
    }
    pub fn with_provenance_calldata(mut self, data: Vec<u8>) -> Result<Self> {
        let call =
            InvisiCore::transact_0Call::abi_decode_validate(&data).map_err(|e| e.to_string())?;
        let Plan::Transfer {
            params,
            outputs,
            funding,
            ..
        } = &self.plan
        else {
            return Err("private Note transaction required".into());
        };
        let expected = abi::TransactRequest {
            params: params.clone(),
            deliveries: outputs.iter().map(|v| v.delivery.clone()).collect(),
            funding: funding.clone(),
        };
        if call.abi_encode() != data
            || call.r.abi_encode() != expected.abi_encode()
            || call._0.is_empty()
        {
            return Err("retained provenance calldata mismatch".into());
        }
        self.provenance_data = Some(data);
        if let Some(packet) = self
            .provenance_packet
            .lock()
            .map_err(|_| "provenance cache lock poisoned")?
            .as_ref()
        {
            self.validate_cached_native_statement(packet)?;
        }
        Ok(self)
    }
    pub(super) fn provenance_calldata(&self) -> Result<Vec<u8>> {
        if !["evm", "noir-recursive"].contains(&self.target.as_str()) {
            return Err("ready transaction required for provenance".into());
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
            &self.target,
            self.public_inputs()?.into_iter().map(field_word).collect(),
        )?;
        prover::assert_bundle(proof, &statement)?;
        let data = InvisiCore::transact_0Call {
            _0: proof.proof.clone().into(),
            r: abi::TransactRequest {
                params: params.clone(),
                deliveries: outputs.iter().map(|v| v.delivery.clone()).collect(),
                funding: funding.clone(),
            },
        }
        .abi_encode();
        if self.target == "noir-recursive" {
            invisi_sdk_rpc::broadcaster::aggregate_member_capacity(&data)
                .map_err(|e| e.to_string())?;
        }
        Ok(data)
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
        if cap.manifest.sha256.is_empty() || cap.manifest.sha256 != cap.client.trust.manifest_sha256
        {
            return Err("local provenance proving resources required".into());
        }
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
        let number = source_number(&c.confirmed_block_number)?;
        let hash = B256::from(source_word(&c.confirmed_block_hash)?.to_be_bytes::<32>());
        chain.canonical_anchor(number, hash)?;
        let id_root = format!("{}:{}", c.chain_generation, c.root_sequence);
        let tree = cap.client.sync_recognized_tree(&id_root, c, count.max(1))?;
        chain.canonical_anchor(number, hash)?;
        trees.insert(*id, tree);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{test_support::note_fixture, *};
    use super::*;
    fn cache_word(n: U256) -> String {
        hex(&n.to_be_bytes::<32>())
    }
    fn cache_split(n: B256) -> [U256; 2] {
        [U256::from_be_slice(&n[..16]), U256::from_be_slice(&n[16..])]
    }
    fn cached_packet_fixture() -> (source::ProvenanceProof, source::TrustContext) {
        let golden: Value = serde_json::from_str(include_str!(
            "../../testdata/provenance-golden-vectors.json"
        ))
        .unwrap();
        let mut fields = golden["certificate"]["fields"].clone();
        for value in fields.as_object_mut().unwrap().values_mut() {
            *value = json!(value.to_string())
        }
        fields["signature"] = json!(format!(
            "0x{}",
            golden["certificate"]["signatureHex"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
        ));
        let certificate: RootCertificate = serde_json::from_value(fields).unwrap();
        let spki = hex::decode(
            golden["certificate"]["publicKeySpkiHex"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let key: [u8; 32] = spki[spki.len() - 32..].try_into().unwrap();
        let trust = source::TrustContext {
            scope: source::Scope {
                chain_id: 4,
                protocol_address: U256::from(5),
            },
            chain_generation: 6,
            provider_id: U256::from(1),
            signing_keys: BTreeMap::from([(U256::from(2), key)]),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: "a".repeat(64),
        };
        let request = abi::TransactRequest {
            params: abi::CrossTreeTransactParams {
                token: Address::from_slice(&U256::from(2).to_be_bytes::<32>()[12..]),
                sources: vec![abi::InputSource {
                    treeId: U256::from(1),
                    merkleRoot: B256::from(U256::from(11).to_be_bytes::<32>()),
                }],
                nullifiers: vec![B256::from(U256::from(12).to_be_bytes::<32>())],
                noteCommitments: vec![],
                withdrawalAddress: Address::from_slice(&U256::from(10).to_be_bytes::<32>()[12..]),
                withdrawalAmount: U256::from(1),
                deadline: U256::from(100),
                feeRecipient: Address::ZERO,
                feeAmount: U256::ZERO,
            },
            deliveries: vec![],
            funding: abi::FundingParams {
                amount: U256::ZERO,
                payer: Address::ZERO,
                sigNonce: U256::ZERO,
                deadline: U256::ZERO,
                signature: Bytes::new(),
                permit: crate::protocol::IMetaTx::TokenPermit {
                    deadline: U256::ZERO,
                    v: 0,
                    r: B256::ZERO,
                    s: B256::ZERO,
                },
            },
        };
        // The fixed native statement is independent of the decoder. Only ZK proof bytes are mocked; the certificate uses a signed cross-SDK vector.
        let mut words = vec![4, 5, 2, 1, 0, 1, 1, 11, 12]
            .into_iter()
            .map(U256::from)
            .collect::<Vec<_>>();
        words.extend(cache_split(keccak256(
            (request.deliveries.clone(),).abi_encode_params(),
        )));
        words.extend([10, 1, 100, 0, 0, 0, 0].map(U256::from));
        let auth=invisi_sdk_primitives::wallet::authorization_digest(&json!({"operation":"transact","capacity":1,"context":{"chainId":"4","protocolAddress":"5"},"words":words.iter().map(U256::to_string).collect::<Vec<_>>()})).unwrap();
        words.extend(cache_split(B256::from(auth)));
        let digest = source::operation_digest(&trust.scope, 1, &words).unwrap();
        let digest_value = U256::from_be_bytes(digest);
        let sd = source::sources_digest(
            6,
            &[Source {
                tree_id: 8,
                root: U256::from(10),
                leaf_count: 9,
            }],
        )
        .unwrap();
        let nd = source::input_digest(&[U256::from(12)]).unwrap();
        let limbs = source::limbs(digest_value);
        let binding = source::binding_digest(
            source::scope_hash(&trust.scope).unwrap(),
            U256::from(2),
            6,
            1,
            sd,
            1,
            digest_value,
            nd,
        )
        .unwrap();
        let pi = [
            U256::from(4),
            U256::from(5),
            U256::from(2),
            U256::from(6),
            U256::from(1),
            sd,
            U256::from(1),
            limbs[0],
            limbs[1],
            nd,
            binding,
        ]
        .map(cache_word)
        .to_vec();
        let packet = source::ProvenanceProof {
            format: "invisi-provenance-submission-v1".into(),
            data: format!(
                "0x{}",
                hex::encode(
                    InvisiCore::transact_0Call {
                        _0: Bytes::from(vec![1, 2]),
                        r: request
                    }
                    .abi_encode()
                )
            ),
            context: source::ProofContext {
                chain_id: "4".into(),
                protocol_address: "0x0000000000000000000000000000000000000005".into(),
                token_address: "0x0000000000000000000000000000000000000002".into(),
            },
            main_circuit_capacity: 1,
            public_inputs: words.into_iter().map(cache_word).collect(),
            operation_digest: cache_word(digest_value),
            sidecars: vec![ProofSidecar {
                operation_index: "0".into(),
                proof_bundle: source::ProofBundle {
                    format: "invisi-provenance-proof-v1".into(),
                    circuit_id: "provenance_k10".into(),
                    manifest_sha256: trust.manifest_sha256.clone(),
                    target: "evm".into(),
                    public_inputs: pi,
                    proof: "0x0102".into(),
                    root_certificates: vec![certificate],
                },
            }],
        };
        (packet, trust)
    }
    #[test]
    fn cached_public_packet_is_local_and_failed_reproof_preserves_it() {
        let (chain, wallet, params, _) = note_fixture();
        let (packet, trust) = cached_packet_fixture();
        let call = InvisiCore::transact_0Call::abi_decode_validate(
            &hex::decode(packet.data.trim_start_matches("0x")).unwrap(),
        )
        .unwrap();
        let mut prepared = Invisi::new(chain.clone())
            .prepare_transfer(&wallet, params)
            .unwrap();
        prepared.context = ProtocolContext {
            chain_id: 4,
            protocol_address: U256::from(5),
        };
        prepared.token = call.r.params.token;
        prepared.plan = Plan::Transfer {
            params: call.r.params,
            inputs: vec![],
            outputs: vec![],
            funding: call.r.funding,
            capacity: 1,
        };
        prepared.provenance = Some(Arc::new(PreparedProvenance {
            client: Arc::new(ProvenanceClient::new("http://127.0.0.1:1", trust).unwrap()),
            manifest: source::authenticate_manifest(
                include_bytes!("../../provenance/manifest.json"),
                "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762",
            )
            .unwrap(),
            prover: Arc::new(NoProver),
            budgets: SourceReplayBudgets::default(),
        }));
        *prepared.provenance_packet.lock().unwrap() = Some(packet.clone());
        assert!(prepared.proof.is_none());
        assert_eq!(
            prepared.prove_provenance(chain.as_ref()).unwrap().data,
            packet.data
        );
        let before = serde_json::to_value(prepared.export_provenance_proof().unwrap()).unwrap();
        assert!(prepared.reprove_provenance(chain.as_ref()).is_err());
        assert_eq!(
            serde_json::to_value(prepared.export_provenance_proof().unwrap()).unwrap(),
            before
        );
        let snapshot = journal::ManagedPrepared::snapshot_funds(&prepared)
            .snapshot()
            .unwrap();
        let saved = serde_json::to_value(snapshot).unwrap();
        assert_eq!(saved["provenancePacket"]["data"], packet.data);
        let mut original = saved.clone();
        original.as_object_mut().unwrap().remove("provenancePacket");
        original["ready"] = json!(true);
        let mut retained: journal::PreparedSnapshot =
            serde_json::from_value(original.clone()).unwrap();
        retained
            .update_provenance_proof(&journal::ManagedPrepared::snapshot_funds(&prepared))
            .unwrap();
        let mut updated = serde_json::to_value(retained).unwrap();
        assert_eq!(
            updated.as_object_mut().unwrap().remove("provenancePacket"),
            Some(saved["provenancePacket"].clone())
        );
        assert_eq!(updated, original);

        let mut wrong = packet.clone();
        wrong.public_inputs[0] = "0x01".into();
        *prepared.provenance_packet.lock().unwrap() = Some(wrong);
        assert!(prepared.prove_provenance(chain.as_ref()).is_err());
    }
    #[test]
    fn string_errors_cannot_acknowledge_pre_send_refusal() {
        for message in [
            "CREDIT_PERIOD_CHANGED: regenerate",
            "RPC -32025: INSUFFICIENT_EXECUTION_SLACK: refresh",
            "CREDIT_PERIOD_ENDING: regenerate",
        ] {
            assert!(BroadcasterSubmitError::Unknown(message.into())
                .pre_send_refusal()
                .is_none());
            assert!(
                BroadcasterSubmitError::Rpc(invisi_sdk_rpc::rpc::Error::Transport(message.into()))
                    .pre_send_refusal()
                    .is_none()
            );
        }
    }
    struct ClientQuoteTransport {
        context: ProtocolContext,
        fee: u64,
    }
    impl RpcTransport for ClientQuoteTransport {
        fn send(&self, request: &Value) -> invisi_sdk_rpc::rpc::Result<Value> {
            let relay = SignedRelay {
                fees: 0.into(),
                quotes: 0.into(),
            };
            let result = match request["method"].as_str().unwrap() {
                "broadcaster_estimateQuote" => json!(RelayFee {
                    fee_recipient: relay.configuration().fee_recipient,
                    fee_amount: self.fee.to_string(),
                    max_gas: "100000".into(),
                }),
                "broadcaster_getQuote" => {
                    let data =
                        hex_bytes(request["params"][0]["data"].as_str().unwrap(), None).unwrap();
                    json!(PreparedBroadcaster::quote(
                        &relay,
                        &data,
                        self.context.chain_id,
                        word_address(self.context.protocol_address).unwrap(),
                        0,
                        &[]
                    )
                    .unwrap()
                    .signed())
                }
                "broadcaster_getTransactionStatus" => {
                    json!({"id":request["params"][0]["id"],"state":"pending"})
                }
                "broadcaster_cancelTransaction" => {
                    json!({"id":request["params"][0]["id"],"state":"cancelled"})
                }
                method => panic!("unexpected quote RPC: {method}"),
            };
            Ok(json!({"jsonrpc":"2.0", "id":request["id"], "result":result}))
        }
    }
    #[test]
    fn stock_shield_price_refresh_requires_structured_refusal_and_increase_under_cap() {
        struct DriftTransport {
            context: ProtocolContext,
            mode: &'static str,
            estimates: Arc<std::sync::atomic::AtomicUsize>,
            quotes: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl RpcTransport for DriftTransport {
            fn send(&self, request: &Value) -> invisi_sdk_rpc::rpc::Result<Value> {
                let fee = if request["method"] == "broadcaster_estimateQuote" {
                    let count = self
                        .estimates
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if count == 0 || self.mode == "unchanged" {
                        2
                    } else {
                        5
                    }
                } else {
                    5
                };
                if request["method"] == "broadcaster_getQuote"
                    && self
                        .quotes
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        == 0
                {
                    if self.mode == "transport" {
                        return Err(invisi_sdk_rpc::rpc::Error::Transport(
                            "lost quote response".into(),
                        ));
                    }
                    if self.mode == "bad-signature" {
                        let mut result = ClientQuoteTransport {
                            context: self.context,
                            fee,
                        }
                        .send(request)?;
                        result["result"]["signature"] = json!("0x00");
                        return Ok(result);
                    }
                    return Ok(
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":if self.mode == "other-code" {-32602} else {-32000},"message":"Request rejected"}}),
                    );
                }
                ClientQuoteTransport {
                    context: self.context,
                    fee,
                }
                .send(request)
            }
        }
        for (mode, cap, succeeds, expected_estimates) in [
            ("increase", 10, true, 2),
            ("increase", 4, false, 2),
            ("unchanged", 10, false, 2),
            ("transport", 10, false, 1),
            ("bad-signature", 10, false, 1),
            ("other-code", 10, false, 1),
        ] {
            let (chain, wallet, p, _) = note_fixture();
            let prepared = Invisi::new(chain.clone())
                .prepare_shield_with_signature_funding(
                    &wallet,
                    ShieldPreparation {
                        token: p.token,
                        outputs: vec![NoteOutput::identity(
                            chain.context,
                            p.token,
                            U256::from(123),
                            U256::from(20),
                        )
                        .unwrap()],
                        funding: abi::FundingParams {
                            amount: U256::from(20),
                            payer: wallet.owner_address,
                            ..empty_funding()
                        },
                        fee: Fee::default(),
                        deadline: 100,
                    },
                    SignatureFundingNonce::Current,
                )
                .unwrap();
            let estimates = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let quotes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let relay = BroadcasterClient::new(
                SignedRelay {
                    fees: 0.into(),
                    quotes: 0.into(),
                }
                .configuration(),
                DriftTransport {
                    context: chain.context,
                    mode,
                    estimates: estimates.clone(),
                    quotes: quotes.clone(),
                },
            )
            .unwrap();
            let result = prepared.quote_for_broadcaster(
                chain,
                Arc::new(relay),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(cap)),
                    ..Default::default()
                },
            );
            assert_eq!(result.is_ok(), succeeds, "{mode} cap={cap}");
            assert_eq!(
                estimates.load(std::sync::atomic::Ordering::SeqCst),
                expected_estimates,
                "{mode}"
            );
            assert!(
                prepared.broadcaster_state().is_none(),
                "failed candidate altered original"
            );
            if let Ok(finalized) = result {
                assert_eq!(finalized.funding().amount, U256::from(25));
                assert_eq!(quotes.load(std::sync::atomic::Ordering::SeqCst), 2);
            }
        }
    }
    #[test]
    fn stock_plain_shield_quotes_paid_features_with_one_estimate() {
        struct ObservedTransport {
            inner: ClientQuoteTransport,
            calls: Arc<std::sync::Mutex<Vec<Value>>>,
        }
        impl RpcTransport for ObservedTransport {
            fn send(&self, request: &Value) -> invisi_sdk_rpc::rpc::Result<Value> {
                self.calls.lock().unwrap().push(request.clone());
                self.inner.send(request)
            }
        }
        let (chain, fixture_wallet, p, _) = note_fixture();
        let signing = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let wallet = Wallet::from_keys(
            Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
            fixture_wallet.receiving_keys().clone(),
        )
        .unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![NoteOutput::for_recipient(
                        chain.context,
                        p.token,
                        &wallet,
                        U256::from(20),
                        Vec::new(),
                    )
                    .unwrap()],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner_address,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap();
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay = BroadcasterClient::new(
            SignedRelay {
                fees: 0.into(),
                quotes: 0.into(),
            }
            .configuration(),
            ObservedTransport {
                inner: ClientQuoteTransport {
                    context: chain.context,
                    fee: 2,
                },
                calls: calls.clone(),
            },
        )
        .unwrap();
        let authority = chain.clone();
        let quoted = prepared
            .quote_for_broadcaster(
                chain,
                Arc::new(relay),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(10)),
                    ..Default::default()
                },
            )
            .unwrap();
        let calls = calls.lock().unwrap();
        let methods: Vec<_> = calls
            .iter()
            .map(|r| r["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            vec!["broadcaster_estimateQuote", "broadcaster_getQuote"]
        );
        let initial = hex_bytes(calls[0]["params"][0]["data"].as_str().unwrap(), None).unwrap();
        let intent = invisi_sdk_rpc::broadcaster::decode_intent(&initial).unwrap();
        assert_eq!(intent.fee_amount, U256::from(1));
        assert_eq!(
            intent.fee_recipient,
            quoted.broadcaster_state().unwrap().fee_recipient
        );
        assert_eq!(quoted.funding().amount, U256::from(22));
        let snapshot = journal::ManagedPrepared::snapshot_funds(&quoted)
            .snapshot()
            .unwrap();
        let mut saved = serde_json::to_value(&snapshot).unwrap();
        let restored: journal::PreparedSnapshot = serde_json::from_value(saved.clone()).unwrap();
        let journal::ManagedPrepared::Funds(restored) = restored.restore(&wallet, None).unwrap()
        else {
            panic!("funds expected")
        };
        assert!(restored.outputs()[0].self_contained);
        assert!(restored.stock_broadcaster.is_some());
        assert!(quoted.clone().ready().is_err());
        let request = quoted
            .export_funding_authorization(authority.as_ref())
            .unwrap();
        let (sig, id) = signing
            .sign_prehash_recoverable(request.digest.as_slice())
            .unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(id.to_byte());
        let authorized = quoted
            .clone()
            .with_funding_signature(authority.as_ref(), signature)
            .unwrap();
        let ready = authorized.ready().unwrap();
        let ready_snapshot = journal::ManagedPrepared::snapshot_funds(&ready)
            .snapshot()
            .unwrap();
        let ready_snapshot: journal::PreparedSnapshot =
            serde_json::from_slice(&serde_json::to_vec(&ready_snapshot).unwrap()).unwrap();
        let journal::ManagedPrepared::Funds(ready_restored) =
            ready_snapshot.restore(&wallet, None).unwrap()
        else {
            panic!("funds expected")
        };
        assert_eq!(ready_restored.phase(), Phase::Ready);
        assert!(ready_restored.stock_broadcaster.is_some());
        assert!(ready_restored.outputs()[0].self_contained);
        saved["outputs"][0]
            .as_object_mut()
            .unwrap()
            .remove("selfContained");
        saved.as_object_mut().unwrap().remove("stockBroadcaster");
        saved
            .as_object_mut()
            .unwrap()
            .remove("selectedFundingTerms");
        let legacy: journal::PreparedSnapshot = serde_json::from_value(saved).unwrap();
        let journal::ManagedPrepared::Funds(legacy) = legacy.restore(&wallet, None).unwrap() else {
            panic!("funds expected")
        };
        assert!(!legacy.outputs()[0].self_contained);
        assert!(legacy.stock_broadcaster.is_none());
        let mut tampered = serde_json::to_value(&snapshot).unwrap();
        tampered["broadcaster"]["quote"]["quote"]["feeAmount"] = json!("999");
        let tampered: journal::PreparedSnapshot = serde_json::from_value(tampered).unwrap();
        assert!(tampered.restore(&wallet, None).is_err());
    }
    #[test]
    fn client_lifecycle_accepts_note_and_credit_and_leaves_failed_target_unchanged() {
        let (chain, wallet, mut p, _) = note_fixture();
        p.outputs =
            vec![
                NoteOutput::identity(chain.context(), p.token, U256::from(123), U256::from(1))
                    .unwrap(),
            ];
        p.withdrawal = None;
        p.automatic_change = true;
        let mut note = Invisi::new(chain.clone())
            .prepare_transfer(&wallet, p)
            .unwrap();
        let relay = SignedRelay {
            fees: 0.into(),
            quotes: 0.into(),
        };
        let client = crate::broadcaster::BroadcasterClient::new(
            relay.configuration(),
            ClientQuoteTransport {
                context: chain.context(),
                fee: 1,
            },
        )
        .unwrap();
        let options = BroadcasterOptions {
            max_fee_amount: Some(U256::from(10)),
            ..Default::default()
        };
        client.quote(&mut note, chain.clone(), &options).unwrap();
        assert_eq!(
            note.broadcaster_state().unwrap().quote.quote.fee_amount,
            "1"
        );
        let state = CreditDeliveryState {
            note: crate::credit::CreditState {
                context: chain.context(),
                token_address: address_word(note.token),
                spender_wallet_identity: address_word(Address::repeat_byte(2)),
                owner_wallet_identity: address_word(wallet.owner_address()),
                grant_id: 1,
                nonce: U256::from(74),
                expiry: chain.snapshot().unwrap().timestamp + 1000,
                credit_shared_key: U256::from(75),
                policy: crate::credit::CreditPolicy::default(),
                usage: crate::credit::CreditUsage::default(),
                available_credit: U256::from(400),
                unlimited: false,
                payload: Vec::new(),
            },
            owner_receiving_keys: wallet.receiving_keys().clone(),
            spender_receiving_keys: wallet.receiving_keys().clone(),
        };
        let mut credit = Invisi::new(chain.clone())
            .prepare_create_credit_explicit(
                &wallet,
                state,
                chain.snapshot().unwrap().timestamp + 100,
                Fee::default(),
            )
            .unwrap()
            .with_broadcaster_fee_budget(chain.as_ref(), U256::from(10))
            .unwrap();
        let before = serde_json::to_value(
            journal::ManagedPrepared::Credit(credit.clone())
                .snapshot()
                .unwrap(),
        )
        .unwrap();
        let expensive = crate::broadcaster::BroadcasterClient::new(
            relay.configuration(),
            ClientQuoteTransport {
                context: chain.context(),
                fee: 11,
            },
        )
        .unwrap();
        assert!(expensive
            .quote(&mut credit, chain.clone(), &options)
            .is_err());
        assert_eq!(
            serde_json::to_value(
                journal::ManagedPrepared::Credit(credit.clone())
                    .snapshot()
                    .unwrap()
            )
            .unwrap(),
            before
        );
        client.quote(&mut credit, chain.clone(), &options).unwrap();
        assert_eq!(
            credit.broadcaster_state().unwrap().quote.quote.fee_amount,
            "1"
        );

        assert!(client.cancel(&mut note).unwrap_err().contains("recover"));
        assert!(client.cancel(&mut credit).unwrap_err().contains("recover"));
        let note_data = note.broadcaster_intent().unwrap().data;
        let credit_data = credit.broadcaster_intent().unwrap().data;
        for (state, data) in [
            (note.broadcaster.as_mut().unwrap(), note_data),
            (credit.broadcaster.as_mut().unwrap(), credit_data),
        ] {
            state.attempted = true;
            state.submitted_data = data;
            state.submission_id = Some("server-owned".into());
        }
        assert!(client
            .submit(&mut note, chain.as_ref())
            .unwrap_err()
            .contains("proof"));
        assert!(client
            .submit(&mut credit, chain.as_ref())
            .unwrap_err()
            .contains("proof"));
        for state in [
            note.broadcaster.as_mut().unwrap(),
            credit.broadcaster.as_mut().unwrap(),
        ] {
            let token = CancellationToken::generate();
            state.quote.quote.schedule = Some(invisi_sdk_rpc::broadcaster::Schedule {
                publish_after: "1".into(),
                execute_before: "2".into(),
                cancel_token_hash: token.commitment(),
            });
            state.cancellation_token = Some(token);
        }
        assert_eq!(
            client.cancel(&mut note).unwrap().state,
            invisi_sdk_rpc::broadcaster::StatusState::Cancelled
        );
        assert_eq!(
            client.cancel(&mut credit).unwrap().state,
            invisi_sdk_rpc::broadcaster::StatusState::Cancelled
        );
    }
    #[test]
    fn signed_source_requirement_resolves_factory_without_legacy_hint() {
        struct SourceQuoteTransport(ClientQuoteTransport);
        impl RpcTransport for SourceQuoteTransport {
            fn send(&self, request: &Value) -> invisi_sdk_rpc::rpc::Result<Value> {
                if request["method"] == "broadcaster_getStatus" {
                    let relay = SignedRelay {
                        fees: 0.into(),
                        quotes: 0.into(),
                    };
                    return Ok(
                        json!({"jsonrpc":"2.0","id":request["id"],"result":{"apiVersion":"v1","protocolVersion":"1","chainId":self.0.context.chain_id.to_string(),"protocol":word_address(self.0.context.protocol_address).unwrap(),"sender":relay.configuration().quote_signer,"feeRecipient":relay.configuration().fee_recipient,"submissionHalted":false,"provenance":{"enabled":true,"requestHashFormat":invisi_sdk_rpc::broadcaster::REQUEST_HASH_FORMAT,"trackingRequired":true,"trackingSupported":true}}}),
                    );
                }
                let mut response = self.0.send(request)?;
                if request["method"] == "broadcaster_getQuote" {
                    let mut signed: SignedQuote =
                        serde_json::from_value(response["result"].clone()).unwrap();
                    signed.quote.request_hash =
                        B256::from(source::provenance_intent_hash(signed.quote.request_hash.0));
                    signed.request_hash_format =
                        Some(invisi_sdk_rpc::broadcaster::REQUEST_HASH_FORMAT.into());
                    signed.provenance_required = Some(true);
                    let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
                    let public = key.verifying_key().to_encoded_point(false);
                    let trust = Trust {
                        chain_id: self.0.context.chain_id,
                        protocol: word_address(self.0.context.protocol_address).unwrap(),
                        signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
                    };
                    let (signature, recovery) = key
                        .sign_prehash_recoverable(
                            invisi_sdk_rpc::broadcaster::quote_digest(&signed.quote, &trust)
                                .unwrap()
                                .as_slice(),
                        )
                        .unwrap();
                    let mut bytes = signature.to_bytes().to_vec();
                    bytes.push(recovery.to_byte());
                    signed.signature = hex(&bytes);
                    response["result"] = serde_json::to_value(signed).unwrap();
                }
                Ok(response)
            }
        }
        let (chain, wallet, mut params, _) = note_fixture();
        params.outputs = vec![NoteOutput::identity(
            chain.context(),
            params.token,
            U256::from(123),
            U256::from(1),
        )
        .unwrap()];
        params.withdrawal = None;
        params.automatic_change = true;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let mut runtime = Invisi::new(chain.clone());
        runtime.provenance_factory = Some(Arc::new(move |_| {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("source factory reached".into())
        }));
        let mut prepared = runtime.prepare_transfer(&wallet, params).unwrap();
        let relay = SignedRelay {
            fees: 0.into(),
            quotes: 0.into(),
        };
        let client = crate::broadcaster::BroadcasterClient::new(
            relay.configuration(),
            SourceQuoteTransport(ClientQuoteTransport {
                context: chain.context(),
                fee: 1,
            }),
        )
        .unwrap();
        assert!(PreparedBroadcaster::provenance_mode(client.rpc()).is_none());
        client
            .quote(
                &mut prepared,
                chain.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(10)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let capacity = match &prepared.plan {
            Plan::Transfer { capacity, .. } => *capacity,
            _ => unreachable!(),
        };
        let statement = prover::statement(
            &format!("transact_user_slots{capacity}"),
            "evm",
            prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(field_word)
                .collect(),
        )
        .unwrap();
        let proof = vec![0; 32];
        prepared.proof = Some(ProofBundle {
            format_version: 1,
            circuit_name: statement.circuit_name,
            target: statement.target,
            bb_version: "6.0.0".into(),
            artifact_sha256: statement.artifact_sha256,
            vk_sha256: statement.vk_sha256,
            proof_sha256: prover::sha256(&proof),
            proof,
            public_inputs: statement.expected_public_inputs,
        });
        prepared.phase = Phase::Proved;
        let error = prepared
            .freeze_broadcaster_evidence(chain.as_ref(), client.rpc())
            .unwrap_err();
        assert!(error.contains("source factory reached"), "{error}");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut unauthenticated = prepared.clone();
        unauthenticated
            .broadcaster
            .as_mut()
            .unwrap()
            .quote
            .signature = "0x00".into();
        assert!(unauthenticated
            .freeze_broadcaster_evidence(chain.as_ref(), client.rpc())
            .is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (_, wrong_trust) = cached_packet_fixture();
        let wrong_scope = Arc::new(PreparedProvenance {
            client: Arc::new(ProvenanceClient::new("http://127.0.0.1:1", wrong_trust).unwrap()),
            manifest: source::authenticate_manifest(
                include_bytes!("../../provenance/manifest.json"),
                "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762",
            )
            .unwrap(),
            prover: Arc::new(NoProver),
            budgets: SourceReplayBudgets::default(),
        });
        // A restored frozen packet must reject duplicate valid Source bundles before
        // any final capability-specific validation, even when no proving is needed.
        let mut duplicated = prepared.clone();
        duplicated.provenance = Some(wrong_scope.clone());
        let (packet, _) = cached_packet_fixture();
        source::validate_proof_bundle(&packet.sidecars[0].proof_bundle, &wrong_scope.client.trust)
            .unwrap();
        let data = duplicated
            .encode_operation_call(Address::ZERO, true, chain.snapshot().unwrap().timestamp)
            .unwrap()
            .data;
        let frozen = duplicated.broadcaster.as_mut().unwrap();
        frozen.submitted_data = data;
        frozen.sidecars = vec![packet.sidecars[0].clone(), packet.sidecars[0].clone()];
        assert!(duplicated
            .submit_for_broadcaster(chain.as_ref(), client.rpc())
            .unwrap_err()
            .contains("one Source sidecar required"));
        prepared.provenance_factory = Some(Arc::new(move |_| Ok(wrong_scope.clone())));
        assert!(prepared
            .freeze_broadcaster_evidence(chain.as_ref(), client.rpc())
            .unwrap_err()
            .contains("deployment/provenance/manifest mismatch"));
    }
    #[test]
    fn original_preparation_survives_missing_provenance_capability() {
        let (chain, wallet, p, _) = note_fixture();
        let prepared = Invisi::new(chain.clone())
            .prepare_transfer(&wallet, p)
            .unwrap();
        let relay = Arc::new(MissingCapabilityRelay);
        assert!(prepared
            .quote_for_broadcaster(
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
    fn expired_unsubmitted_quote_renews_the_same_authorized_intent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (chain, wallet, p, _) = note_fixture();
        let relay = Arc::new(SignedRelay {
            fees: AtomicUsize::new(0),
            quotes: AtomicUsize::new(0),
        });
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![NoteOutput::identity(
                        chain.context,
                        p.token,
                        U256::from(123),
                        U256::from(20),
                    )
                    .unwrap()],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner_address,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap()
            .quote_for_broadcaster(
                chain.clone(),
                relay.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        let data = prepared.broadcaster_intent().unwrap().data;
        let mut saved = prepared.broadcaster_state().unwrap().clone();
        saved.quote.quote.deadline = "10".into();
        let trust = Trust {
            chain_id: chain.context.chain_id,
            protocol: word_address(chain.context.protocol_address).unwrap(),
            signer: saved.signer,
        };
        let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
        let (sig, recovery) = key
            .sign_prehash_recoverable(
                invisi_sdk_rpc::broadcaster::quote_digest(&saved.quote.quote, &trust)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery.to_byte());
        saved.quote.signature = hex(&signature);
        assert_eq!(
            submission_quote(&saved, chain.context, relay.as_ref(), &data, 9)
                .unwrap()
                .signed(),
            &saved.quote
        );
        assert_eq!(relay.quotes.load(Ordering::SeqCst), 1);
        let renewed = submission_quote(&saved, chain.context, relay.as_ref(), &data, 11).unwrap();
        assert_eq!(renewed.signed().quote.deadline, "100");
        assert_eq!(
            renewed.signed().quote.request_hash,
            saved.quote.quote.request_hash
        );
        assert_eq!(
            renewed.signed().quote.fee_amount,
            saved.quote.quote.fee_amount
        );
        assert_eq!(relay.fees.load(Ordering::SeqCst), 3);
        assert_eq!(relay.quotes.load(Ordering::SeqCst), 2);
        assert_eq!(saved.quote.quote.deadline, "10");
        for attempted in [false, true] {
            let mut frozen = saved.clone();
            if attempted {
                frozen.attempted = true;
            } else {
                frozen.submitted_data = data.clone();
            }
            assert!(submission_quote(&frozen, chain.context, relay.as_ref(), &data, 11).is_err());
        }
        assert!(
            submission_quote(&saved, chain.context, relay.as_ref(), &data, 101)
                .unwrap_err()
                .contains("intent expired")
        );
        let mut tampered = saved.clone();
        tampered.quote.quote.fee_amount = "3".into();
        assert!(submission_quote(&tampered, chain.context, relay.as_ref(), &data, 11).is_err());
        let mut foreign = saved.clone();
        foreign.endpoint = "https://other.example".into();
        assert!(submission_quote(&foreign, chain.context, relay.as_ref(), &data, 11).is_err());
        assert_eq!(relay.quotes.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn fee_convergence_attaches_only_final_signed_intent_and_freezes_funding() {
        let (chain, fixture_wallet, p, _) = note_fixture();
        let signing = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let wallet = Wallet::from_keys(owner, fixture_wallet.receiving_keys().clone()).unwrap();
        let output =
            NoteOutput::identity(chain.context, p.token, U256::from(123), U256::from(20)).unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner_address,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
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
            .quote_for_broadcaster(
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
            .quote_for_broadcaster(chain.clone(), relay.clone(), &BroadcasterOptions::default())
            .unwrap_err()
            .contains("maximum"));
        let quoted = prepared
            .quote_for_broadcaster(
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
        assert!(quoted
            .broadcaster_state()
            .unwrap()
            .cancel(relay.as_ref(), "invented-id")
            .unwrap_err()
            .contains("recover"));
        let request = quoted.export_funding_authorization(chain.as_ref()).unwrap();
        let (sig, recovery) = signing
            .sign_prehash_recoverable(request.digest.as_slice())
            .unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery.to_byte());
        let mut attempted = quoted
            .clone()
            .with_funding_signature(chain.as_ref(), signature)
            .unwrap()
            .ready()
            .unwrap();
        let retained = attempted.broadcaster.as_mut().unwrap();
        retained.attempted = true;
        let mut source_state = retained.clone();
        source_state.sidecars = vec![ProofSidecar {
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
            data: retained.submitted_data.clone(),
            sidecars: serde_json::json!([]),
            lookup: None,
            response: "server-id".into(),
        };
        let mut tampered = attempted.clone();
        tampered.broadcaster.as_mut().unwrap().sidecars = source_state.sidecars;
        assert!(tampered
            .submit_for_broadcaster(chain.as_ref(), relay.as_ref())
            .unwrap_err()
            .contains("unexpected frozen Source evidence"));
        assert_eq!(
            attempted
                .submit_for_broadcaster(chain.as_ref(), &replay)
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
            .submit_for_broadcaster(chain.as_ref(), &wrong)
            .unwrap_err()
            .contains("ID mismatch"));
        let wrong = RetryRelay {
            response: "different".into(),
            ..replay.clone()
        };
        assert!(attempted
            .submit_for_broadcaster(chain.as_ref(), &wrong)
            .unwrap_err()
            .contains("not found"));
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
            .submit_for_broadcaster(chain.as_ref(), &wrong)
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
    fn frozen_funds_submit_rejects_changed_call_or_member_before_transport() {
        let (chain, fixture_wallet, p, _) = note_fixture();
        let signing = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let wallet = Wallet::from_keys(owner, fixture_wallet.receiving_keys().clone()).unwrap();
        let relay = Arc::new(SignedRelay {
            fees: 0.into(),
            quotes: 0.into(),
        });
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![NoteOutput::identity(
                        chain.context,
                        p.token,
                        U256::from(123),
                        U256::from(20),
                    )
                    .unwrap()],
                    funding: abi::FundingParams {
                        payer: owner,
                        amount: U256::from(20),
                        ..empty_funding()
                    },
                    fee: Default::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap()
            .quote_for_broadcaster(
                chain.clone(),
                relay.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        let request = prepared
            .export_funding_authorization(chain.as_ref())
            .unwrap();
        let (signature, recovery) = signing
            .sign_prehash_recoverable(request.digest.as_slice())
            .unwrap();
        let mut signature = signature.to_bytes().to_vec();
        signature.push(recovery.to_byte());
        let mut prepared = prepared
            .with_funding_signature(chain.as_ref(), signature)
            .unwrap()
            .ready()
            .unwrap();
        prepared
            .freeze_broadcaster_evidence(chain.as_ref(), relay.as_ref())
            .unwrap();
        let mut changed = prepared.clone();
        changed.broadcaster.as_mut().unwrap().submitted_data.push(0);
        assert!(changed
            .submit_for_broadcaster(chain.as_ref(), relay.as_ref())
            .is_err());
        let mut changed = prepared;
        changed.broadcaster.as_mut().unwrap().member_proof = Some(MemberProof {
            format_version: 1,
            circuit_name: "tampered".into(),
            target: "noir-recursive".into(),
            bb_version: "6.0.0".into(),
            artifact_sha256: "00".repeat(32),
            vk_sha256: "00".repeat(32),
            proof_hex: "0x00".into(),
            proof_sha256: "00".repeat(32),
            public_inputs: vec![],
        });
        assert!(changed
            .submit_for_broadcaster(chain.as_ref(), relay.as_ref())
            .is_err());
    }

    #[test]
    fn failed_fee_convergence_does_not_attach_or_consume_original() {
        let (chain, wallet, p, _) = note_fixture();
        let output =
            NoteOutput::identity(chain.context, p.token, U256::from(123), U256::from(20)).unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner_address,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap();
        let relay = Arc::new(SignedRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            quotes: std::sync::atomic::AtomicUsize::new(0),
        });
        assert!(prepared
            .quote_for_broadcaster(
                chain,
                relay.clone(),
                &BroadcasterOptions {
                    max_attempts: 1,
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
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
            include_bytes!("../../provenance/manifest.json"),
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
        let mut config = json!({"endpoint":"http://127.0.0.1:1","chainId":"31337","protocolAddress":"0x1234","generation":"1","providerId":"0x01","signingKeyId":"0x01","signingPublicKey":format!("0x{}","00".repeat(32)),"manifestSha256":"6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762","assetRoot":std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("provenance"),"bbBinary":"unused","noirExecutor":"unused","timeoutSeconds":120,"threads":4,"budgets":{"maxRootPages":1,"maxCertificates":1,"maxTotalLeaves":1}});
        config["opening"] = json!({"nonce":"1"});
        assert!(serde_json::from_value::<LocalProvenanceConfiguration>(config.clone()).is_err());
        config.as_object_mut().unwrap().remove("opening");
        let invalid_config = serde_json::from_value(config.clone()).unwrap();
        let error = PreparedProvenance::from_local_configuration(invalid_config)
            .err()
            .unwrap();
        assert!(error.contains("key ID mismatch"), "{error}");
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
    #[test]
    fn cached_source_packet_binds_the_actual_recursive_main_proof_bytes() {
        let (chain, wallet, preparation, _) = note_fixture();
        let mut prepared = Invisi::new(chain)
            .prepare_transfer(&wallet, preparation)
            .unwrap();
        prepared.target = "noir-recursive".into();
        let capacity = match &prepared.plan {
            Plan::Transfer { capacity, .. } => *capacity,
            _ => unreachable!(),
        };
        let statement = prover::statement(
            &format!("transact_user_slots{capacity}"),
            &prepared.target,
            prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(field_word)
                .collect(),
        )
        .unwrap();
        let proof = vec![0; 458 * 32];
        prepared.proof = Some(ProofBundle {
            format_version: 1,
            circuit_name: statement.circuit_name,
            target: statement.target,
            bb_version: "6.0.0".into(),
            artifact_sha256: statement.artifact_sha256,
            vk_sha256: statement.vk_sha256,
            proof_sha256: prover::sha256(&proof),
            proof,
            public_inputs: statement.expected_public_inputs,
        });
        let packet = source::ProvenanceProof {
            format: "invisi-provenance-submission-v1".into(),
            data: hex(&prepared.provenance_calldata().unwrap()),
            context: source::ProofContext {
                chain_id: prepared.context.chain_id.to_string(),
                protocol_address: hex(word_address(prepared.context.protocol_address)
                    .unwrap()
                    .as_slice()),
                token_address: hex(prepared.token.as_slice()),
            },
            main_circuit_capacity: capacity,
            public_inputs: prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(|v| hex(&v.to_be_bytes::<32>()))
                .collect(),
            operation_digest: "unused".into(),
            sidecars: vec![],
        };
        prepared.validate_cached_native_statement(&packet).unwrap();
        let proof = prepared.proof.as_mut().unwrap();
        proof.proof[0] = 1;
        proof.proof_sha256 = prover::sha256(&proof.proof);
        assert!(prepared
            .validate_cached_native_statement(&packet)
            .unwrap_err()
            .contains("proof bytes"));
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
                reason_code: None,
                publish_after: None,
                execute_before: None,
                confirmation: None,
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
                reason_code: None,
                publish_after: None,
                execute_before: None,
                confirmation: None,
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
        fn fee(&self, _: Address, data: Option<&[u8]>) -> Result<RelayFee> {
            assert!(data.is_some(), "final intent calldata required");
            let n = self.fees.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(RelayFee {
                fee_amount: if n % 2 == 0 { "1" } else { "2" }.into(),
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
                schedule: None,
                execution: invisi_sdk_rpc::broadcaster::Execution::Direct,
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
    #[test]
    fn repeated_quotes_retain_the_original_funds_read_set() {
        let (chain, wallet, p, _) = note_fixture();
        let output =
            NoteOutput::identity(chain.context(), p.token, U256::from(123), U256::from(20))
                .unwrap();
        let mut prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token: p.token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        amount: U256::from(20),
                        payer: wallet.owner_address,
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap();
        let original = prepared.preparation_reads.clone().unwrap();
        for _ in 0..2 {
            prepared = prepared
                .quote_for_broadcaster(
                    chain.clone(),
                    Arc::new(SignedRelay {
                        fees: 0.into(),
                        quotes: 0.into(),
                    }),
                    &BroadcasterOptions {
                        max_fee_amount: Some(U256::from(100)),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(
                Arc::ptr_eq(&original, prepared.preparation_reads.as_ref().unwrap()),
                "quote replaced the operation read set"
            );
        }
    }
    #[test]
    fn exact_public_transfer_adds_fee_and_requests_only_final_gross_permit() {
        let (chain, wallet, mut p, _) = note_fixture();
        let business = sum(p.inputs.iter().map(|i| i.note.amount)).unwrap() + U256::from(20);
        p.withdrawal = None;
        p.outputs = vec![
            NoteOutput::identity(chain.context(), p.token, U256::from(123), business).unwrap(),
        ];
        p.funding = abi::FundingParams {
            amount: U256::from(20),
            payer: wallet.owner_address(),
            ..empty_funding()
        };
        p.fee = Fee::default();
        p.automatic_change = false;
        let prepared = Invisi::new(chain.clone())
            .prepare_transfer_with_signature_funding(&wallet, p, SignatureFundingNonce::Current)
            .unwrap();
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = calls.clone();
        let quoted = prepared
            .quote_for_broadcaster(
                chain,
                Arc::new(SignedRelay {
                    fees: 0.into(),
                    quotes: 0.into(),
                }),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    funding_permit: Some(Arc::new(move |request| {
                        seen.lock().unwrap().push(request.amount);
                        Ok(empty_funding().permit)
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(quoted.funding().amount > U256::from(20));
        assert_eq!(*calls.lock().unwrap(), vec![quoted.funding().amount]);
        assert_eq!(quoted.outputs()[0].amount(), business);
    }
    #[test]
    fn payout_fee_reprices_frozen_gross_and_requires_positive_net() {
        let (chain, wallet, mut p, _) = note_fixture();
        p.outputs.clear();
        p.withdrawal = Some((
            wallet.owner_address(),
            sum(p.inputs.iter().map(|i| i.note.amount)).unwrap(),
        ));
        p.fee = Fee::default();
        p.funding = empty_funding();
        p.automatic_change = false;
        let gross = p.withdrawal.unwrap().1;
        let prepared = Invisi::new(chain.clone())
            .prepare_transfer(&wallet, p)
            .unwrap();
        let relay = Arc::new(SignedRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            quotes: std::sync::atomic::AtomicUsize::new(0),
        });
        let quoted = prepared
            .quote_for_broadcaster(
                chain.clone(),
                relay,
                &BroadcasterOptions {
                    fee_source: Some(BroadcasterFeeSource::Payout),
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        match &quoted.plan {
            Plan::Transfer {
                params,
                inputs,
                outputs,
                funding,
                ..
            } => {
                assert_eq!(params.withdrawalAmount + params.feeAmount, gross);
                assert_eq!(params.feeAmount, U256::from(2));
                assert!(!inputs.is_empty());
                assert!(outputs.is_empty());
                assert_eq!(funding.amount, U256::ZERO);
            }
            _ => panic!("withdrawal required"),
        }
        assert!(quoted.needs_authorization());
        assert!(prepared.broadcaster_state().is_none());
    }
    #[test]
    fn payout_rejects_funding_change_and_fee_cap() {
        for shape in ["funding", "change", "cap"] {
            let (chain, wallet, mut p, _) = note_fixture();
            let gross = sum(p.inputs.iter().map(|i| i.note.amount)).unwrap();
            p.outputs.clear();
            p.fee = Fee::default();
            p.funding = empty_funding();
            p.withdrawal = Some((wallet.owner_address(), gross));
            p.automatic_change = false;
            if shape == "funding" {
                p.funding.amount = U256::from(1);
                p.funding.payer = wallet.owner_address();
                p.withdrawal = Some((wallet.owner_address(), gross + U256::from(1)));
            }
            if shape == "change" {
                p.withdrawal = Some((wallet.owner_address(), gross - U256::from(1)));
                p.automatic_change = true;
            }
            let prepared = Invisi::new(chain.clone())
                .prepare_transfer(&wallet, p)
                .unwrap();
            let relay = Arc::new(SignedRelay {
                fees: 0.into(),
                quotes: 0.into(),
            });
            assert!(
                prepared
                    .quote_for_broadcaster(
                        chain,
                        relay.clone(),
                        &BroadcasterOptions {
                            fee_source: Some(BroadcasterFeeSource::Payout),
                            max_fee_amount: Some(U256::from(if shape == "cap" { 1 } else { 100 })),
                            ..Default::default()
                        }
                    )
                    .is_err(),
                "{shape}"
            );
            assert!(prepared.broadcaster_state().is_none());
            assert_eq!(relay.quotes.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }
    include!("preparation_profile.rs");
}

#[cfg(test)]
mod alignment_defaults_tests {
    use super::*;
    #[test]
    fn bounded_defaults_match_portable_clients() {
        assert_eq!(BroadcasterOptions::default().max_attempts, 4);
        assert_eq!(SourceReplayBudgets::default().max_root_pages, 10);
        assert_eq!(SourceReplayBudgets::default().max_total_leaves, 100_000);
    }
}
