//! Registered relay quotes bind canonical public calldata, deployment context and exact fees.
use crate::protocol::{InvisiCore, ProtocolContract};
use crate::rpc::{self, decimal, Error, HttpTransport, JsonRpc, Result, RpcTransport};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface, SolValue};
use invisi_sdk_protocol::provenance::{provenance_intent_hash, ProofSidecar};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
pub const REQUEST_HASH_FORMAT: &str = "invisi-broadcaster-provenance-intent-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trust {
    pub chain_id: u64,
    pub protocol: Address,
    pub signer: Address,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Execution {
    Direct,
    Aggregate,
}
impl Execution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Aggregate => "aggregate",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    pub execution: Execution,
    pub token: Address,
    pub fee_recipient: Address,
    pub fee_amount: String,
    pub deadline: String,
    pub max_gas: String,
    pub request_hash: B256,
}
/// Public scheduling commitment; cancellation preimages must never be sent with a quote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Schedule {
    pub publish_after: String,
    pub execute_before: String,
    #[serde(deserialize_with = "canonical_cancel_hash")]
    pub cancel_token_hash: B256,
}
fn canonical_cancel_hash<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<B256, D::Error> {
    let value = String::deserialize(deserializer)?;
    let hash: B256 = value.parse().map_err(serde::de::Error::custom)?;
    if hash == B256::ZERO || value != format!("{hash}") {
        return Err(serde::de::Error::custom("noncanonical cancellation hash"));
    }
    Ok(hash)
}
impl Schedule {
    pub fn validate(&self) -> Result<(u64, u64)> {
        let parse = |v: &str| -> Result<u64> {
            let n = v
                .parse::<u64>()
                .map_err(|_| Error::Invalid("invalid schedule timestamp"))?;
            if n == 0 || n > rpc::MAX_SAFE_INTEGER || n.to_string() != v {
                return Err(Error::Invalid("noncanonical schedule timestamp"));
            }
            Ok(n)
        };
        let after = parse(&self.publish_after)?;
        let before = parse(&self.execute_before)?;
        if before <= after || self.cancel_token_hash == B256::ZERO {
            return Err(Error::Invalid(
                "invalid schedule bounds or cancellation hash",
            ));
        }
        Ok((after, before))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulingCapability {
    pub enabled: bool,
    pub max_delay_seconds: String,
    pub default_execution_window_seconds: String,
    pub max_execution_window_seconds: String,
    pub min_deadline_slack_seconds: String,
}
impl SchedulingCapability {
    pub fn validate_schedule(&self, schedule: &Schedule, now: u64, deadline: U256) -> Result<()> {
        let (after, before) = schedule.validate()?;
        let parse = |s: &str| -> Result<u64> {
            let v = s
                .parse::<u64>()
                .map_err(|_| Error::Invalid("invalid scheduling capability seconds"))?;
            if v == 0 || v > rpc::MAX_SAFE_INTEGER || v.to_string() != s {
                return Err(Error::Invalid("invalid scheduling capability seconds"));
            }
            Ok(v)
        };
        let max_delay = parse(&self.max_delay_seconds)?;
        let default_window = parse(&self.default_execution_window_seconds)?;
        let max_window = parse(&self.max_execution_window_seconds)?;
        let slack = parse(&self.min_deadline_slack_seconds)?;
        if !self.enabled
            || default_window > max_window
            || after <= now
            || after - now > max_delay
            || before - after > max_window
            || deadline < U256::from(before) + U256::from(slack)
        {
            return Err(Error::Invalid(
                "schedule outside broadcaster capability or intent deadline",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedQuote {
    pub quote: Quote,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_required: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub method: &'static str,
    pub token: Address,
    pub fee_recipient: Address,
    pub fee_amount: U256,
    pub deadline: U256,
}
fn stripped_intent(data: &[u8]) -> Result<(Intent, Vec<u8>)> {
    let call = ProtocolContract::decode_call(data)
        .map_err(|_| Error::Invalid("unsupported broadcaster calldata"))?;
    if call.abi_encode() != data {
        return Err(Error::Invalid("noncanonical broadcaster calldata"));
    }
    use InvisiCore::InvisiCoreCalls as Calls;
    let make = |method, token, fee_recipient, fee_amount, deadline| Intent {
        method,
        token,
        fee_recipient,
        fee_amount,
        deadline,
    };
    Ok(match call {
        Calls::shield(mut c) => {
            let p = &c.p;
            let intent = make("shield", p.token, p.feeRecipient, p.feeAmount, p.deadline);
            c._3.signature = Bytes::new();
            (intent, c.abi_encode())
        }
        Calls::transact_0(mut c) => {
            let p = &c.r.params;
            let intent = make("transact", p.token, p.feeRecipient, p.feeAmount, p.deadline);
            c._0 = Bytes::new();
            c.r.funding.signature = Bytes::new();
            (intent, c.abi_encode())
        }
        Calls::createCredit(mut c) => {
            let p = &c.p;
            let intent = make(
                "createCredit",
                p.token,
                p.feeRecipient,
                p.feeAmount,
                p.deadline,
            );
            c._0 = Bytes::new();
            (intent, c.abi_encode())
        }
        Calls::updateCredit(mut c) => {
            let p = &c.p;
            let intent = make(
                "updateCredit",
                p.token,
                p.feeRecipient,
                p.feeAmount,
                p.deadline,
            );
            c._0 = Bytes::new();
            (intent, c.abi_encode())
        }
        Calls::creditDraw(mut c) => {
            let p = &c.p;
            let intent = make(
                "creditDraw",
                p.token,
                p.feeRecipient,
                p.feeAmount,
                p.deadline,
            );
            c._0 = Bytes::new();
            (intent, c.abi_encode())
        }
        Calls::revokeCredit(mut c) => {
            let intent = make(
                "revokeCredit",
                c.token,
                c.feeRecipient,
                c.feeAmount,
                c.deadline,
            );
            c.signature = Bytes::new();
            (intent, c.abi_encode())
        }
        _ => {
            return Err(Error::Invalid(
                "broadcaster accepts only supported direct operations",
            ))
        }
    })
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemberProof {
    pub format_version: u32,
    pub circuit_name: String,
    pub target: String,
    pub bb_version: String,
    pub artifact_sha256: String,
    pub vk_sha256: String,
    pub proof_hex: String,
    pub proof_sha256: String,
    pub public_inputs: Vec<B256>,
}
pub fn validate_member_proof(data: &[u8], proof: &MemberProof) -> Result<()> {
    use sha2::{Digest, Sha256};
    let capacity = aggregate_member_capacity(data)?;
    let InvisiCore::InvisiCoreCalls::transact_0(call) = ProtocolContract::decode_call(data)
        .map_err(|_| Error::Invalid("invalid member calldata"))?
    else {
        unreachable!()
    };
    let expected = invisi_sdk_protocol::statements::statement(
        &format!("transact_user_slots{capacity}"),
        "noir-recursive",
        proof.public_inputs.clone(),
    )
    .map_err(|_| Error::Invalid("invalid member statement"))?;
    let bytes = rpc::bytes(&json!(proof.proof_hex), 458 * 32, 458 * 32)?;
    if proof.format_version != 1
        || proof.target != "noir-recursive"
        || proof.bb_version != "6.0.0"
        || proof.circuit_name != expected.circuit_name
        || proof.artifact_sha256 != expected.artifact_sha256
        || proof.vk_sha256 != expected.vk_sha256
        || bytes.as_slice() != call._0.as_ref()
        || hex::encode(Sha256::digest(&bytes)) != proof.proof_sha256
        || U256::from_be_slice(proof.public_inputs[3].as_slice())
            != U256::from(call.r.params.nullifiers.len())
        || U256::from_be_slice(proof.public_inputs[4].as_slice())
            != U256::from(call.r.params.noteCommitments.len())
    {
        return Err(Error::Invalid("invalid broadcaster member proof"));
    }
    Ok(())
}
/// Match the canonical outer transaction without trusting a relay's claimed member list.
pub fn matches_execution_transaction(
    member_data: &[u8],
    execution: Execution,
    transaction_data: &[u8],
) -> bool {
    if execution == Execution::Direct {
        return member_data == transaction_data;
    }
    if aggregate_member_capacity(member_data).is_err() {
        return false;
    }
    use InvisiCore::InvisiCoreCalls as Calls;
    let (Ok(Calls::transact_0(member)), Ok(Calls::transact_1(outer))) = (
        ProtocolContract::decode_call(member_data),
        ProtocolContract::decode_call(transaction_data),
    ) else {
        return false;
    };
    outer.abi_encode() == transaction_data
        && outer
            .requests
            .iter()
            .filter(|request| request.abi_encode() == member.r.abi_encode())
            .count()
            == 1
}
pub fn aggregate_member_capacity(data: &[u8]) -> Result<usize> {
    use InvisiCore::InvisiCoreCalls as Calls;
    match ProtocolContract::decode_call(data) {
        Ok(Calls::transact_0(c)) if c.abi_encode() == data => {
            let capacity = c.r.params.nullifiers.len() + c.r.params.noteCommitments.len();
            if c.r.params.nullifiers.is_empty()
                || !(1..=10).contains(&capacity)
                || c.r.funding.amount != U256::ZERO
            {
                return Err(Error::Invalid(
                    "unfunded private C1 through C10 member required",
                ));
            }
            Ok(capacity)
        }
        _ => Err(Error::Invalid(
            "unfunded private C1 through C10 member required",
        )),
    }
}
pub fn decode_intent(data: &[u8]) -> Result<Intent> {
    Ok(stripped_intent(data)?.0)
}
pub fn request_hash(data: &[u8]) -> Result<B256> {
    let (intent, stripped) = stripped_intent(data)?;
    Ok(keccak256(
        (
            "InvisiBroadcasterIntentV1",
            intent.method,
            Bytes::from(stripped),
        )
            .abi_encode_params(),
    ))
}
pub fn quote_digest(quote: &Quote, trust: &Trust) -> Result<B256> {
    if trust.chain_id == 0 || trust.protocol == Address::ZERO || trust.signer == Address::ZERO {
        return Err(Error::Invalid("invalid broadcaster trust"));
    }
    let domain=keccak256((keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),keccak256("InvisiBroadcaster"),keccak256("1"),U256::from(trust.chain_id),trust.protocol).abi_encode());
    let structure = if let Some(schedule) = &quote.schedule {
        let (after, before) = schedule.validate()?;
        keccak256((keccak256("ScheduledQuote(address token,address feeRecipient,uint256 feeAmount,uint256 deadline,uint256 maxGas,bytes32 requestHash,string execution,uint256 publishAfter,uint256 executeBefore,bytes32 cancelTokenHash)"),quote.token,quote.fee_recipient,decimal(&json!(quote.fee_amount))?,decimal(&json!(quote.deadline))?,decimal(&json!(quote.max_gas))?,quote.request_hash,keccak256(quote.execution.as_str()),U256::from(after),U256::from(before),schedule.cancel_token_hash).abi_encode())
    } else {
        keccak256((keccak256("Quote(address token,address feeRecipient,uint256 feeAmount,uint256 deadline,uint256 maxGas,bytes32 requestHash,string execution)"),quote.token,quote.fee_recipient,decimal(&json!(quote.fee_amount))?,decimal(&json!(quote.deadline))?,decimal(&json!(quote.max_gas))?,quote.request_hash,keccak256(quote.execution.as_str())).abi_encode())
    };

    let mut message = vec![0x19, 0x01];
    message.extend_from_slice(domain.as_slice());
    message.extend_from_slice(structure.as_slice());
    Ok(keccak256(message))
}
pub fn verify_quote(signed: &SignedQuote, trust: &Trust, data: &[u8], now: u64) -> Result<()> {
    verify_quote_for_provenance(signed, trust, data, now, None)
}
pub fn verify_quote_for_provenance(
    signed: &SignedQuote,
    trust: &Trust,
    data: &[u8],
    now: u64,
    provenance: Option<()>,
) -> Result<()> {
    if signed.provenance_required == Some(false)
        || (provenance.is_some() && signed.provenance_required != Some(true))
    {
        return Err(Error::Invalid("invalid broadcaster provenance metadata"));
    }
    let base = request_hash(data)?;
    let hash = if signed.provenance_required == Some(true) {
        if signed.request_hash_format.as_deref() != Some(REQUEST_HASH_FORMAT) {
            return Err(Error::Invalid("broadcaster provenance format mismatch"));
        }
        B256::from(provenance_intent_hash(base.0))
    } else {
        if signed.request_hash_format.is_some() {
            return Err(Error::Invalid("unexpected broadcaster provenance metadata"));
        }
        base
    };
    verify_quote_with_hash(signed, trust, data, now, hash)
}
pub(crate) fn verify_quote_with_hash(
    signed: &SignedQuote,
    trust: &Trust,
    data: &[u8],
    now: u64,
    expected_hash: B256,
) -> Result<()> {
    let intent = decode_intent(data)?;
    let quote = &signed.quote;
    if quote.execution == Execution::Aggregate {
        aggregate_member_capacity(data)?;
    }
    let amount = decimal(&json!(quote.fee_amount))?;
    let deadline = decimal(&json!(quote.deadline))?;
    let gas = decimal(&json!(quote.max_gas))?;
    if quote.request_hash != expected_hash
        || quote.token != intent.token
        || quote.fee_recipient != intent.fee_recipient
        || amount != intent.fee_amount
        || amount == U256::ZERO
        || amount >= U256::from(1) << 128
        || gas == U256::ZERO
        || deadline > intent.deadline
    {
        return Err(Error::Invalid(
            "quote does not match final intent or bounds",
        ));
    }
    if deadline < U256::from(now) {
        return Err(Error::Invalid("broadcaster quote expired"));
    }
    let bytes = rpc::bytes(&json!(signed.signature), 65, 65)?;
    let recovery = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => return Err(Error::Invalid("invalid quote recovery id")),
    };
    let signature = Signature::from_slice(&bytes[..64])
        .map_err(|_| Error::Invalid("invalid quote signature"))?;
    if signature.normalize_s().is_some() {
        return Err(Error::Invalid("noncanonical quote signature"));
    }
    let key = VerifyingKey::recover_from_prehash(
        quote_digest(quote, trust)?.as_slice(),
        &signature,
        RecoveryId::try_from(recovery).map_err(|_| Error::Invalid("invalid quote recovery id"))?,
    )
    .map_err(|_| Error::Invalid("invalid quote signature"))?;
    let public = key.to_encoded_point(false);
    let address = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
    if address != trust.signer {
        return Err(Error::Invalid("untrusted quote signer"));
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub endpoint: String,
    pub quote_signer: Address,
    pub fee_recipient: Address,
}
impl Configuration {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| Error::Invalid("invalid broadcaster endpoint"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || self.quote_signer == Address::ZERO
            || self.fee_recipient == Address::ZERO
        {
            return Err(Error::Invalid(
                "broadcaster requires HTTPS and registered nonzero addresses",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct VerifiedQuote {
    signed: SignedQuote,
    trust: Trust,
}
impl VerifiedQuote {
    pub fn authenticate(
        signed: SignedQuote,
        trust: Trust,
        data: &[u8],
        now: u64,
        provenance: Option<()>,
    ) -> Result<Self> {
        verify_quote_for_provenance(&signed, &trust, data, now, provenance)?;
        Ok(Self { signed, trust })
    }
    pub fn signed(&self) -> &SignedQuote {
        &self.signed
    }
    pub fn trust(&self) -> &Trust {
        &self.trust
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fee {
    pub fee_recipient: Address,
    pub fee_amount: String,
    pub max_gas: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusState {
    Pending,
    Scheduled,
    Preparing,
    Cancelled,
    Queued,
    Proving,
    Rejected,
    Expired,
    Submitted,
    Confirmed,
    Reverted,
    Uncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationBlock {
    pub number: String,
    pub hash: B256,
    pub timestamp: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "serde_json::Value")]
pub struct Confirmation {
    pub level: rpc::ConfirmationLevel,
    pub status: rpc::FinalityStatus,
    pub block: Option<ConfirmationBlock>,
}
impl TryFrom<serde_json::Value> for Confirmation {
    type Error = String;
    fn try_from(v: serde_json::Value) -> std::result::Result<Self, String> {
        if v.as_object()
            .is_none_or(|o| o.len() != 3 || !o.contains_key("block"))
        {
            return Err("invalid broadcaster confirmation".into());
        }
        let level =
            serde_json::from_value(v["level"].clone()).map_err(|_| "invalid confirmation level")?;
        let status = serde_json::from_value(v["status"].clone())
            .map_err(|_| "invalid confirmation status")?;
        let block = if v["block"].is_null() {
            None
        } else {
            let block: ConfirmationBlock = serde_json::from_value(v["block"].clone())
                .map_err(|_| "invalid confirmation block")?;
            rpc::uint(&serde_json::Value::String(block.number.clone()), 64)
                .map_err(|_| "invalid confirmation block number")?;
            if block.timestamp > rpc::MAX_SAFE_INTEGER {
                return Err("unsafe confirmation timestamp".into());
            }
            Some(block)
        };
        if level == rpc::ConfirmationLevel::Pending && block.is_some()
            || level != rpc::ConfirmationLevel::Pending
                && block.is_none()
                && (status == rpc::FinalityStatus::Available
                    || level == rpc::ConfirmationLevel::Safe
                    || level == rpc::ConfirmationLevel::Finalized)
        {
            return Err("invalid confirmation anchor".into());
        }
        Ok(Self {
            level,
            status,
            block,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "optional_confirmation"
    )]
    pub confirmation: Option<Confirmation>,
    pub id: String,
    pub state: StatusState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<B256>,
}
fn optional_confirmation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Confirmation>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    serde_json::from_value(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
pub struct BroadcasterClient<T: RpcTransport> {
    configuration: Configuration,
    rpc: JsonRpc<T>,
    provenance_mode: Option<()>,
}
impl BroadcasterClient<HttpTransport> {
    pub fn connect(configuration: Configuration) -> Result<Self> {
        configuration.validate()?;
        let transport = HttpTransport::new(&configuration.endpoint)?.with_response_limit(65536)?;
        Self::new(configuration, transport)
    }
}
impl<T: RpcTransport> BroadcasterClient<T> {
    pub fn new(configuration: Configuration, transport: T) -> Result<Self> {
        configuration.validate()?;
        Ok(Self {
            configuration,
            rpc: JsonRpc::new(transport),
            provenance_mode: None,
        })
    }
    pub fn with_provenance_mode(mut self) -> Self {
        self.provenance_mode = Some(());
        self
    }
    pub fn provenance_mode(&self) -> Option<()> {
        self.provenance_mode
    }
    pub fn supports_token(&self, token: Address, chain_id: u64, protocol: Address) -> Result<bool> {
        if token == Address::ZERO {
            return Err(Error::Invalid("nonzero token required"));
        }
        let value = self.rpc.call(
            "broadcaster_getTokenSupport",
            json!([{"tokenAddress":token}]),
        )?;
        let supported = value["supported"]
            .as_bool()
            .ok_or(Error::Invalid("invalid token support"))?;
        let halted = value["submissionHalted"]
            .as_bool()
            .ok_or(Error::Invalid("invalid token support"))?;
        if value["apiVersion"] != "v1"
            || value["protocolVersion"] != "1"
            || decimal(&value["chainId"])? != U256::from(chain_id)
            || value["protocol"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(protocol)
            || value["sender"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(self.configuration.quote_signer)
            || value["feeRecipient"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(self.configuration.fee_recipient)
            || value["tokenAddress"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(token)
            || value["provenance"]["enabled"].as_bool().is_none()
        {
            return Err(Error::Invalid("invalid token support identity"));
        }
        Ok(supported && !halted)
    }
    pub fn submission_requirements(&self, quote: &VerifiedQuote) -> Result<bool> {
        let value = self.rpc.call("broadcaster_getStatus", json!([]))?;
        let p = &value["provenance"];
        let required = p["enabled"]
            .as_bool()
            .ok_or(Error::Invalid("invalid broadcaster service status"))?;
        if value["apiVersion"] != "v1"
            || value["protocolVersion"] != "1"
            || decimal(&value["chainId"])? != U256::from(quote.trust.chain_id)
            || value["protocol"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(quote.trust.protocol)
            || value["sender"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(self.configuration.quote_signer)
            || value["feeRecipient"]
                .as_str()
                .and_then(|v| v.parse::<Address>().ok())
                != Some(self.configuration.fee_recipient)
            || value["submissionHalted"] != false
            || (quote.signed.quote.execution == Execution::Aggregate
                && p["aggregateSupported"] != true)
            || required != (quote.signed.provenance_required == Some(true))
            || (required
                && (p["requestHashFormat"] != REQUEST_HASH_FORMAT
                    || p["trackingRequired"] != true
                    || p["trackingSupported"] != true))
        {
            return Err(Error::Invalid(
                "broadcaster requirements changed or invalid; obtain a new quote",
            ));
        }
        Ok(required)
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn estimate_quote(&self, data: &[u8]) -> Result<Fee> {
        self.estimate_quote_with_schedule(data, None)
    }
    pub fn estimate_quote_with_schedule(
        &self,
        data: &[u8],
        schedule: Option<&Schedule>,
    ) -> Result<Fee> {
        let intent = decode_intent(data)?;
        self.fee_with_schedule(intent.token, Some(data), schedule)
    }
    pub fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<Fee> {
        self.fee_with_schedule(token, data, None)
    }
    pub fn fee_with_schedule(
        &self,
        token: Address,
        data: Option<&[u8]>,
        schedule: Option<&Schedule>,
    ) -> Result<Fee> {
        if token == Address::ZERO {
            return Err(Error::Invalid("nonzero fee token required"));
        }
        let data = data.ok_or(Error::Invalid(
            "public calldata required for broadcaster estimate",
        ))?;
        decode_intent(data)?;
        let mut params = json!({"data":format!("0x{}", hex::encode(data))});
        if let Some(schedule) = schedule {
            schedule.validate()?;
            params["schedule"] = json!(schedule);
        }
        let fee: Fee = serde_json::from_value(
            self.rpc
                .call("broadcaster_estimateQuote", json!([params]))?,
        )
        .map_err(|_| Error::Invalid("invalid broadcaster fee"))?;
        let amount = decimal(&json!(fee.fee_amount))?;
        let gas = decimal(&json!(fee.max_gas))?;
        if fee.fee_recipient != self.configuration.fee_recipient
            || amount == U256::ZERO
            || amount >= U256::from(1) << 128
            || gas == U256::ZERO
        {
            return Err(Error::Invalid(
                "invalid broadcaster fee bounds or recipient",
            ));
        }
        Ok(fee)
    }
    pub fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
    ) -> Result<VerifiedQuote> {
        self.quote_with_sidecars(data, chain_id, protocol, now, &[])
    }
    pub fn quote_with_sidecars(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> Result<VerifiedQuote> {
        self.quote_with_schedule(data, chain_id, protocol, now, sidecars, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn quote_with_schedule(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
        schedule: Option<&Schedule>,
    ) -> Result<VerifiedQuote> {
        if let Some(schedule) = schedule {
            self.scheduling_capability()?.validate_schedule(
                schedule,
                now,
                decode_intent(data)?.deadline,
            )?;
        }
        if self.provenance_mode.is_none() && !sidecars.is_empty() {
            return Err(Error::Invalid("unexpected proof sidecars"));
        }
        decode_intent(data)?;
        let _wire = sidecars
            .iter()
            .map(invisi_sdk_protocol::provenance::proof_sidecar_to_wire)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid("invalid proof sidecar"))?;
        let mut params = json!({"data":format!("0x{}",hex::encode(data))});
        if let Some(schedule) = schedule {
            params["schedule"] = json!(schedule);
        }
        let signed: SignedQuote =
            serde_json::from_value(self.rpc.call("broadcaster_getQuote", json!([params]))?)
                .map_err(|_| Error::Invalid("invalid signed broadcaster quote"))?;
        if signed.quote.schedule.as_ref() != schedule {
            return Err(Error::Invalid("quote schedule mismatch"));
        }
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.configuration.quote_signer,
        };
        verify_quote_for_provenance(&signed, &trust, data, now, self.provenance_mode)?;
        if signed.quote.fee_recipient != self.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered quote fee recipient"));
        }
        Ok(VerifiedQuote { signed, trust })
    }
    pub fn submit_transaction(&self, data: &[u8], verified: &VerifiedQuote) -> Result<Status> {
        self.submit_with_sidecars(data, verified, &[])
    }
    pub fn submit_with_sidecars(
        &self,
        data: &[u8],
        verified: &VerifiedQuote,
        sidecars: &[ProofSidecar],
    ) -> Result<Status> {
        self.submit_with_member_proof(data, verified, sidecars, None)
    }
    pub fn submit_with_member_proof(
        &self,
        data: &[u8],
        verified: &VerifiedQuote,
        sidecars: &[ProofSidecar],
        member_proof: Option<&MemberProof>,
    ) -> Result<Status> {
        decode_intent(data)?;
        if (verified.signed.quote.execution == Execution::Aggregate) != member_proof.is_some() {
            return Err(Error::Invalid("quote execution and member proof mismatch"));
        }
        if let Some(proof) = member_proof {
            validate_member_proof(data, proof)?;
        }
        if verified.signed.provenance_required != Some(true) && !sidecars.is_empty() {
            return Err(Error::Invalid("unexpected proof sidecars"));
        }
        let wire = sidecars
            .iter()
            .map(invisi_sdk_protocol::provenance::proof_sidecar_to_wire)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid("invalid proof sidecar"))?;
        let mut trust = verified.trust.clone();
        trust.signer = self.configuration.quote_signer;
        verify_quote_for_provenance(&verified.signed, &trust, data, 0, self.provenance_mode)?;
        if verified.signed.quote.fee_recipient != self.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered quote fee recipient"));
        }
        let mut request = json!({"data":format!("0x{}",hex::encode(data)),"quote":verified.signed.quote,"signature":verified.signed.signature,"proofSidecars":wire});
        if let Some(proof) = member_proof {
            request["memberProof"] = serde_json::to_value(proof)
                .map_err(|_| Error::Invalid("invalid broadcaster member proof"))?;
        }
        let status: Status = serde_json::from_value(
            self.rpc
                .call("broadcaster_submitTransaction", json!([request]))?,
        )
        .map_err(|_| Error::Invalid("invalid broadcaster status"))?;
        validate_id(&status.id)?;
        let returned_id = status.id.clone();
        check_status(status, &returned_id)
    }
    pub fn lookup_status(&self, id: &str) -> Result<Option<Status>> {
        match self.status(id) {
            Ok(status) => Ok(Some(status)),
            Err(Error::Remote { code: -32001, .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub fn cancel_transaction(&self, id: &str, cancel_token: B256) -> Result<Status> {
        validate_id(id)?;
        if cancel_token == B256::ZERO {
            return Err(Error::Invalid("invalid cancellation token"));
        }
        let status: Status = serde_json::from_value(self.rpc.call(
            "broadcaster_cancelTransaction",
            json!([{"id":id,"cancelToken":cancel_token}]),
        )?)
        .map_err(|_| Error::Invalid("invalid broadcaster cancellation status"))?;
        check_status(status, id)
    }
    pub fn scheduling_capability(&self) -> Result<SchedulingCapability> {
        let status = self.rpc.call("broadcaster_getStatus", json!([]))?;
        serde_json::from_value(status["scheduling"].clone())
            .map_err(|_| Error::Invalid("invalid scheduling capability"))
    }
    pub fn status(&self, id: &str) -> Result<Status> {
        validate_id(id)?;
        let status: Status = serde_json::from_value(
            self.rpc
                .call("broadcaster_getTransactionStatus", json!([{"id":id}]))?,
        )
        .map_err(|_| Error::Invalid("invalid broadcaster status"))?;
        check_status(status, id)
    }
}
fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 256 {
        return Err(Error::Invalid("invalid broadcaster id"));
    }
    Ok(())
}
fn check_status(status: Status, id: &str) -> Result<Status> {
    if let Some(confirmation) = &status.confirmation {
        if matches!(
            status.state,
            StatusState::Scheduled
                | StatusState::Preparing
                | StatusState::Cancelled
                | StatusState::Queued
                | StatusState::Proving
                | StatusState::Rejected
                | StatusState::Expired
        ) || confirmation.level != rpc::ConfirmationLevel::Pending
            && status.transaction_hash.is_none()
        {
            return Err(Error::Invalid("invalid broadcaster confirmation context"));
        }
    }
    if status.id != id {
        return Err(Error::Invalid("broadcaster status identity mismatch"));
    }
    Ok(status)
}
