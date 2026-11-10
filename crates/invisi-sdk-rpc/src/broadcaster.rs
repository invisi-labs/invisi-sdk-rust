//! Registered relay quotes bind canonical public calldata, deployment context and exact fees.
use crate::protocol::{InvisiProtocol, ProtocolContract};
use crate::rpc::{self, decimal, Error, HttpTransport, JsonRpc, Result, RpcTransport};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface, SolValue};
use invisi_sdk_core::provenance::{provenance_intent_hash, ProofSidecar};
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quote {
    pub token: Address,
    pub fee_recipient: Address,
    pub fee_amount: String,
    pub deadline: String,
    pub max_gas: String,
    pub request_hash: B256,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedQuote {
    pub quote: Quote,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_policy_id: Option<B256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash_format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_tracking: Option<crate::provenance_tracking::Tracking>,
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
    use InvisiProtocol::InvisiProtocolCalls as Calls;
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
    let structure=keccak256((keccak256("Quote(address token,address feeRecipient,uint256 feeAmount,uint256 deadline,uint256 maxGas,bytes32 requestHash)"),quote.token,quote.fee_recipient,decimal(&json!(quote.fee_amount))?,decimal(&json!(quote.deadline))?,decimal(&json!(quote.max_gas))?,quote.request_hash).abi_encode());
    let mut message = vec![0x19, 0x01];
    message.extend_from_slice(domain.as_slice());
    message.extend_from_slice(structure.as_slice());
    Ok(keccak256(message))
}
pub fn verify_quote(signed: &SignedQuote, trust: &Trust, data: &[u8], now: u64) -> Result<()> {
    verify_quote_for_policy(signed, trust, data, now, None)
}
pub fn verify_quote_for_policy(
    signed: &SignedQuote,
    trust: &Trust,
    data: &[u8],
    now: u64,
    policy: Option<B256>,
) -> Result<()> {
    let base = request_hash(data)?;
    let hash = match policy {
        Some(policy)
            if policy != B256::ZERO
                && signed.provenance_policy_id == Some(policy)
                && signed.request_hash_format.as_deref() == Some(REQUEST_HASH_FORMAT) =>
        {
            B256::from(provenance_intent_hash(
                base.0,
                U256::from_be_bytes(policy.0),
            ))
        }
        None if signed.provenance_policy_id.is_none()
            && signed.request_hash_format.is_none()
            && signed.provenance_tracking.is_none() =>
        {
            base
        }
        _ => return Err(Error::Invalid("broadcaster provenance policy mismatch")),
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
        || deadline < U256::from(now)
    {
        return Err(Error::Invalid(
            "quote does not match final intent or bounds",
        ));
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
        policy: Option<B256>,
    ) -> Result<Self> {
        verify_quote_for_policy(&signed, &trust, data, now, policy)?;
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
    Submitted,
    Confirmed,
    Reverted,
    Uncertain,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub id: String,
    pub state: StatusState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<B256>,
}
pub struct BroadcasterClient<T: RpcTransport> {
    configuration: Configuration,
    rpc: JsonRpc<T>,
    required_policy: Option<B256>,
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
            required_policy: None,
        })
    }
    pub fn with_provenance_policy(mut self, policy: B256) -> Result<Self> {
        if policy == B256::ZERO {
            return Err(Error::Invalid("nonzero provenance policy required"));
        }
        self.required_policy = Some(policy);
        Ok(self)
    }
    pub fn required_policy(&self) -> Option<B256> {
        self.required_policy
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<Fee> {
        if token == Address::ZERO {
            return Err(Error::Invalid("nonzero fee token required"));
        }
        let mut params = json!({"token":token});
        if let Some(data) = data {
            params["data"] = json!(format!("0x{}", hex::encode(data)));
        }
        let fee: Fee =
            serde_json::from_value(self.rpc.call("broadcaster_getFee", json!([params]))?)
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
        if self.required_policy.is_none() && !sidecars.is_empty() {
            return Err(Error::Invalid("unexpected proof sidecars"));
        }
        decode_intent(data)?;
        let wire = sidecars
            .iter()
            .map(invisi_sdk_core::provenance::proof_sidecar_to_wire)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid("invalid proof sidecar"))?;
        let signed: SignedQuote = serde_json::from_value(self.rpc.call(
            "broadcaster_getQuote",
            json!([{"data":format!("0x{}",hex::encode(data)), "proofSidecars":wire}]),
        )?)
        .map_err(|_| Error::Invalid("invalid signed broadcaster quote"))?;
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.configuration.quote_signer,
        };
        verify_quote_for_policy(&signed, &trust, data, now, self.required_policy)?;
        if signed.quote.fee_recipient != self.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered quote fee recipient"));
        }
        Ok(VerifiedQuote { signed, trust })
    }
    pub fn submit(
        &self,
        data: &[u8],
        verified: &VerifiedQuote,
        idempotency_key: &str,
    ) -> Result<Status> {
        self.submit_with_sidecars(data, verified, idempotency_key, &[])
    }
    pub fn submit_with_sidecars(
        &self,
        data: &[u8],
        verified: &VerifiedQuote,
        idempotency_key: &str,
        sidecars: &[ProofSidecar],
    ) -> Result<Status> {
        validate_id(idempotency_key)?;
        decode_intent(data)?;
        if self.required_policy.is_none() && !sidecars.is_empty() {
            return Err(Error::Invalid("unexpected proof sidecars"));
        }
        let wire = sidecars
            .iter()
            .map(invisi_sdk_core::provenance::proof_sidecar_to_wire)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Invalid("invalid proof sidecar"))?;
        let mut trust = verified.trust.clone();
        trust.signer = self.configuration.quote_signer;
        verify_quote_for_policy(&verified.signed, &trust, data, 0, self.required_policy)?;
        if verified.signed.quote.fee_recipient != self.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered quote fee recipient"));
        }
        let status:Status=serde_json::from_value(self.rpc.call("broadcaster_submitTransaction",json!([{"data":format!("0x{}",hex::encode(data)),"quote":verified.signed.quote,"signature":verified.signed.signature,"idempotencyKey":idempotency_key,"proofSidecars":wire}]))?).map_err(|_|Error::Invalid("invalid broadcaster status"))?;
        check_status(status, idempotency_key)
    }
    pub fn lookup_status(&self, id: &str) -> Result<Option<Status>> {
        match self.status(id) {
            Ok(status) => Ok(Some(status)),
            Err(Error::Remote { code: -32001, .. }) => Ok(None),
            Err(error) => Err(error),
        }
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
    if id.is_empty() || id.len() > 128 || !id.is_ascii() || id.bytes().any(|b| b < 32 || b == 127) {
        return Err(Error::Invalid("invalid broadcaster id"));
    }
    Ok(())
}
fn check_status(status: Status, id: &str) -> Result<Status> {
    if status.id != id {
        return Err(Error::Invalid("broadcaster status identity mismatch"));
    }
    Ok(status)
}
