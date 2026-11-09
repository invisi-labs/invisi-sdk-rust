//! 显式绑定受信策略的广播流程，与既有报价模型保持独立。
use super::*;
use invisi_sdk_core::provenance::{provenance_intent_hash, ProofSidecar};
pub const REQUEST_HASH_FORMAT: &str = "invisi-broadcaster-provenance-intent-v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceSignedQuote {
    pub quote: Quote,
    pub signature: String,
    pub provenance_policy_id: Option<B256>,
    pub request_hash_format: Option<String>,
}
pub fn verify_provenance_quote(
    s: &ProvenanceSignedQuote,
    t: &Trust,
    data: &[u8],
    now: u64,
    required_policy: B256,
) -> Result<()> {
    if s.provenance_policy_id != Some(required_policy)
        || s.request_hash_format.as_deref() != Some(REQUEST_HASH_FORMAT)
    {
        return Err(Error::Invalid("broadcaster provenance policy mismatch"));
    }
    let expected = B256::from(provenance_intent_hash(
        request_hash(data)?.0,
        U256::from_be_bytes(required_policy.0),
    ));
    super::verify_quote_with_hash(
        &SignedQuote {
            quote: s.quote.clone(),
            signature: s.signature.clone(),
        },
        t,
        data,
        now,
        expected,
    )
}
#[derive(Clone, Debug)]
pub struct ProvenanceVerifiedQuote {
    signed: ProvenanceSignedQuote,
    trust: Trust,
}
impl ProvenanceVerifiedQuote {
    pub fn signed(&self) -> &ProvenanceSignedQuote {
        &self.signed
    }
}
pub struct ProvenanceBroadcasterClient<T: RpcTransport> {
    base: BroadcasterClient<T>,
    required_policy: B256,
}
impl ProvenanceBroadcasterClient<HttpTransport> {
    pub fn connect(configuration: Configuration, required_policy: B256) -> Result<Self> {
        Ok(Self {
            base: BroadcasterClient::connect(configuration)?,
            required_policy,
        })
    }
}
impl<T: RpcTransport> ProvenanceBroadcasterClient<T> {
    pub fn new(configuration: Configuration, transport: T, required_policy: B256) -> Result<Self> {
        Ok(Self {
            base: BroadcasterClient::new(configuration, transport)?,
            required_policy,
        })
    }
    pub fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<Fee> {
        self.base.fee(token, data)
    }
    pub fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[ProofSidecar],
    ) -> Result<ProvenanceVerifiedQuote> {
        decode_intent(data)?;
        let signed: ProvenanceSignedQuote = serde_json::from_value(self.base.rpc.call(
            "broadcaster_getQuote",
            json!([{"data":format!("0x{}",hex::encode(data)),"proofSidecars":sidecars.iter().map(invisi_sdk_core::provenance::proof_sidecar_to_wire).collect::<std::result::Result<Vec<_>,_>>().map_err(|_|Error::Invalid("invalid proof sidecar"))?}]),
        )?)
        .map_err(|_| Error::Invalid("invalid provenance quote"))?;
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.base.configuration.quote_signer,
        };
        verify_provenance_quote(&signed, &trust, data, now, self.required_policy)?;
        if signed.quote.fee_recipient != self.base.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered fee recipient"));
        }
        Ok(ProvenanceVerifiedQuote { signed, trust })
    }
    pub fn submit(
        &self,
        data: &[u8],
        verified: &ProvenanceVerifiedQuote,
        idempotency_key: &str,
        sidecars: &[ProofSidecar],
    ) -> Result<Status> {
        super::validate_id(idempotency_key)?;
        let mut trust = verified.trust.clone();
        trust.signer = self.base.configuration.quote_signer;
        verify_provenance_quote(&verified.signed, &trust, data, 0, self.required_policy)?;
        if verified.signed.quote.fee_recipient != self.base.configuration.fee_recipient {
            return Err(Error::Invalid("unregistered fee recipient"));
        }
        let out:Status=serde_json::from_value(self.base.rpc.call("broadcaster_submitTransaction",json!([{"data":format!("0x{}",hex::encode(data)),"quote":verified.signed.quote,"signature":verified.signed.signature,"idempotencyKey":idempotency_key,"proofSidecars":sidecars.iter().map(invisi_sdk_core::provenance::proof_sidecar_to_wire).collect::<std::result::Result<Vec<_>,_>>().map_err(|_|Error::Invalid("invalid proof sidecar"))?}]))?).map_err(|_|Error::Invalid("invalid broadcaster status"))?;
        if out.id != idempotency_key {
            return Err(Error::Invalid("broadcaster status id mismatch"));
        }
        Ok(out)
    }
    pub fn status(&self, id: &str) -> Result<Status> {
        self.base.status(id)
    }
}
