//! Broadcaster wire support for complete Router/account envelopes.
use crate::{canonical::*, ensure, Error, Result};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use invisi_sdk::{
    broadcaster::{quote_digest, Execution, Fee, SignedQuote, Trust},
    rpc::{JsonRpc, RpcTransport},
};
use serde_json::{json, Value};
/// Uses the ordinary broadcaster methods with embedded Core calldata and a bound outer envelope.
/// Applications retain provenance sidecars and status/journal handling.
pub struct RouterRelayClient<T> {
    rpc: JsonRpc<T>,
    trust: Trust,
    fee_recipient: Address,
}
impl<T: RpcTransport> RouterRelayClient<T> {
    pub fn new(transport: T, trust: Trust, fee_recipient: Address) -> Result<Self> {
        ensure(
            trust.chain_id > 0
                && !trust.protocol.is_zero()
                && !trust.signer.is_zero()
                && !fee_recipient.is_zero(),
            "invalid relay trust",
        )?;
        Ok(Self {
            rpc: JsonRpc::new(transport),
            trust,
            fee_recipient,
        })
    }
    fn params(&self, p: &Payment, e: &RouterEnvelope) -> Result<Value> {
        p.check_envelope(e)?;
        ensure(
            p.core().to == self.trust.protocol && p.chain_id() == self.trust.chain_id,
            "relay Core mismatch",
        )?;
        Ok(json!({"data":format!("0x{}",hex::encode(&p.core().data)),"router":e}))
    }
    pub fn estimate_quote(&self, p: &Payment, e: &RouterEnvelope) -> Result<Fee> {
        let params = self.params(p, e)?;
        let f: Fee = serde_json::from_value(
            self.rpc
                .call("broadcaster_estimateQuote", json!([params]))
                .map_err(|e| Error::Provider(e.to_string()))?,
        )
        .map_err(|_| Error::Invalid("invalid relay fee"))?;
        ensure(
            f.fee_recipient == self.fee_recipient
                && !decimal(&f.fee_amount)?.is_zero()
                && decimal(&f.fee_amount)? < (U256::from(1) << 128)
                && !decimal(&f.max_gas)?.is_zero(),
            "invalid relay fee",
        )?;
        Ok(f)
    }
    pub fn get_quote(&self, p: &Payment, e: &RouterEnvelope, now: u64) -> Result<SignedQuote> {
        let params = self.params(p, e)?;
        let q: SignedQuote = serde_json::from_value(
            self.rpc
                .call("broadcaster_getQuote", json!([params]))
                .map_err(|e| Error::Provider(e.to_string()))?,
        )
        .map_err(|_| Error::Invalid("invalid signed relay quote"))?;
        self.verify_quote(p, e, &q, now)?;
        Ok(q)
    }
    pub fn verify_quote(
        &self,
        p: &Payment,
        e: &RouterEnvelope,
        q: &SignedQuote,
        now: u64,
    ) -> Result<()> {
        self.params(p, e)?;
        let r = p.request();
        let x = &q.quote;
        ensure(
            q.request_hash_format.as_deref() == Some(ENVELOPE_HASH_FORMAT)
                && x.schedule.is_none()
                && x.execution == Execution::Direct,
            "unsupported relay quote format/execution",
        )?;
        ensure(
            x.request_hash == envelope_hash(self.trust.chain_id, self.trust.protocol, e)?
                && x.token == r.params.token
                && x.fee_recipient == self.fee_recipient
                && x.fee_recipient == r.params.feeRecipient
                && decimal(&x.fee_amount)? == r.params.feeAmount
                && !r.params.feeAmount.is_zero()
                && !decimal(&x.max_gas)?.is_zero(),
            "relay quote differs from payment",
        )?;
        let deadline = decimal(&x.deadline)?;
        if p.intent().mode == SPONSORED_NATIVE {
            let action =
                PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&e.data)?;
            ensure(
                deadline <= action.deadline,
                "relay quote outlives account action",
            )?;
        }
        ensure(
            deadline >= U256::from(now)
                && deadline <= p.intent().deadline
                && deadline <= r.params.deadline,
            "invalid relay quote deadline",
        )?;
        let sig = hex::decode(
            q.signature
                .strip_prefix("0x")
                .ok_or(Error::Invalid("invalid relay signature"))?,
        )
        .map_err(|_| Error::Invalid("invalid relay signature"))?;
        let digest = quote_digest(x, &self.trust)
            .map_err(|_| Error::Invalid("invalid relay quote digest"))?;
        ensure(
            recover_signer(digest, &sig)? == self.trust.signer,
            "untrusted relay quote signer",
        )
    }
    /// Recheck quote and envelope immediately before submission. Sidecars are passed unchanged to
    /// the service's provenance validator; they are never included in the Router transaction.
    pub fn submit_transaction(
        &self,
        p: &Payment,
        e: &RouterEnvelope,
        q: &SignedQuote,
        now: u64,
        proof_sidecars: &[Value],
    ) -> Result<Value> {
        self.verify_quote(p, e, q, now)?;
        let mut params = self.params(p, e)?;
        params["quote"] = json!(q.quote);
        params["signature"] = json!(q.signature);
        params["proofSidecars"] = json!(proof_sidecars);
        self.rpc
            .call("broadcaster_submitTransaction", json!([params]))
            .map_err(|e| Error::Provider(e.to_string()))
    }
}
fn decimal(s: &str) -> Result<U256> {
    let n: U256 = s
        .parse()
        .map_err(|_| Error::Invalid("invalid relay decimal"))?;
    ensure(n.to_string() == s, "noncanonical relay decimal")?;
    Ok(n)
}
