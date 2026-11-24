use super::*;
pub const FEE_LOCK_MODEL: &str = "core-gas-v1.3.4";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeeLock {
    pub token: Address,
    pub fee_recipient: Address,
    pub numerator: String,
    pub denominator: String,
    pub gas_price: String,
    pub markup_bps: String,
    pub gas_margin_bps: String,
    pub max_gas: String,
    pub deadline: String,
    pub model: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedFeeLock {
    pub lock: FeeLock,
    pub signature: String,
}
#[derive(Clone, Debug)]
pub struct VerifiedFeeLock {
    pub(crate) signed: SignedFeeLock,
    pub(crate) trust: Trust,
}
pub fn fee_lock_digest(lock: &FeeLock, trust: &Trust) -> Result<B256> {
    if trust.chain_id == 0
        || trust.protocol == Address::ZERO
        || trust.signer == Address::ZERO
        || lock.token == Address::ZERO
        || lock.fee_recipient == Address::ZERO
        || lock.model != FEE_LOCK_MODEL
    {
        return Err(Error::Invalid("invalid fee lock"));
    }
    let mut numbers = Vec::new();
    for (i, value) in [
        &lock.numerator,
        &lock.denominator,
        &lock.gas_price,
        &lock.markup_bps,
        &lock.gas_margin_bps,
        &lock.max_gas,
        &lock.deadline,
    ]
    .iter()
    .enumerate()
    {
        let n = decimal(&json!(value))?;
        if n.to_string() != **value
            || ((i < 3 || i >= 5) && n == U256::ZERO)
            || ((i == 3 || i == 4) && n > U256::from(100000))
            || (i >= 5 && n >= U256::from(1) << 63)
        {
            return Err(Error::Invalid("invalid fee lock bounds"));
        }
        numbers.push(n);
    }
    let domain=keccak256((keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),keccak256("InvisiBroadcaster"),keccak256("1"),U256::from(trust.chain_id),trust.protocol).abi_encode());
    let structure=keccak256((keccak256("FeeLock(address token,address feeRecipient,uint256 numerator,uint256 denominator,uint256 gasPrice,uint256 markupBps,uint256 gasMarginBps,uint256 maxGas,uint256 deadline,string model)"),lock.token,lock.fee_recipient,numbers[0],numbers[1],numbers[2],numbers[3],numbers[4],numbers[5],numbers[6],keccak256(&lock.model)).abi_encode());
    let mut data = vec![0x19, 0x01];
    data.extend_from_slice(domain.as_slice());
    data.extend_from_slice(structure.as_slice());
    Ok(keccak256(data))
}
pub fn verify_fee_lock(
    ticket: &SignedFeeLock,
    trust: &Trust,
    token: Address,
    recipient: Address,
    now: u64,
) -> Result<()> {
    let digest = fee_lock_digest(&ticket.lock, trust)?;
    if ticket.lock.token != token
        || ticket.lock.fee_recipient != recipient
        || decimal(&json!(ticket.lock.deadline))? <= U256::from(now)
    {
        return Err(Error::Invalid("expired or mismatched fee lock"));
    }
    let bytes = rpc::bytes(&json!(ticket.signature), 65, 65)?;
    let recovery = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => return Err(Error::Invalid("invalid fee lock recovery id")),
    };
    let signature = Signature::from_slice(&bytes[..64])
        .map_err(|_| Error::Invalid("invalid fee lock signature"))?;
    if signature.normalize_s().is_some() {
        return Err(Error::Invalid("noncanonical fee lock signature"));
    }
    let key = VerifyingKey::recover_from_prehash(
        digest.as_slice(),
        &signature,
        RecoveryId::try_from(recovery)
            .map_err(|_| Error::Invalid("invalid fee lock recovery id"))?,
    )
    .map_err(|_| Error::Invalid("invalid fee lock signature"))?;
    let public = key.to_encoded_point(false);
    if Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]) != trust.signer {
        return Err(Error::Invalid("untrusted fee lock"));
    }
    Ok(())
}
impl VerifiedFeeLock {
    pub fn signed(&self) -> &SignedFeeLock {
        &self.signed
    }
    pub(crate) fn validate(&self, data: &[u8], recipient: Address, now: u64) -> Result<()> {
        verify_fee_lock(
            &self.signed,
            &self.trust,
            decode_intent(data)?.token,
            recipient,
            now,
        )
    }
}
impl<T: RpcTransport> BroadcasterClient<T> {
    /// Missing advertised capability preserves legacy behavior; lock errors never downgrade.
    pub fn lock_fee(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
    ) -> Result<Option<VerifiedFeeLock>> {
        let status = self.rpc.call("broadcaster_getStatus", json!([]))?;
        if status["apiVersion"] != "v1"
            || status["protocolVersion"] != "1"
            || decimal(&status["chainId"])? != U256::from(chain_id)
            || status["protocol"]
                .as_str()
                .and_then(|s| s.parse::<Address>().ok())
                != Some(protocol)
            || status["sender"]
                .as_str()
                .and_then(|s| s.parse::<Address>().ok())
                != Some(self.configuration.quote_signer)
            || status["feeRecipient"]
                .as_str()
                .and_then(|s| s.parse::<Address>().ok())
                != Some(self.configuration.fee_recipient)
            || status["submissionHalted"] != false
        {
            return Err(Error::Invalid("invalid broadcaster fee lock status"));
        }
        let Some(cap) = status.get("feeLock") else {
            return Ok(None);
        };
        if cap["version"] != "1"
            || cap["model"] != FEE_LOCK_MODEL
            || !cap["core"].is_boolean()
            || !cap["router"].is_boolean()
        {
            return Err(Error::Invalid("unsupported fee lock capability"));
        }
        if cap["core"] == false {
            return Ok(None);
        }
        let signed: SignedFeeLock = serde_json::from_value(self.rpc.call(
            "broadcaster_lockFee",
            json!([{"data":format!("0x{}",hex::encode(data))}]),
        )?)
        .map_err(|_| Error::Invalid("invalid fee lock response"))?;
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.configuration.quote_signer,
        };
        verify_fee_lock(
            &signed,
            &trust,
            decode_intent(data)?.token,
            self.configuration.fee_recipient,
            now,
        )?;
        Ok(Some(VerifiedFeeLock { signed, trust }))
    }
}
