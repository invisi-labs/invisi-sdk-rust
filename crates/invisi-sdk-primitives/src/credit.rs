//! Current Credit available balance, gross usage and authenticated successor recovery.
use crate::note::{
    address_hex, bytes_hex, decimal, decimal_u16, decimal_u64, field, field_hex, field_modulus,
    hash_fields, positive_address, uint, ModelError, ModelResult, ProtocolContext,
};
use alloy_primitives::U256;
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditPolicy {
    #[serde(default, with = "decimal")]
    pub single_limit: U256,
    #[serde(default, with = "decimal")]
    pub daily_limit: U256,
    #[serde(default, with = "decimal")]
    pub monthly_limit: U256,
}
impl CreditPolicy {
    pub fn validate(&self) -> ModelResult<()> {
        for n in [self.single_limit, self.daily_limit, self.monthly_limit] {
            uint(n, 126, "credit limit")?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditUsage {
    #[serde(default, with = "decimal_u64")]
    pub last_day: u64,
    #[serde(default, with = "decimal")]
    pub daily_spent: U256,
    #[serde(default, with = "decimal_u64")]
    pub last_month: u64,
    #[serde(default, with = "decimal")]
    pub monthly_spent: U256,
    #[serde(default, with = "decimal")]
    pub total_spent: U256,
}
impl CreditUsage {
    pub fn validate(&self) -> ModelResult<()> {
        for n in [self.daily_spent, self.monthly_spent, self.total_spent] {
            uint(n, 128, "credit usage")?;
        }
        if (self.last_day == 0 && self.daily_spent != U256::ZERO)
            || (self.last_month == 0 && self.monthly_spent != U256::ZERO)
        {
            return Err(ModelError::Invalid("noncanonical credit usage"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditState {
    #[serde(flatten)]
    pub context: ProtocolContext,
    #[serde(with = "decimal")]
    pub token_address: U256,
    #[serde(with = "address_hex")]
    pub spender_wallet_identity: U256,
    #[serde(with = "address_hex")]
    pub owner_wallet_identity: U256,
    #[serde(with = "decimal_u64")]
    pub revocation_shard: u64,
    #[serde(with = "decimal_u16")]
    pub revocation_slot: u16,
    #[serde(with = "decimal")]
    pub nonce: U256,
    #[serde(with = "decimal_u64")]
    pub expiry: u64,
    #[serde(with = "decimal")]
    pub credit_shared_key: U256,
    #[serde(flatten)]
    pub policy: CreditPolicy,
    #[serde(flatten)]
    pub usage: CreditUsage,
    #[serde(with = "decimal")]
    pub available_credit: U256,
    pub unlimited: bool,
    #[serde(default, with = "bytes_hex")]
    pub payload: Vec<u8>,
}
impl CreditState {
    pub fn validate(&self) -> ModelResult<()> {
        self.context.validate()?;
        positive_address(self.context.protocol_address, "protocol address")?;
        positive_address(self.token_address, "token address")?;
        positive_address(self.spender_wallet_identity, "spender identity")?;
        positive_address(self.owner_wallet_identity, "owner identity")?;
        if self.revocation_shard == 0 || self.expiry == 0 || self.credit_shared_key == U256::ZERO {
            return Err(ModelError::Invalid("credit shard, expiry or shared key"));
        }
        field(self.nonce, "credit nonce")?;
        field(self.credit_shared_key, "credit shared key")?;
        self.policy.validate()?;
        self.usage.validate()?;
        uint(self.available_credit, 128, "available credit")?;
        if self.unlimited && self.available_credit != U256::ZERO {
            return Err(ModelError::Invalid("unlimited available credit"));
        }
        Ok(())
    }
    pub fn commitment(&self) -> ModelResult<U256> {
        self.validate()?;
        hash_fields(&[
            U256::from(5),
            U256::from(self.context.chain_id),
            self.context.protocol_address,
            self.spender_wallet_identity,
            self.owner_wallet_identity,
            self.token_address,
            U256::from(self.revocation_shard),
            U256::from(self.revocation_slot),
            self.nonce,
            U256::from(self.expiry),
            compute_credit_shared_key_hash(self.credit_shared_key)?,
            self.policy.single_limit,
            self.policy.daily_limit,
            self.policy.monthly_limit,
            self.available_credit,
            U256::from(self.unlimited as u8),
            U256::from(self.usage.last_day),
            self.usage.daily_spent,
            U256::from(self.usage.last_month),
            self.usage.monthly_spent,
            self.usage.total_spent,
        ])
    }
    pub fn nullifier(&self) -> ModelResult<U256> {
        compute_credit_nullifier(
            self.context.chain_id,
            self.credit_shared_key,
            self.commitment()?,
        )
    }
}
pub fn compute_credit_shared_key_hash(key: U256) -> ModelResult<U256> {
    field(key, "credit shared key")?;
    if key == U256::ZERO {
        return Err(ModelError::Invalid("credit shared key"));
    }
    hash_fields(&[U256::from(7), key])
}
pub fn compute_credit_nullifier(chain_id: u64, key: U256, commitment: U256) -> ModelResult<U256> {
    compute_credit_shared_key_hash(key)?;
    field(commitment, "credit commitment")?;
    hash_fields(&[U256::from(6), U256::from(chain_id), key, commitment])
}
pub fn derive_credit_state_nonce(
    context: ProtocolContext,
    token: U256,
    nullifier: U256,
    key: U256,
) -> ModelResult<U256> {
    hash_fields(&[
        U256::from(10),
        U256::from(context.chain_id),
        context.protocol_address,
        token,
        nullifier,
        key,
    ])
}
pub fn compute_credit_recovery_pad(
    context: ProtocolContext,
    token: U256,
    nullifier: U256,
    key: U256,
) -> ModelResult<U256> {
    hash_fields(&[
        U256::from(9),
        U256::from(context.chain_id),
        context.protocol_address,
        token,
        nullifier,
        key,
    ])
}
/// One-based UTC day and month, using integer Gregorian arithmetic for all uint64 seconds.
pub fn credit_periods(timestamp: u64) -> (u64, u64) {
    let days = u128::from(timestamp) / 86400;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    ((days + 1) as u64, ((year - 1970) * 12 + month) as u64)
}
pub fn apply_credit_draw_usage(
    previous: &CreditState,
    amount: U256,
    timestamp: u64,
) -> ModelResult<CreditState> {
    previous.validate()?;
    uint(amount, 126, "draw amount")?;
    if amount == U256::ZERO {
        return Err(ModelError::Invalid("draw amount"));
    }
    let mut next = previous.clone();
    let (day, month) = credit_periods(timestamp);
    if next.policy.single_limit != U256::ZERO && amount > next.policy.single_limit {
        return Err(ModelError::Exceeded("single limit"));
    }
    if day < next.usage.last_day || month < next.usage.last_month {
        return Err(ModelError::Invalid("credit period rollback"));
    }
    next.usage.daily_spent = if day == next.usage.last_day {
        next.usage.daily_spent
    } else {
        U256::ZERO
    } + amount;
    next.usage.monthly_spent = if month == next.usage.last_month {
        next.usage.monthly_spent
    } else {
        U256::ZERO
    } + amount;
    next.usage.last_day = day;
    next.usage.last_month = month;
    next.usage.total_spent += amount;
    next.usage.validate()?;
    if next.policy.daily_limit != U256::ZERO && next.usage.daily_spent > next.policy.daily_limit {
        return Err(ModelError::Exceeded("daily limit"));
    }
    if next.policy.monthly_limit != U256::ZERO
        && next.usage.monthly_spent > next.policy.monthly_limit
    {
        return Err(ModelError::Exceeded("monthly limit"));
    }
    if !next.unlimited {
        if amount > next.available_credit {
            return Err(ModelError::Exceeded("available credit"));
        }
        next.available_credit -= amount;
    }
    Ok(next)
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditTransition {
    pub state: CreditState,
    #[serde(with = "field_hex")]
    pub state_commitment: U256,
    #[serde(with = "field_hex")]
    pub nullifier: U256,
    #[serde(with = "decimal")]
    pub recovery_amount: U256,
}
pub fn derive_credit_state(
    previous: &CreditState,
    debit: U256,
    timestamp: u64,
) -> ModelResult<CreditTransition> {
    let nullifier = previous.nullifier()?;
    let nonce = derive_credit_state_nonce(
        previous.context,
        previous.token_address,
        nullifier,
        previous.credit_shared_key,
    )?;
    let mask = compute_credit_recovery_pad(
        previous.context,
        previous.token_address,
        nullifier,
        previous.credit_shared_key,
    )?;
    if nonce == previous.nonce {
        return Err(ModelError::Invalid("unchanged state nonce"));
    }
    let mut state = apply_credit_draw_usage(previous, debit, timestamp)?;
    state.nonce = nonce;
    let state_commitment = state.commitment()?;
    Ok(CreditTransition {
        state,
        state_commitment,
        nullifier,
        recovery_amount: (debit + mask) % field_modulus(),
    })
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditStateRecovery {
    #[serde(with = "decimal_u64")]
    pub timestamp: u64,
    #[serde(with = "field_hex")]
    pub credit_nullifier: U256,
    #[serde(with = "field_hex")]
    pub state_commitment: U256,
    #[serde(with = "decimal")]
    pub recovery_amount: U256,
}
pub fn recover_credit_state(
    context: ProtocolContext,
    previous: &CreditState,
    recovery: &CreditStateRecovery,
) -> ModelResult<CreditState> {
    if context != previous.context {
        return Err(ModelError::Mismatch("credit context"));
    }
    field(recovery.recovery_amount, "recovery amount")?;
    let nullifier = previous.nullifier()?;
    if nullifier != recovery.credit_nullifier {
        return Err(ModelError::Mismatch("previous credit nullifier"));
    }
    let mask = compute_credit_recovery_pad(
        context,
        previous.token_address,
        nullifier,
        previous.credit_shared_key,
    )?;
    let debit = (recovery.recovery_amount + field_modulus() - mask) % field_modulus();
    let mut transition = derive_credit_state(previous, debit, recovery.timestamp)?;
    if transition.state_commitment != recovery.state_commitment {
        return Err(ModelError::Mismatch("recovered credit commitment"));
    }
    transition.state.payload.clear();
    Ok(transition.state)
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditUpdateChanges {
    #[serde(default, with = "optional_payload")]
    pub payload: Option<Vec<u8>>,
    #[serde(default, with = "optional_decimal")]
    pub single_limit: Option<U256>,
    #[serde(default, with = "optional_decimal")]
    pub daily_limit: Option<U256>,
    #[serde(default, with = "optional_decimal")]
    pub monthly_limit: Option<U256>,
    #[serde(default, with = "optional_u64")]
    pub expiry: Option<u64>,
    pub unlimited: Option<bool>,
    #[serde(default, with = "decimal")]
    pub increase_available_credit: U256,
    #[serde(default, with = "decimal")]
    pub decrease_available_credit: U256,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditUpdateTransition {
    pub state: CreditState,
    #[serde(with = "field_hex")]
    pub state_commitment: U256,
    #[serde(with = "field_hex")]
    pub nullifier: U256,
}
pub fn derive_credit_update(
    previous: &CreditState,
    changes: &CreditUpdateChanges,
    deadline: u64,
) -> ModelResult<CreditUpdateTransition> {
    previous.validate()?;
    let increase = changes.increase_available_credit;
    let decrease = changes.decrease_available_credit;
    uint(increase, 128, "credit increase")?;
    uint(decrease, 128, "credit decrease")?;
    if increase != U256::ZERO && decrease != U256::ZERO {
        return Err(ModelError::Invalid("mutually exclusive credit adjustments"));
    }
    let mut state = previous.clone();
    if let Some(payload) = &changes.payload {
        state.payload = payload.clone();
    }
    state.unlimited = changes.unlimited.unwrap_or(state.unlimited);
    if state.unlimited {
        if increase != U256::ZERO || decrease != U256::ZERO {
            return Err(ModelError::Invalid("unlimited credit adjustment"));
        }
        state.available_credit = U256::ZERO;
    } else {
        if decrease > state.available_credit {
            return Err(ModelError::Exceeded("available credit decrease"));
        }
        state.available_credit = state.available_credit + increase - decrease;
        uint(state.available_credit, 128, "available credit")?;
    }
    state.policy.single_limit = changes.single_limit.unwrap_or(state.policy.single_limit);
    state.policy.daily_limit = changes.daily_limit.unwrap_or(state.policy.daily_limit);
    state.policy.monthly_limit = changes.monthly_limit.unwrap_or(state.policy.monthly_limit);
    state.expiry = changes.expiry.unwrap_or(state.expiry);
    if previous.expiry < deadline || state.expiry < deadline {
        return Err(ModelError::Invalid("expiry before deadline"));
    }
    let nullifier = previous.nullifier()?;
    state.nonce = derive_credit_state_nonce(
        previous.context,
        previous.token_address,
        nullifier,
        previous.credit_shared_key,
    )?;
    if state.nonce == previous.nonce {
        return Err(ModelError::Invalid("unchanged state nonce"));
    }
    let state_commitment = state.commitment()?;
    Ok(CreditUpdateTransition {
        state,
        state_commitment,
        nullifier,
    })
}

mod optional_decimal {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<U256>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<U256>, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        value
            .map(|s| {
                if s.is_empty()
                    || s.len() > 78
                    || !s.bytes().all(|b| b.is_ascii_digit())
                    || (s.len() > 1 && s.starts_with('0'))
                {
                    return Err(serde::de::Error::custom("noncanonical decimal integer"));
                }
                U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

mod optional_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        value
            .map(|s| {
                if s.is_empty()
                    || !s.bytes().all(|b| b.is_ascii_digit())
                    || (s.len() > 1 && s.starts_with('0'))
                {
                    return Err(serde::de::Error::custom("noncanonical decimal integer"));
                }
                s.parse().map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

pub use crate::delivery::CreditDeliveryState;
pub fn compute_credit_commitment(state: &CreditState) -> ModelResult<U256> {
    state.commitment()
}
pub fn normalize_credit_state(state: &CreditState) -> ModelResult<CreditState> {
    state.validate()?;
    Ok(state.clone())
}

mod optional_payload {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => s.serialize_some(&format!("0x{}", hex::encode(v))),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                let raw = s
                    .strip_prefix("0x")
                    .ok_or_else(|| serde::de::Error::custom("hex payload required"))?;
                hex::decode(raw).map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}
