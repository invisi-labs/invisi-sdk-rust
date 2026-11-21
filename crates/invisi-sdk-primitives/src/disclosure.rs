//! Explicit selective disclosure. Opening exports never include the Credit shared key.
use crate::{
    credit::{compute_credit_shared_key_hash, CreditState},
    delivery::{self, CreditRole, DeliveryContext},
    note::{hash_fields, ModelError, ModelResult, Note},
};
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisclosureKind {
    Note,
    Credit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisclosureMethod {
    Opening,
    PayloadKey,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DisclosureRole {
    Funds,
    Owner,
    Spender,
}
impl DisclosureRole {
    fn name(self) -> &'static str {
        match self {
            Self::Funds => "funds",
            Self::Owner => "owner",
            Self::Spender => "spender",
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::Funds => 0,
            Self::Owner => 1,
            Self::Spender => 2,
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureExport {
    pub version: u8,
    pub kind: DisclosureKind,
    pub method: DisclosureMethod,
    pub context: DeliveryContext,
    pub data: BTreeMap<String, String>,
}
#[derive(Clone)]
pub struct Disclosure {
    material: DisclosureExport,
}
impl fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Disclosure([explicit export required])")
    }
}
#[derive(Debug, Clone)]
pub struct DisclosureOutput {
    pub context: DeliveryContext,
    pub role: DisclosureRole,
    pub ciphertext: Option<Vec<u8>>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisclosureResult {
    Note(Note),
    Credit {
        opening: BTreeMap<String, String>,
        payload: Option<Vec<u8>>,
    },
}
const CREDIT_FIELDS: [&str; 16] = [
    "spenderWalletIdentity",
    "ownerWalletIdentity",
    "grantId",
    "nonce",
    "expiry",
    "creditSharedKeyHash",
    "singleLimit",
    "dailyLimit",
    "monthlyLimit",
    "availableCredit",
    "unlimited",
    "lastDay",
    "dailySpent",
    "lastMonth",
    "monthlySpent",
    "totalSpent",
];
fn invalid() -> ModelError {
    ModelError::Invalid("disclosure")
}
fn decimal(s: &str) -> ModelResult<U256> {
    if s.is_empty()
        || s.len() > 78
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    U256::from_str_radix(s, 10).map_err(|_| invalid())
}
fn hex(value: U256, size: usize) -> String {
    format!("0x{}", hex::encode(&value.to_be_bytes::<32>()[32 - size..]))
}
fn address(s: &str) -> ModelResult<U256> {
    let b = crate::note::decode_hex(s)?;
    if b.len() != 20 {
        return Err(invalid());
    }
    let n = U256::from_be_slice(&b);
    crate::note::positive_address(n, "disclosure owner")?;
    Ok(n)
}
fn get<'a>(data: &'a BTreeMap<String, String>, name: &str) -> ModelResult<&'a str> {
    data.get(name).map(String::as_str).ok_or_else(invalid)
}
fn number(data: &BTreeMap<String, String>, name: &str) -> ModelResult<U256> {
    decimal(get(data, name)?)
}
fn note_data(note: &Note) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ownerAddress".into(), hex(note.owner_address, 20)),
        ("amount".into(), note.amount.to_string()),
        ("nonce".into(), note.nonce.to_string()),
    ])
}
fn credit_data(state: &CreditState) -> ModelResult<BTreeMap<String, String>> {
    state.validate()?;
    let n = state;
    let mut data = BTreeMap::new();
    for (name, value) in [
        ("spenderWalletIdentity", hex(n.spender_wallet_identity, 20)),
        ("ownerWalletIdentity", hex(n.owner_wallet_identity, 20)),
        ("grantId", n.grant_id.to_string()),
        ("nonce", n.nonce.to_string()),
        ("expiry", n.expiry.to_string()),
        (
            "creditSharedKeyHash",
            hex(compute_credit_shared_key_hash(n.credit_shared_key)?, 32),
        ),
        ("singleLimit", n.policy.single_limit.to_string()),
        ("dailyLimit", n.policy.daily_limit.to_string()),
        ("monthlyLimit", n.policy.monthly_limit.to_string()),
        ("availableCredit", n.available_credit.to_string()),
        ("unlimited", if n.unlimited { "1" } else { "0" }.into()),
        ("lastDay", n.usage.last_day.to_string()),
        ("dailySpent", n.usage.daily_spent.to_string()),
        ("lastMonth", n.usage.last_month.to_string()),
        ("monthlySpent", n.usage.monthly_spent.to_string()),
        ("totalSpent", n.usage.total_spent.to_string()),
    ] {
        data.insert(name.into(), value);
    }
    Ok(data)
}
fn credit_commitment(
    data: &BTreeMap<String, String>,
    context: &DeliveryContext,
) -> ModelResult<U256> {
    let spender = address(get(data, "spenderWalletIdentity")?)?;
    let owner = address(get(data, "ownerWalletIdentity")?)?;
    let key = crate::note::decode_hex(get(data, "creditSharedKeyHash")?)?;
    if key.len() != 32 {
        return Err(invalid());
    }
    let key = U256::from_be_slice(&key);
    crate::note::field(key, "shared key hash")?;
    let grant_id = number(data, "grantId")?;
    let nonce = number(data, "nonce")?;
    let expiry = number(data, "expiry")?;
    crate::note::uint(grant_id, 128, "grant ID")?;
    crate::note::uint(expiry, 64, "expiry")?;
    if grant_id == U256::ZERO || expiry == U256::ZERO {
        return Err(invalid());
    }
    let mut values = vec![
        U256::from(5),
        U256::from(context.context.chain_id),
        context.context.protocol_address,
        spender,
        owner,
        context.token_address,
        grant_id,
        nonce,
        expiry,
        key,
    ];
    for name in ["singleLimit", "dailyLimit", "monthlyLimit"] {
        let n = number(data, name)?;
        crate::note::uint(n, 126, "credit limit")?;
        values.push(n);
    }
    let available = number(data, "availableCredit")?;
    crate::note::uint(available, 128, "available credit")?;
    let unlimited = number(data, "unlimited")?;
    if unlimited > U256::from(1) || (unlimited == U256::from(1) && available != U256::ZERO) {
        return Err(invalid());
    }
    values.extend_from_slice(&[available, unlimited]);
    for (period, spent) in [("lastDay", "dailySpent"), ("lastMonth", "monthlySpent")] {
        let p = number(data, period)?;
        let s = number(data, spent)?;
        crate::note::uint(p, 64, "period")?;
        crate::note::uint(s, 128, "spent")?;
        if p == U256::ZERO && s != U256::ZERO {
            return Err(invalid());
        }
        values.extend_from_slice(&[p, s]);
    }
    let total = number(data, "totalSpent")?;
    crate::note::uint(total, 128, "total spent")?;
    values.push(total);
    hash_fields(&values)
}
fn validate_context(context: &DeliveryContext) -> ModelResult<()> {
    context.validate()?;
    crate::note::positive_address(context.context.protocol_address, "disclosure protocol")?;
    crate::note::positive_address(context.token_address, "disclosure token")
}
impl Disclosure {
    pub fn from_note(note: &Note) -> ModelResult<Self> {
        note.validate()?;
        crate::note::positive_address(note.context.protocol_address, "disclosure protocol")?;
        crate::note::positive_address(note.token_address, "disclosure token")?;
        Ok(Self {
            material: DisclosureExport {
                version: 1,
                kind: DisclosureKind::Note,
                method: DisclosureMethod::Opening,
                context: DeliveryContext {
                    context: note.context,
                    token_address: note.token_address,
                    output_commitment: note.commitment()?,
                },
                data: note_data(note),
            },
        })
    }
    pub fn from_credit(state: &CreditState) -> ModelResult<Self> {
        state.validate()?;
        Ok(Self {
            material: DisclosureExport {
                version: 1,
                kind: DisclosureKind::Credit,
                method: DisclosureMethod::Opening,
                context: DeliveryContext {
                    context: state.context,
                    token_address: state.token_address,
                    output_commitment: state.commitment()?,
                },
                data: credit_data(state)?,
            },
        })
    }
    pub fn from_encrypted(
        viewing_key: &[u8],
        envelope: &[u8],
        context: &DeliveryContext,
        role: DisclosureRole,
        owner: U256,
    ) -> ModelResult<Self> {
        validate_context(context)?;
        if role == DisclosureRole::Funds {
            delivery::decrypt_note(viewing_key, envelope, context, owner)?;
        } else {
            delivery::decrypt_credit(
                viewing_key,
                envelope,
                context,
                if role == DisclosureRole::Owner {
                    CreditRole::Owner
                } else {
                    CreditRole::Spender
                },
                owner,
            )?;
        }
        let key = delivery::payload_key(viewing_key, envelope, role != DisclosureRole::Funds)?;
        Self::from_export(DisclosureExport {
            version: 1,
            kind: if role == DisclosureRole::Funds {
                DisclosureKind::Note
            } else {
                DisclosureKind::Credit
            },
            method: DisclosureMethod::PayloadKey,
            context: context.clone(),
            data: BTreeMap::from([
                ("payloadKey".into(), format!("0x{}", hex::encode(&*key))),
                ("ownerAddress".into(), hex(owner, 20)),
                ("role".into(), role.name().into()),
            ]),
        })
    }
    pub fn from_export(material: DisclosureExport) -> ModelResult<Self> {
        if material.version != 1 {
            return Err(invalid());
        }
        validate_context(&material.context)?;
        let fields: Vec<&str> = if material.method == DisclosureMethod::PayloadKey {
            vec!["payloadKey", "ownerAddress", "role"]
        } else if material.kind == DisclosureKind::Note {
            vec!["ownerAddress", "amount", "nonce"]
        } else {
            CREDIT_FIELDS.to_vec()
        };
        if material.data.len() != fields.len()
            || fields.iter().any(|k| !material.data.contains_key(*k))
        {
            return Err(invalid());
        }
        let result = Self { material };
        if result.material.method == DisclosureMethod::Opening {
            result.verify(&DisclosureOutput {
                context: result.material.context.clone(),
                role: if result.material.kind == DisclosureKind::Note {
                    DisclosureRole::Funds
                } else {
                    DisclosureRole::Owner
                },
                ciphertext: None,
            })?;
        } else {
            let data = &result.material.data;
            let bytes = crate::note::decode_hex(get(data, "payloadKey")?)?;
            if bytes.len() != 32 {
                return Err(invalid());
            }
            address(get(data, "ownerAddress")?)?;
            let role = get(data, "role")?;
            if (result.material.kind == DisclosureKind::Note && role != "funds")
                || (result.material.kind == DisclosureKind::Credit
                    && role != "owner"
                    && role != "spender")
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
    pub fn export(&self) -> DisclosureExport {
        self.material.clone()
    }
    pub fn verify(&self, output: &DisclosureOutput) -> ModelResult<DisclosureResult> {
        validate_context(&output.context)?;
        if self.material.context != output.context {
            return Err(ModelError::Mismatch("disclosure context"));
        }
        let d = &self.material.data;
        let context = &output.context;
        if self.material.kind == DisclosureKind::Note && output.role != DisclosureRole::Funds {
            return Err(invalid());
        }
        if self.material.kind == DisclosureKind::Credit && output.role == DisclosureRole::Funds {
            return Err(invalid());
        }
        if self.material.method == DisclosureMethod::Opening {
            if self.material.kind == DisclosureKind::Note {
                let note = Note {
                    context: context.context,
                    token_address: context.token_address,
                    owner_address: address(get(d, "ownerAddress")?)?,
                    amount: number(d, "amount")?,
                    nonce: number(d, "nonce")?,
                    payload: vec![],
                };
                if note.commitment() != Ok(context.output_commitment) {
                    return Err(ModelError::Mismatch("disclosed note commitment"));
                }
                return Ok(DisclosureResult::Note(note));
            }
            if credit_commitment(d, context) != Ok(context.output_commitment) {
                return Err(ModelError::Mismatch("disclosed credit commitment"));
            }
            return Ok(DisclosureResult::Credit {
                opening: d.clone(),
                payload: None,
            });
        }
        if get(d, "role")? != output.role.name() {
            return Err(ModelError::Mismatch("disclosure role"));
        }
        let key = zeroize::Zeroizing::new(crate::note::decode_hex(get(d, "payloadKey")?)?);
        let envelope = output.ciphertext.as_ref().ok_or_else(invalid)?;
        let plain = delivery::open_payload(&key, envelope, context, output.role.byte())?;
        let owner = address(get(d, "ownerAddress")?)?;
        if output.role == DisclosureRole::Funds {
            let note = delivery::decode_note(&plain, context)?;
            if note.owner_address != owner {
                return Err(ModelError::Mismatch("disclosure recipient"));
            }
            Ok(DisclosureResult::Note(note))
        } else {
            let state = delivery::decode_credit(&plain, context)?;
            let recipient = if output.role == DisclosureRole::Owner {
                state.note.owner_wallet_identity
            } else {
                state.note.spender_wallet_identity
            };
            if recipient != owner {
                return Err(ModelError::Mismatch("disclosure recipient"));
            }
            Ok(DisclosureResult::Credit {
                opening: credit_data(&state.note)?,
                payload: Some(state.note.payload),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureScope {
    pub version: u8,
    pub kind: DisclosureKind,
    pub method: DisclosureMethod,
    pub permits_owner_sweep: bool,
    pub reveals_note_consumption: bool,
    pub reveals_credit_shared_key: bool,
    pub reveals_receiving_keys: bool,
    pub reveals_payload: bool,
}
impl Disclosure {
    pub fn scope(&self) -> DisclosureScope {
        let note = self.material.kind == DisclosureKind::Note;
        let payload = self.material.method == DisclosureMethod::PayloadKey;
        DisclosureScope {
            version: 1,
            kind: self.material.kind,
            method: self.material.method,
            permits_owner_sweep: note,
            reveals_note_consumption: note,
            reveals_credit_shared_key: !note && payload,
            reveals_receiving_keys: !note && payload,
            reveals_payload: payload,
        }
    }
}
impl Drop for Disclosure {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for value in self.material.data.values_mut() {
            value.zeroize();
        }
    }
}
