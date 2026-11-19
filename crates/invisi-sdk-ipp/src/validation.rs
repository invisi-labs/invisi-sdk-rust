use crate::{Error, Result};
use alloy_primitives::U256;
use chrono::Timelike;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;
use url::Url;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidMessage)
    }
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut m = Map::new();
                while let Some((k, v)) = a.next_entry::<String, Unique>()? {
                    if m.insert(k, v.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = vec![];
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0)
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(s.into())))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                s: String,
            ) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(s)))
            }
            fn visit_bool<E: serde::de::Error>(self, b: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(b)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_u64<E: serde::de::Error>(self, n: u64) -> std::result::Result<Unique, E> {
                if n > 9007199254740991 {
                    return Err(E::custom("unsafe number"));
                }
                Ok(Unique(n.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, n: i64) -> std::result::Result<Unique, E> {
                if n < 0 {
                    Err(E::custom("negative number"))
                } else {
                    self.visit_u64(n as u64)
                }
            }
            fn visit_f64<E: serde::de::Error>(self, n: f64) -> std::result::Result<Unique, E> {
                if n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= 9007199254740991.0 {
                    self.visit_u64(n as u64)
                } else {
                    Err(E::custom("unsafe number"))
                }
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    require(bytes.len() <= MAX_BODY_BYTES)?;
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Unique::deserialize(&mut de)
        .map_err(|_| Error::InvalidMessage)?
        .0;
    de.end().map_err(|_| Error::InvalidMessage)?;
    Ok(v)
}
pub(crate) fn object<'a>(
    v: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>> {
    let m = v.as_object().ok_or(Error::InvalidMessage)?;
    require(
        required.iter().all(|k| m.contains_key(*k))
            && m.keys()
                .all(|k| required.contains(&k.as_str()) || optional.contains(&k.as_str())),
    )?;
    Ok(m)
}
pub(crate) fn text(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or(Error::InvalidMessage)?;
    require(
        !s.is_empty()
            && s.encode_utf16().count() <= 8192
            && !s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}'),
    )?;
    Ok(s)
}
pub(crate) fn uint(v: &Value, bits: usize, positive: bool) -> Result<U256> {
    let s = text(v)?;
    require(
        s.len() <= 80 && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0')),
    )?;
    let n = s.parse::<U256>().map_err(|_| Error::InvalidMessage)?;
    require((bits == 256 || n < (U256::from(1) << bits)) && (!positive || n != U256::ZERO))?;
    Ok(n)
}
fn number(v: &Value, max: u64) -> Result<()> {
    require(v.as_u64().is_some_and(|n| n <= max))
}
pub fn timestamp(v: &Value) -> Result<i64> {
    let s = text(v)?;
    require(s.len() == 20 && s.as_bytes()[4] == b'-' && s.ends_with('Z'))?;
    let d = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| Error::InvalidMessage)?;
    require(
        d.second() < 60 && d.nanosecond() == 0 && d.format("%Y-%m-%dT%H:%M:%SZ").to_string() == s,
    )?;
    Ok(d.and_utc().timestamp())
}
fn hex(v: &Value, bytes: usize, nonzero: bool) -> Result<()> {
    let s = text(v)?;
    require(
        s.len() == 2 + bytes * 2
            && s.starts_with("0x")
            && s[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (!nonzero || s[2..].bytes().any(|b| b != b'0')),
    )
}
pub(crate) fn field(v: &Value) -> Result<()> {
    hex(v, 32, true)?;
    require(
        U256::from_str_radix(&text(v)?[2..], 16).map_err(|_| Error::InvalidMessage)?
            < invisi_sdk_primitives::note::field_modulus(),
    )
}
fn network(v: &Value) -> Result<()> {
    let s = text(v)?;
    let n = s.strip_prefix("eip155:").ok_or(Error::InvalidMessage)?;
    uint(&Value::String(n.into()), 64, true)?;
    Ok(())
}
pub fn api_url(s: &str, origin: Option<&str>) -> Result<Url> {
    text(&Value::String(s.into()))?;
    require(s.bytes().all(|b| (0x21..=0x7e).contains(&b)))?;
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'%' {
            require(
                i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit(),
            )?;
        }
    }
    require(
        percent_encoding::percent_decode_str(s)
            .decode_utf8()
            .is_ok(),
    )?;
    let u = Url::parse(s).map_err(|_| Error::InvalidMessage)?;
    require(
        u.scheme() == "https"
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none()
            && u.as_str() == s
            && origin.is_none_or(|o| u.origin().ascii_serialization() == o),
    )?;
    for (k, _) in u.query_pairs() {
        let k = k.to_ascii_lowercase();
        require(
            ![
                "token",
                "secret",
                "key",
                "opening",
                "credential",
                "authorization",
            ]
            .iter()
            .any(|s| k.contains(s)),
        )?;
    }
    Ok(u)
}
pub(crate) fn no_secret(url: &str, secret: &str) -> Result<()> {
    let u = api_url(url, None)?;
    let route = format!(
        "{}{}",
        u.path(),
        u.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    let decoded = percent_encoding::percent_decode_str(&route)
        .decode_utf8()
        .map_err(|_| Error::InvalidMessage)?;
    require(!route.contains(secret) && !decoded.contains(secret))
}
pub(crate) fn bearer(s: &str) -> Result<()> {
    text(&Value::String(s.into()))?;
    let base = s.trim_end_matches('=');
    require(
        !base.is_empty()
            && base
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b)),
    )
}
pub(crate) fn idempotency(s: &str) -> Result<()> {
    require(!s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (0x21..=0x7e).contains(&b)))
}
fn link(v: &Value, method: &str, origin: Option<&str>) -> Result<()> {
    object(v, &["href", "method"], &[])?;
    require(v["method"] == method)?;
    api_url(text(&v["href"])?, origin)?;
    Ok(())
}
fn header(v: &Value, kind: &str) -> Result<()> {
    require(v["ippVersion"] == 1 && v["type"] == kind)
}
fn mode(v: &Value) -> Result<&str> {
    let s = text(&v["mode"])?;
    require(["payment", "credit"].contains(&s))?;
    Ok(s)
}
fn status(v: &Value, session: bool) -> Result<()> {
    let s = text(&v["status"])?;
    require(
        ["requires_action", "processing", "succeeded", "failed"].contains(&s)
            || (session && s == "open"),
    )?;
    require(if s == "failed" {
        v["failureReason"] == "expired" || v["failureReason"] == "closed"
    } else {
        v["failureReason"].is_null()
    })
}
fn terms(v: &Value, extra: &[&str]) -> Result<()> {
    let mut keys = vec![
        "spender",
        "availableCredit",
        "unlimited",
        "singleLimit",
        "dailyLimit",
        "monthlyLimit",
        "expiresAt",
    ];
    keys.extend_from_slice(extra);
    object(v, &keys, &["initialPayment"])?;
    if let Some(payment) = v.get("initialPayment") {
        object(payment, &["amount"], &[])?;
        uint(&payment["amount"], 126, true)?;
    }
    let s = text(&v["spender"])?;
    require(s.starts_with("0i"))?;
    invisi_sdk_primitives::address::ReceivingAddress::parse(s)
        .map_err(|_| Error::InvalidMessage)?;
    let amount = uint(&v["availableCredit"], 128, false)?;
    let unlimited = v["unlimited"].as_bool().ok_or(Error::InvalidMessage)?;
    require(if unlimited {
        amount == U256::ZERO
    } else {
        amount != U256::ZERO
    })?;
    for k in ["singleLimit", "dailyLimit", "monthlyLimit"] {
        uint(&v[k], 126, false)?;
    }
    timestamp(&v["expiresAt"])?;
    Ok(())
}
fn options(v: &Value, mode: &str) -> Result<()> {
    let list = v.as_array().ok_or(Error::InvalidMessage)?;
    require(!list.is_empty() && list.len() <= 100)?;
    let mut ids = std::collections::HashSet::new();
    for o in list {
        object(
            o,
            &[
                "id",
                "method",
                "network",
                "asset",
                if mode == "payment" {
                    "amount"
                } else {
                    "credit"
                },
            ],
            &[],
        )?;
        require(ids.insert(text(&o["id"])?))?;
        require(o["method"] == "invisi")?;
        network(&o["network"])?;
        let a = &o["asset"];
        object(a, &["address", "symbol", "decimals"], &[])?;
        hex(&a["address"], 20, true)?;
        text(&a["symbol"])?;
        number(&a["decimals"], 255)?;
        if mode == "payment" {
            uint(&o["amount"], 128, true)?;
        } else {
            terms(&o["credit"], &[])?;
        }
    }
    Ok(())
}
pub fn parse_checkout_input(v: Value) -> Result<crate::CheckoutInput> {
    let v = parse_json(&serde_json::to_vec(&v).map_err(|_| Error::InvalidMessage)?)?;
    object(
        &v,
        &["ippVersion", "mode", "options", "expiresAt"],
        &["description"],
    )?;
    require(v["ippVersion"] == 1)?;
    options(&v["options"], mode(&v)?)?;
    timestamp(&v["expiresAt"])?;
    if let Some(s) = v.get("description") {
        text(s)?;
    }
    Ok(crate::CheckoutInput(v))
}
pub fn parse_checkout_entry(s: &str) -> Result<(String, String)> {
    let (base, fragment) = s.split_once('#').ok_or(Error::InvalidMessage)?;
    api_url(base, None)?;
    require(!fragment.contains('#'))?;
    let mut params = url::form_urlencoded::parse(fragment.as_bytes());
    let pairs: Vec<_> = params.by_ref().collect();
    require(pairs.len() == 2)?;
    let get = |k: &str| -> Result<String> {
        let found: Vec<_> = pairs.iter().filter(|(key, _)| key == k).collect();
        require(found.len() == 1)?;
        Ok(found[0].1.to_string())
    };
    let session = get("sessionUrl")?;
    let token = get("token")?;
    api_url(&session, None)?;
    bearer(&token)?;
    no_secret(base, &token)?;
    no_secret(&session, &token)?;
    Ok((session, token))
}
pub fn parse_checkout(v: Value) -> Result<crate::Checkout> {
    let v = parse_json(&serde_json::to_vec(&v).map_err(|_| Error::InvalidMessage)?)?;
    object(
        &v,
        &[
            "ippVersion",
            "type",
            "sessionUrl",
            "checkoutUrl",
            "expiresAt",
        ],
        &[],
    )?;
    header(&v, "checkout")?;
    api_url(text(&v["sessionUrl"])?, None)?;
    timestamp(&v["expiresAt"])?;
    let (s, _) = parse_checkout_entry(text(&v["checkoutUrl"])?)?;
    require(v["sessionUrl"] == s)?;
    Ok(crate::Checkout(v))
}
pub fn parse_payment_request(v: Value, origin: Option<&str>) -> Result<crate::Request> {
    let v = parse_json(&serde_json::to_vec(&v).map_err(|_| Error::InvalidMessage)?)?;
    let m = mode(&v)?;
    object(
        &v,
        &[
            "ippVersion",
            "type",
            "mode",
            "method",
            "sessionId",
            "requestId",
            "optionId",
            "status",
            "createdAt",
            "expiresAt",
            "links",
            "failureReason",
            if m == "payment" { "payment" } else { "credit" },
        ],
        &[],
    )?;
    header(
        &v,
        if m == "payment" {
            "payment_request"
        } else {
            "credit_request"
        },
    )?;
    require(v["method"] == "invisi")?;
    for k in ["sessionId", "requestId", "optionId"] {
        text(&v[k])?;
    }
    status(&v, false)?;
    require(timestamp(&v["expiresAt"])? > timestamp(&v["createdAt"])?)?;
    object(&v["links"], &["credentials"], &[])?;
    link(&v["links"]["credentials"], "POST", origin)?;
    let d = &v[m];
    if m == "payment" {
        object(
            d,
            &[
                "network",
                "protocolAddress",
                "tokenAddress",
                "amount",
                "recipient",
            ],
            &[],
        )?;
        uint(&d["amount"], 128, true)?;
        object(&d["recipient"], &["type", "identity"], &[])?;
        require(d["recipient"]["type"] == "identity")?;
        field(&d["recipient"]["identity"])?;
    } else {
        terms(
            d,
            &[
                "operation",
                "network",
                "protocolAddress",
                "tokenAddress",
                "creditSharedKey",
            ],
        )?;
        require(d["operation"] == "create")?;
        field(&d["creditSharedKey"])?;
        require(timestamp(&d["expiresAt"])? >= timestamp(&v["expiresAt"])?)?;
    }
    network(&d["network"])?;
    hex(&d["protocolAddress"], 20, true)?;
    hex(&d["tokenAddress"], 20, true)?;
    Ok(crate::Request(v))
}
fn receipt(v: &Value, credit: bool) -> Result<()> {
    let mut keys = vec![
        "network",
        "protocolAddress",
        "transactionHash",
        "commitment",
        "blockNumber",
        "blockHash",
        "completedAt",
    ];
    if credit {
        keys.extend([
            "creditId",
            "creditStatus",
            "owner",
            "revocationShard",
            "revocationSlot",
            "verificationBlock",
            "expiresAt",
        ]);
    }
    object(v, &keys, if credit { &["initialPayment"] } else { &[] })?;
    network(&v["network"])?;
    hex(&v["protocolAddress"], 20, true)?;
    hex(&v["transactionHash"], 32, true)?;
    field(&v["commitment"])?;
    uint(&v["blockNumber"], 64, false)?;
    hex(&v["blockHash"], 32, true)?;
    timestamp(&v["completedAt"])?;
    if credit {
        text(&v["creditId"])?;
        require(
            v["creditStatus"] == "active"
                || v["creditStatus"] == "depleted" && v.get("initialPayment").is_some(),
        )?;
        if let Some(p) = v.get("initialPayment") {
            object(
                p,
                &[
                    "noteCommitment",
                    "grossAmount",
                    "netAmount",
                    "feeAmount",
                    "feeRecipient",
                ],
                &[],
            )?;
            field(&p["noteCommitment"])?;
            require(p["noteCommitment"] != v["commitment"])?;
            let gross = uint(&p["grossAmount"], 126, true)?;
            let net = uint(&p["netAmount"], 126, true)?;
            let fee = uint(&p["feeAmount"], 126, false)?;
            hex(&p["feeRecipient"], 20, false)?;
            let recipient = text(&p["feeRecipient"])?;
            require(
                gross == net + fee
                    && (fee == U256::ZERO) == recipient[2..].bytes().all(|b| b == b'0'),
            )?;
        }
        hex(&v["owner"], 20, true)?;
        uint(&v["revocationShard"], 64, false)?;
        number(&v["revocationSlot"], 65535)?;
        timestamp(&v["expiresAt"])?;
        let b = &v["verificationBlock"];
        object(b, &["number", "hash", "timestamp"], &[])?;
        uint(&b["number"], 64, false)?;
        hex(&b["hash"], 32, true)?;
        timestamp(&b["timestamp"])?;
    }
    Ok(())
}
pub fn parse_payment_session(v: Value, origin: Option<&str>) -> Result<crate::PaymentSession> {
    let v = parse_json(&serde_json::to_vec(&v).map_err(|_| Error::InvalidMessage)?)?;
    object(
        &v,
        &[
            "ippVersion",
            "type",
            "mode",
            "sessionId",
            "status",
            "merchant",
            "options",
            "activeRequestId",
            "createdAt",
            "expiresAt",
            "links",
            "failureReason",
            "receipt",
            "evidenceStatus",
            "exceptionSummary",
        ],
        &["description"],
    )?;
    header(&v, "payment_session")?;
    let m = mode(&v)?;
    text(&v["sessionId"])?;
    status(&v, true)?;
    object(&v["merchant"], &["name"], &[])?;
    text(&v["merchant"]["name"])?;
    if let Some(d) = v.get("description") {
        text(d)?;
    }
    options(&v["options"], m)?;
    require(timestamp(&v["expiresAt"])? > timestamp(&v["createdAt"])?)?;
    object(&v["links"], &["confirm", "request"], &[])?;
    link(&v["links"]["confirm"], "POST", origin)?;
    if v["activeRequestId"].is_null() {
        require(
            v["links"]["request"].is_null() && (v["status"] == "open" || v["status"] == "failed"),
        )?;
    } else {
        text(&v["activeRequestId"])?;
        require(v["status"] != "open")?;
        link(&v["links"]["request"], "GET", origin)?;
    }
    if v["status"] == "succeeded" {
        receipt(&v["receipt"], m == "credit")?;
        require(["confirmed", "reconciling", "disputed"].contains(&text(&v["evidenceStatus"])?))?;
    } else {
        require(v["receipt"].is_null() && v["evidenceStatus"].is_null())?;
    }
    let e = &v["exceptionSummary"];
    object(e, &["count", "unresolvedCount"], &[])?;
    number(&e["count"], 9007199254740991)?;
    number(
        &e["unresolvedCount"],
        e["count"].as_u64().ok_or(Error::InvalidMessage)?,
    )?;
    Ok(crate::PaymentSession(v))
}
pub fn parse_credential(v: Value, request: Option<&crate::Request>) -> Result<crate::Credential> {
    let v = parse_json(&serde_json::to_vec(&v).map_err(|_| Error::InvalidMessage)?)?;
    object(
        &v,
        &[
            "ippVersion",
            "type",
            "mode",
            "method",
            "sessionId",
            "requestId",
            "proof",
        ],
        &[],
    )?;
    header(&v, "credential")?;
    let m = mode(&v)?;
    require(v["method"] == "invisi")?;
    text(&v["sessionId"])?;
    text(&v["requestId"])?;
    let p = &v["proof"];
    object(
        p,
        &["type", "transactionHash", "commitment"],
        if m == "credit" {
            &["owner", "revocationShard", "revocationSlot"]
        } else {
            &[]
        },
    )?;
    require(
        p["type"]
            == if m == "credit" {
                "credit_created"
            } else {
                "note"
            },
    )?;
    hex(&p["transactionHash"], 32, true)?;
    field(&p["commitment"])?;
    if let Some(x) = p.get("owner") {
        hex(x, 20, true)?;
    }
    if let Some(x) = p.get("revocationShard") {
        uint(x, 64, false)?;
    }
    if let Some(x) = p.get("revocationSlot") {
        number(x, 65535)?;
    }
    if let Some(r) = request {
        for k in ["mode", "sessionId", "requestId", "method"] {
            require(v[k] == r.0[k])?;
        }
    }
    Ok(crate::Credential(v))
}
pub fn assert_request_matches_session(r: &crate::Request, s: &crate::PaymentSession) -> Result<()> {
    let r = &r.0;
    let s = &s.0;
    require(
        r["sessionId"] == s["sessionId"]
            && r["mode"] == s["mode"]
            && (s["activeRequestId"].is_null() || s["activeRequestId"] == r["requestId"]),
    )?;
    let o = s["options"]
        .as_array()
        .and_then(|a| a.iter().find(|o| o["id"] == r["optionId"]))
        .ok_or(Error::InvalidMessage)?;
    require(o["method"] == r["method"])?;
    let m = text(&r["mode"])?;
    let d = &r[m];
    require(d["network"] == o["network"] && d["tokenAddress"] == o["asset"]["address"])?;
    if m == "payment" {
        require(d["amount"] == o["amount"])?;
    } else {
        for (k, v) in o["credit"].as_object().ok_or(Error::InvalidMessage)? {
            require(d[k] == *v)?;
        }
        require(d.get("initialPayment") == o["credit"].get("initialPayment"))?;
    }
    Ok(())
}
pub(crate) fn check(ok: bool) -> Result<()> {
    require(ok)
}

pub(crate) fn assert_receipt_matches_request(
    receipt: &Value,
    request: &crate::Request,
) -> Result<()> {
    let r = &request.0;
    let d = &r[text(&r["mode"])?];
    for key in ["network", "protocolAddress"] {
        require(receipt[key] == d[key])?;
    }
    if r["mode"] == "credit" {
        match (d.get("initialPayment"), receipt.get("initialPayment")) {
            (Some(terms), Some(result)) => require(terms["amount"] == result["netAmount"])?,
            (None, None) => {}
            _ => return Err(Error::InvalidMessage),
        }
    }
    Ok(())
}

#[cfg(test)]
mod initial_payment_receipt_tests {
    use super::*;
    #[test]
    fn confirmed_receipt_binds_frozen_initial_payment_net() {
        let request = crate::Request(
            serde_json::json!({"mode":"credit","credit":{"network":"eip155:1","protocolAddress":"core","initialPayment":{"amount":"5"}}}),
        );
        let mut receipt = serde_json::json!({"network":"eip155:1","protocolAddress":"core","initialPayment":{"netAmount":"5"}});
        assert!(assert_receipt_matches_request(&receipt, &request).is_ok());
        receipt["initialPayment"]["netAmount"] = serde_json::json!("6");
        assert!(assert_receipt_matches_request(&receipt, &request).is_err());
        receipt.as_object_mut().unwrap().remove("initialPayment");
        assert!(assert_receipt_matches_request(&receipt, &request).is_err());
    }
}
