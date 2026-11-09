//! Scoped preflight tracking capabilities and strict current-v1 responses.
use invisi_sdk_core::provenance::parse_integer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const STALE_TRACKING: &str = "TRACKING_STALE_GENERATION";
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrackingMatch {
    pub tx_hash: String,
    pub block_hash: String,
    pub operation_index: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tracking {
    pub id: String,
    pub status: String,
    pub expires_at: String,
    pub operation_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<TrackingMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_sequence: Option<String>,
}
fn word(value: &str) -> Result<(), String> {
    if value.len() != 66
        || !value.starts_with("0x")
        || !value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid tracking word".into());
    }
    parse_integer(value, 256).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn tracking_from_result(result: &Value, id: Option<&str>) -> Result<Tracking, String> {
    let t: Tracking =
        serde_json::from_value(result["tracking"].clone()).map_err(|e| e.to_string())?;
    if t.id.len() != 48
        || !t
            .id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || id.is_some_and(|id| id != t.id)
    {
        return Err("invalid tracking id".into());
    }
    word(&t.operation_digest)?;
    let expiry = parse_integer(&t.expires_at, 64).map_err(|e| e.to_string())?;
    if expiry.is_zero() || expiry.to_string() != t.expires_at {
        return Err("invalid tracking expiry".into());
    }
    match t.status.as_str() {
        "stale_generation" => return Err(STALE_TRACKING.into()),
        "pending_confirmation" | "expired" | "superseded" => {}
        "pending_source" | "recognized" => {
            if t.matched.is_none() {
                return Err("tracking locator required".into());
            }
        }
        _ => return Err("unknown tracking status".into()),
    };
    if let Some(m) = &t.matched {
        word(&m.tx_hash)?;
        word(&m.block_hash)?;
        if parse_integer(&m.operation_index, 32)
            .map_err(|e| e.to_string())?
            .to_string()
            != m.operation_index
        {
            return Err("invalid tracking index".into());
        }
    }
    Ok(t)
}
pub fn preflight_tracking(result: &Value, index: &str, digest: &str) -> Result<Tracking, String> {
    if result["broadcastDecision"] != "allow" {
        return Err("preflight candidate was not allowed".into());
    }
    let member = if let Some(operations) = result["operations"].as_array() {
        operations
            .iter()
            .find(|v| v["operationIndex"] == index)
            .ok_or("preflight member missing")?
    } else {
        result
    };
    if member["broadcastDecision"] != "allow"
        || parse_integer(
            member["operationDigest"]
                .as_str()
                .ok_or("missing operation digest")?,
            256,
        )
        .map_err(|e| e.to_string())?
            != parse_integer(digest, 256).map_err(|e| e.to_string())?
    {
        return Err("preflight statement mismatch".into());
    }
    let t = tracking_from_result(member, None)?;
    if !["pending_confirmation", "pending_source", "recognized"].contains(&t.status.as_str()) {
        return Err("tracking no longer permits broadcast".into());
    }
    if parse_integer(&t.operation_digest, 256).map_err(|e| e.to_string())?
        != parse_integer(digest, 256).map_err(|e| e.to_string())?
    {
        return Err("tracking statement mismatch".into());
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn preflight_terminal_acknowledgement_never_permits_broadcast() {
        for status in ["expired", "superseded"] {
            let digest = format!("0x{:064x}", 9);
            let result = json!({"broadcastDecision":"allow","operationDigest":digest,"tracking":{"id":"a".repeat(48),"status":status,"expiresAt":"1","operationDigest":digest}});
            assert!(preflight_tracking(&result, "0", &digest)
                .unwrap_err()
                .contains("no longer permits broadcast"));
        }
    }
}
