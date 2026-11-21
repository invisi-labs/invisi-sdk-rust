//! Typed views of validated IPP messages. Message constructors always validate first.
use crate::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Payment,
    Credit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    RequiresAction,
    Processing,
    Succeeded,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditTerms {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_payment: Option<InitialPaymentTerms>,
    pub spender: String,
    pub available_credit: String,
    pub unlimited: bool,
    pub single_limit: String,
    pub daily_limit: String,
    pub monthly_limit: String,
    pub expires_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitialPaymentTerms {
    pub amount: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitialPaymentReceipt {
    pub note_commitment: String,
    pub gross_amount: String,
    pub net_amount: String,
    pub fee_amount: String,
    pub fee_recipient: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentOption {
    pub id: String,
    pub method: String,
    pub network: String,
    pub asset: Asset,
    pub amount: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditOption {
    pub id: String,
    pub method: String,
    pub network: String,
    pub asset: Asset,
    pub credit: CreditTerms,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum PaymentMethodOption {
    Payment(PaymentOption),
    Credit(CreditOption),
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentDetails {
    pub network: String,
    pub protocol_address: String,
    pub token_address: String,
    pub amount: String,
    pub recipient: IdentityRecipient,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct IdentityRecipient {
    #[serde(rename = "type")]
    pub kind: String,
    pub identity: String,
}
#[derive(Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditDetails {
    pub operation: String,
    pub network: String,
    pub protocol_address: String,
    pub token_address: String,
    pub credit_shared_key: String,
    #[serde(flatten)]
    pub terms: CreditTerms,
}
impl std::fmt::Debug for CreditDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("CreditDetails")
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReceipt {
    pub network: String,
    pub protocol_address: String,
    pub transaction_hash: String,
    pub commitment: String,
    pub block_number: String,
    pub block_hash: String,
    pub completed_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationBlock {
    pub number: String,
    pub hash: String,
    pub timestamp: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreditReceipt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_payment: Option<InitialPaymentReceipt>,
    #[serde(flatten)]
    pub payment: PaymentReceipt,
    pub credit_id: String,
    pub credit_status: String,
    pub owner: String,
    pub grant_id: String,
    pub verification_block: VerificationBlock,
    pub expires_at: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum Receipt {
    Credit(CreditReceipt),
    Payment(PaymentReceipt),
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionSummary {
    pub count: u64,
    pub unresolved_count: u64,
}
fn typed<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).expect("validated IPP field")
}
impl Checkout {
    pub fn session_url(&self) -> &str {
        self.0["sessionUrl"].as_str().unwrap()
    }
    pub fn checkout_url(&self) -> &str {
        self.0["checkoutUrl"].as_str().unwrap()
    }
    pub fn expires_at(&self) -> &str {
        self.0["expiresAt"].as_str().unwrap()
    }
}
impl CheckoutInput {
    pub fn mode(&self) -> Mode {
        typed(&self.0["mode"])
    }
    pub fn options(&self) -> Vec<PaymentMethodOption> {
        typed(&self.0["options"])
    }
    pub fn expires_at(&self) -> &str {
        self.0["expiresAt"].as_str().unwrap()
    }
}
impl PaymentSession {
    pub fn session_id(&self) -> &str {
        self.0["sessionId"].as_str().unwrap()
    }
    pub fn status(&self) -> Status {
        typed(&self.0["status"])
    }
    pub fn mode(&self) -> Mode {
        typed(&self.0["mode"])
    }
    pub fn options(&self) -> Vec<PaymentMethodOption> {
        typed(&self.0["options"])
    }
    pub fn active_request_id(&self) -> Option<&str> {
        self.0["activeRequestId"].as_str()
    }
    pub fn expires_at(&self) -> &str {
        self.0["expiresAt"].as_str().unwrap()
    }
    pub fn receipt(&self) -> Option<Receipt> {
        typed(&self.0["receipt"])
    }
    pub fn exception_summary(&self) -> ExceptionSummary {
        typed(&self.0["exceptionSummary"])
    }
    pub fn failure_reason(&self) -> Option<&str> {
        self.0["failureReason"].as_str()
    }
    pub fn evidence_status(&self) -> Option<&str> {
        self.0["evidenceStatus"].as_str()
    }
}
impl Request {
    pub fn session_id(&self) -> &str {
        self.0["sessionId"].as_str().unwrap()
    }
    pub fn request_id(&self) -> &str {
        self.0["requestId"].as_str().unwrap()
    }
    pub fn option_id(&self) -> &str {
        self.0["optionId"].as_str().unwrap()
    }
    pub fn status(&self) -> Status {
        typed(&self.0["status"])
    }
    pub fn mode(&self) -> Mode {
        typed(&self.0["mode"])
    }
    pub fn expires_at(&self) -> &str {
        self.0["expiresAt"].as_str().unwrap()
    }
    pub fn payment(&self) -> Option<PaymentDetails> {
        self.0.get("payment").map(typed)
    }
    pub fn credit(&self) -> Option<CreditDetails> {
        self.0.get("credit").map(typed)
    }
}
