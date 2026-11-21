//! Self ERC20: payer funds principal and pays gas; approve Router, not Core.
mod support;
use alloy_primitives::B256;
use invisi_sdk::{
    protocol::TransactionCall,
    prover::Prover,
    sdk::{Invisi, Wallet},
};
use invisi_sdk_payment_router::{canonical::*, *};
pub use support::{payment_intent, payment_preparation, RouteSelection};

/// Host invokes after constructing real Note outputs and configuring signing/submission.
#[allow(clippy::too_many_arguments)]
pub async fn self_token(
    client: &PaymentRouterClient,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
    intent: Intent,
    permit: Permit,
    send_as_payer: impl FnOnce(TransactionCall) -> Result<B256>,
) -> Result<B256> {
    if intent.mode != DIRECT_TOKEN {
        return Err(Error::Invalid("incorrect payment mode"));
    }
    support::direct(
        client,
        sdk,
        wallet,
        prover,
        preparation,
        intent,
        RouteSelection::SameTokenOrWrap,
        permit,
        send_as_payer,
    )
    .await
}
fn main() {
    println!("Host integration recipe: Self ERC20: payer funds principal and pays gas; approve Router, not Core. Main opens no RPC, wallet, prover or broadcaster. See examples/08-payment-router/README.md.");
}
