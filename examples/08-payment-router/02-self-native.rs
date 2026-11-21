//! Self native: payer supplies native principal and outer gas; V3 or wrap targets Core output token.
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
pub async fn self_native(
    client: &PaymentRouterClient,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
    intent: Intent,
    route: RouteSelection<'_>,
    permit: Permit,
    send_as_payer: impl FnOnce(TransactionCall) -> Result<B256>,
) -> Result<B256> {
    if intent.mode != DIRECT_NATIVE {
        return Err(Error::Invalid("incorrect payment mode"));
    }
    support::direct(
        client,
        sdk,
        wallet,
        prover,
        preparation,
        intent,
        route,
        permit,
        send_as_payer,
    )
    .await
}
fn main() {
    println!("Host integration recipe: Self native: payer supplies native principal and outer gas; V3 or wrap targets Core output token. Main opens no RPC, wallet, prover or broadcaster. See examples/08-payment-router/README.md.");
}
