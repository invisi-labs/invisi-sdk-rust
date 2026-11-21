//! Compile-checked host integration recipes for the unreleased canonical API.
//! Main never contacts a provider, signs, proves, or broadcasts. Call these functions
//! only with real host capabilities, executable balances/allowances and proved Core data.
use alloy_primitives::{Address, Bytes, B256, U256};
use invisi_sdk::{
    broadcaster::{Fee, SignedQuote},
    prover::Prover,
    rpc::RpcTransport,
    sdk::{Invisi, Wallet},
};
use invisi_sdk_payment_router::{canonical::*, *};
use invisi_sdk_protocol::protocol::TransactionCall;

/// Real detached Core preparation: funding = Note outputs + Core-token fee.
/// The preparation must have at least two positive outputs and no private inputs.
pub async fn prove_core(
    client: &PaymentRouterClient,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
) -> Result<TransactionCall> {
    let prepared = client.prepare_payment(sdk, wallet, preparation).await?;
    let ready = prepared.prove(prover, false).map_err(Error::Preparation)?;
    ready.export_transaction().map_err(Error::Preparation)
}

/// Specify tokenIn=zero only for native modes. For no swap, use Route::default().
/// Amount is the input cap, not the recipient's net Note amount.
pub async fn intent(
    client: &PaymentRouterClient,
    payer: Address,
    token_in: Address,
    amount_in_maximum: U256,
    deadline: u64,
    relayer: Address,
    mode: u8,
) -> Result<Intent> {
    Ok(Intent {
        payer,
        tokenIn: token_in,
        amountInMaximum: amount_in_maximum,
        refundRecipient: payer,
        relayer,
        nonce: client.router_nonce(payer).await?,
        deadline: U256::from(deadline),
        coreRequestHash: B256::ZERO, // Filled from the real proof by prepare_canonical.
        routeHash: B256::ZERO,
        mode,
    })
}

/// Built-in canonical 0x HTTP: use the returned Payment's final digest for signing.
/// This covers native and arbitrary ERC20 input with Core's fee-inclusive buyAmount.
pub async fn zeroex_payment(
    client: &PaymentRouterClient,
    transport: &ZeroExHttpTransport,
    proved_core: TransactionCall,
    intent: Intent,
) -> Result<Payment> {
    client
        .quote_canonical_zeroex(transport, proved_core, intent, Some(50), None)
        .await
}

/// Host submits approval(token, Router, cap) first, or obtains a valid token permit.
/// Host then signs and sends this unsigned transaction with payer as its sender.
pub async fn self_erc20(
    client: &PaymentRouterClient,
    proved_core: TransactionCall,
    intent: Intent, // DIRECT_TOKEN, nonzero tokenIn, zero relayer.
    route: Route,
    permit: Permit,
) -> Result<TransactionCall> {
    if intent.mode != DIRECT_TOKEN {
        return Err(Error::Invalid("self ERC20 requires DIRECT_TOKEN"));
    }
    let payment = client.prepare_canonical(proved_core, intent, route).await?;
    let call = payment.router_call(permit, Bytes::new())?;
    client
        .simulate_canonical(&payment, call.clone(), payment.intent().payer, &[], None)
        .await?;
    Ok(call)
}

/// Host callback signs the exact final Router EIP-712 digest with the payer wallet.
pub async fn relayed_erc20(
    client: &PaymentRouterClient,
    proved_core: TransactionCall,
    intent: Intent, // RELAYED_TOKEN, fixed Broadcaster relayer, nonzero tokenIn.
    route: Route,
    permit: Permit,
    sign: impl FnOnce(B256) -> Result<Bytes>,
) -> Result<(Payment, RouterEnvelope)> {
    if intent.mode != RELAYED_TOKEN {
        return Err(Error::Invalid("ERC20 relay requires RELAYED_TOKEN"));
    }
    let payment = client.prepare_canonical(proved_core, intent, route).await?;
    let signature = sign(payment.digest(payment.chain_id()))?;
    let envelope = payment.relay_envelope(permit, signature)?;
    simulate_envelope(client, &payment, &envelope, None).await?;
    Ok((payment, envelope))
}

/// Host separately signs AuthorizationRequest::digest() at the payer's current EOA
/// transaction nonce when installing delegation. Supply that SignedAuthorization,
/// or an empty list for an already installed delegation. Delegation persists even
/// on payment revert; revocation does not reset the account action nonce.
pub async fn relayed_native(
    client: &PaymentRouterClient,
    proved_core: TransactionCall,
    intent: Intent, // SPONSORED_NATIVE, tokenIn=zero, fixed Broadcaster relayer.
    route: Route,
    account: &AccountDeployment,
    authorizations: Vec<SignedAuthorization>,
    sign: impl FnOnce(B256) -> Result<Bytes>,
) -> Result<(Payment, RouterEnvelope)> {
    if intent.mode != SPONSORED_NATIVE {
        return Err(Error::Invalid("native relay requires SPONSORED_NATIVE"));
    }
    let payment = client.prepare_canonical(proved_core, intent, route).await?;
    let deadline = payment.intent().deadline;
    let native = client
        .prepare_native_account(&payment, account, deadline, !authorizations.is_empty())
        .await?;
    let signature = sign(native.digest(payment.chain_id()))?;
    let envelope = native.envelope(signature, authorizations)?;
    // Outer value is zero; the payer's delegated account supplies native principal.
    simulate_envelope(client, &payment, &envelope, Some(account)).await?;
    Ok((payment, envelope))
}

async fn simulate_envelope(
    client: &PaymentRouterClient,
    payment: &Payment,
    envelope: &RouterEnvelope,
    account: Option<&AccountDeployment>,
) -> Result<()> {
    client
        .simulate_canonical(
            payment,
            TransactionCall {
                to: envelope.to,
                data: envelope.data.to_vec(),
                value: U256::ZERO,
            },
            payment.intent().relayer,
            &envelope.authorization_list,
            account,
        )
        .await?;
    Ok(())
}

/// The host can inspect/budget the estimated fee before preparing a replacement.
pub enum RelayQuote {
    RebuildWithFee(Fee),
    Ready(SignedQuote),
}

/// Run only after proof, signatures and balance/allowance prerequisites above.
/// The host bounds retries. Retain an approved fee above the current minimum.
/// A required fee increase needs a new Core proof, payment, wallet signatures and
/// envelope before this function is called again; never exceed the host fee cap.
pub fn signed_relay_quote<T: RpcTransport>(
    relay: &RouterRelayClient<T>,
    payment: &Payment,
    envelope: &RouterEnvelope,
    now: u64,
    max_fee_amount: U256,
) -> Result<RelayQuote> {
    let approved_fee = payment.request().params.feeAmount;
    if approved_fee > max_fee_amount {
        return Err(Error::Invalid("approved Core fee exceeds host cap"));
    }
    let estimate = relay.estimate_quote(payment, envelope)?;
    let required_fee: U256 = estimate
        .fee_amount
        .parse()
        .map_err(|_| Error::Invalid("invalid estimated fee amount"))?;
    if required_fee > max_fee_amount {
        return Err(Error::Invalid("required fee exceeds host cap"));
    }
    if required_fee > approved_fee {
        return Ok(RelayQuote::RebuildWithFee(estimate));
    }
    // Verifies envelope format/hash, direct execution, trusted signer, fee and expiry.
    relay
        .get_quote(payment, envelope, now)
        .map(RelayQuote::Ready)
}

/// Explicit host action after saving the frozen request for idempotent recovery.
/// Router pure public funding has no private-input Source proof sidecars.
pub fn submit<T: RpcTransport>(
    relay: &RouterRelayClient<T>,
    payment: &Payment,
    envelope: &RouterEnvelope,
    quote: &SignedQuote,
    now: u64,
) -> Result<serde_json::Value> {
    relay.submit_transaction(payment, envelope, quote, now, &[])
}

fn main() {
    println!("Canonical Router host recipes compile successfully. Supply real proof, wallet signing, deployment and executable funding before using these functions; no RPC or broadcast is performed by main.");
}
