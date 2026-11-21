//! Compile-checked host integration recipes for the unreleased canonical API.
//! Main never contacts a provider, signs, proves, or broadcasts. Call these functions
//! only with real host capabilities. Quote drafts before proof and wallet signing;
//! final simulation and submission require executable balances/allowances.
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
        coreRequestHash: B256::ZERO, // Filled from the draft, then recomputed after proof.
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
/// On-chain EOA signatures use low-s r||s||v with v=27/28 (normalize recovery parity
/// 0/1); ERC-1271 signatures use the contract wallet format.
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

/// Account payment signatures also use v=27/28; EIP-7702 yParity stays 0/1.
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
    Ready(Box<SignedQuote>),
}

/// Run on the unproved, unsigned draft before invoking the prover or wallet.
/// The host bounds retries. Retain an approved fee above the current minimum.
/// A required fee increase rebuilds the unproved Core funding and route before
/// calling again; max_fee_amount is wallet maxFeeAmount in token base units.
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
    // Verifies semantic intent format/hash, direct execution, trusted signer, fee and expiry.
    relay
        .get_quote(payment, envelope, now)
        .map(|quote| RelayQuote::Ready(Box::new(quote)))
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
    println!("Quote the unsigned Router draft before proving and wallet signing. Simulate the complete actual final call before submission. Main performs no RPC or broadcast.");
}

/// Executable bounded fee convergence: quote first, then prove and sign once.
/// Refresh a swap route for each changed fee-inclusive funding amount in the host
/// before retrying; this helper demonstrates the no-swap same-token path.
#[allow(clippy::too_many_arguments)]
pub async fn quote_token_before_proof<T: RpcTransport>(
    client: &PaymentRouterClient,
    relay: &RouterRelayClient<T>,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    mut preparation: RouterPaymentPreparation,
    intent: Intent,
    now: u64,
    max_fee_amount: U256,
    sign: impl FnOnce(B256) -> Result<Bytes>,
) -> Result<(Payment, RouterEnvelope, SignedQuote)> {
    if intent.mode != RELAYED_TOKEN {
        return Err(Error::Invalid("ERC20 relay requires RELAYED_TOKEN"));
    }
    for _ in 0..4 {
        let prepared = client
            .prepare_payment(sdk, wallet, preparation.clone())
            .await?;
        let core = prepared.broadcaster_intent().map_err(Error::Preparation)?;
        let draft = client
            .prepare_canonical_draft(core, intent.clone(), Route::default())
            .await?;
        let draft_envelope = draft.draft_relay_envelope(Permit::default())?;
        let _local_preview = draft.estimate_gas(false, 0, None)?;
        match signed_relay_quote(relay, &draft, &draft_envelope, now, max_fee_amount)? {
            RelayQuote::RebuildWithFee(fee) => {
                preparation.fee.amount = fee
                    .fee_amount
                    .parse()
                    .map_err(|_| Error::Invalid("invalid fee"))?;
                preparation.fee.recipient = fee.fee_recipient;
            }
            RelayQuote::Ready(quote) => {
                let ready = prepared.prove(prover, false).map_err(Error::Preparation)?;
                let payment = client
                    .prepare_canonical(
                        ready.export_transaction().map_err(Error::Preparation)?,
                        draft.intent().clone(),
                        draft.route().clone(),
                    )
                    .await?;
                let signature = sign(payment.digest(payment.chain_id()))?;
                let envelope = payment.relay_envelope(Permit::default(), signature)?;
                relay.verify_quote(&payment, &envelope, &quote, now)?;
                simulate_envelope(client, &payment, &envelope, None).await?;
                return Ok((payment, envelope, *quote));
            }
        }
    }
    Err(Error::Invalid("fee convergence attempt limit exceeded"))
}

/// Native quote metadata is available without account or 7702 wallet signatures.
/// After quote acceptance prove Core, rebuild Payment and NativePayment, then sign
/// their actual digests using the relayed_native recipe and reuse the same quote.
pub async fn native_quote_draft(
    client: &PaymentRouterClient,
    unsigned_core: TransactionCall,
    intent: Intent,
    route: Route,
    account: &AccountDeployment,
    authorization: Option<AuthorizationRequest>,
) -> Result<(Payment, RouterEnvelope)> {
    let draft = client
        .prepare_canonical_draft(unsigned_core, intent, route)
        .await?;
    let native = client
        .prepare_native_account(
            &draft,
            account,
            draft.intent().deadline,
            authorization.is_some(),
        )
        .await?;
    let authorizations = authorization
        .map(|a| a.draft())
        .transpose()?
        .into_iter()
        .collect();
    Ok((draft, native.draft_envelope(authorizations)?))
}
