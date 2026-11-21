//! Host-injected recipes: this module never constructs a fake quote, proof or signature.
#![allow(dead_code)]
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use invisi_sdk::{
    broadcaster::SignedQuote,
    protocol::TransactionCall,
    prover::Prover,
    rpc::RpcTransport,
    sdk::{Invisi, Wallet},
};
use invisi_sdk_payment_router::{canonical::*, *};

/// V3 tokens are in forward economic order; the SDK encodes exact-output reversal.
/// Quoter address, pools and token metadata must come from trusted host configuration.
pub enum RouteSelection<'a> {
    SameTokenOrWrap,
    UniswapV3 {
        quoter: Address,
        tokens: &'a [Address],
        fees: &'a [u32],
    },
    ZeroEx(&'a ZeroExHttpTransport),
}

pub async fn quote_route(
    client: &PaymentRouterClient,
    unsigned_core: TransactionCall,
    intent: Intent,
    selection: &RouteSelection<'_>,
) -> Result<Payment> {
    match selection {
        RouteSelection::SameTokenOrWrap => {
            client
                .prepare_canonical_draft(unsigned_core, intent, Route::default())
                .await
        }
        RouteSelection::UniswapV3 {
            quoter,
            tokens,
            fees,
        } => {
            // Decode the SDK's actual unsigned Core request, without inventing calldata.
            let decoded = invisi_sdk::protocol::InvisiCore::transact_0Call::abi_decode_validate(
                &unsigned_core.data,
            )?;
            let request = decoded.r;
            let path: Bytes = encode_v3_exact_output_path(tokens, fees)?.into();
            let token_in = if intent.tokenIn.is_zero() {
                client.deployment().weth_address
            } else {
                intent.tokenIn
            };
            let required = client
                .quote_canonical_v3(
                    *quoter,
                    path.clone(),
                    token_in,
                    request.params.token,
                    request.funding.amount,
                )
                .await?;
            if required > intent.amountInMaximum {
                return Err(Error::Invalid("V3 quote exceeds reviewed input cap"));
            }
            client
                .prepare_canonical_draft(
                    unsigned_core,
                    intent,
                    Route {
                        channel: 1,
                        path,
                        target: Address::ZERO,
                        data: Bytes::new(),
                    },
                )
                .await
        }
        RouteSelection::ZeroEx(http) => {
            client
                .quote_canonical_zeroex(http, unsigned_core, intent, Some(50), None)
                .await
        }
    }
}

/// Construct two real encrypted outputs in the final Core token. Public Router
/// funding uses no old Note inputs, but this hidden-output transact still needs Core proof.
#[allow(clippy::too_many_arguments)]
pub fn payment_preparation(
    sdk: &Invisi,
    token: Address,
    recipient: &Wallet,
    recipient_amount: U256,
    payer_receiving: &Wallet,
    payer_amount: U256,
    fee: invisi_sdk::sdk::Fee,
    deadline: u64,
) -> Result<RouterPaymentPreparation> {
    let outputs = vec![
        invisi_sdk::sdk::NoteOutput::for_recipient(
            sdk.context(),
            token,
            recipient,
            recipient_amount,
            Vec::new(),
        )
        .map_err(Error::Preparation)?,
        invisi_sdk::sdk::NoteOutput::for_recipient(
            sdk.context(),
            token,
            payer_receiving,
            payer_amount,
            Vec::new(),
        )
        .map_err(Error::Preparation)?,
    ];
    Ok(RouterPaymentPreparation {
        token,
        outputs,
        fee,
        deadline,
    })
}

pub async fn payment_intent(
    client: &PaymentRouterClient,
    payer: Address,
    token_in: Address,
    cap: U256,
    deadline: u64,
    relayer: Address,
    mode: u8,
) -> Result<Intent> {
    Ok(Intent {
        payer,
        tokenIn: token_in,
        amountInMaximum: cap,
        refundRecipient: payer,
        relayer,
        nonce: client.router_nonce(payer).await?,
        deadline: U256::from(deadline),
        coreRequestHash: B256::ZERO,
        routeHash: B256::ZERO,
        mode,
    })
}

/// Host callback reviews, signs and submits the unsigned EVM transaction as payer.
/// It may use an external wallet; no private key is accepted by this recipe.
#[allow(clippy::too_many_arguments)]
pub async fn direct(
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
    if !matches!(intent.mode, DIRECT_TOKEN | DIRECT_NATIVE) {
        return Err(Error::Invalid("direct mode required"));
    }
    let prepared = client.prepare_payment(sdk, wallet, preparation).await?;
    let draft = quote_route(
        client,
        prepared.broadcaster_intent().map_err(Error::Preparation)?,
        intent,
        &route,
    )
    .await?;
    let ready = prepared.prove(prover, false).map_err(Error::Preparation)?;
    let payment = client
        .prepare_canonical(
            ready.export_transaction().map_err(Error::Preparation)?,
            draft.intent().clone(),
            draft.route().clone(),
        )
        .await?;
    let call = payment.router_call(permit, Bytes::new())?;
    client
        .simulate_canonical(&payment, call.clone(), payment.intent().payer, &[], None)
        .await?;
    send_as_payer(call)
}

/// Obtain a signed fee quote on unproved data. If the minimum rises, stop for
/// review and rebuild both Core and route. Never retry after signing/submission.
fn signed_quote<T: RpcTransport>(
    relay: &RouterRelayClient<T>,
    draft: &Payment,
    envelope: &RouterEnvelope,
    now: u64,
    cap: U256,
) -> Result<Option<SignedQuote>> {
    let approved = draft.request().params.feeAmount;
    if approved > cap {
        return Err(Error::Invalid("approved Core fee exceeds wallet cap"));
    }
    let estimate = relay.estimate_quote(draft, envelope)?;
    let required: U256 = estimate
        .fee_amount
        .parse()
        .map_err(|_| Error::Invalid("invalid estimated fee"))?;
    if required > cap {
        return Err(Error::Invalid("service fee exceeds wallet cap"));
    }
    if required > approved {
        return Ok(None);
    }
    relay.get_quote(draft, envelope, now).map(Some)
}

pub async fn simulate_envelope(
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

/// Quote -> Core proof -> payer Router signature -> simulation -> Broadcaster submit.
/// Payer supplies ERC20 principal; Broadcaster supplies outer transaction gas.
#[allow(clippy::too_many_arguments)]
pub async fn relay_token<T: RpcTransport>(
    client: &PaymentRouterClient,
    relay: &RouterRelayClient<T>,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
    intent: Intent,
    route: RouteSelection<'_>,
    permit: Permit,
    now: &dyn Fn() -> u64,
    max_fee: U256,
    sign: impl FnOnce(B256) -> Result<Bytes>,
) -> Result<serde_json::Value> {
    if intent.mode != RELAYED_TOKEN {
        return Err(Error::Invalid("relayed ERC20 mode required"));
    }
    // The host has reviewed a fixed Core fee. A rise fails before proving/signing;
    // the host can rebuild with an explicitly approved fee, rather than auto-spending.
    let prepared = client.prepare_payment(sdk, wallet, preparation).await?;
    let draft = quote_route(
        client,
        prepared.broadcaster_intent().map_err(Error::Preparation)?,
        intent,
        &route,
    )
    .await?;
    let unsigned = draft.draft_relay_envelope(permit.clone())?;
    let quote = signed_quote(relay, &draft, &unsigned, now(), max_fee)?.ok_or(Error::Invalid(
        "rebuild Core fee and route after reviewing new minimum",
    ))?;
    let ready = prepared.prove(prover, false).map_err(Error::Preparation)?;
    let payment = client
        .prepare_canonical(
            ready.export_transaction().map_err(Error::Preparation)?,
            draft.intent().clone(),
            draft.route().clone(),
        )
        .await?;
    let signature = sign(payment.digest(payment.chain_id()))?;
    let envelope = payment.relay_envelope(permit, signature)?;
    relay.verify_quote(&payment, &envelope, &quote, now())?;
    simulate_envelope(client, &payment, &envelope, None).await?;
    // Pure public Router funding consumes no private Note, so no Source sidecars.
    relay.submit_transaction(&payment, &envelope, &quote, now(), &[])
}

/// The host reads the current EOA authorization nonce and supplies its exact request.
/// No arithmetic on the Router nonce or account action nonce can substitute for it.
/// None means delegation is already installed; the SDK verifies live account code.
#[allow(clippy::too_many_arguments)]
pub async fn relay_native<T: RpcTransport>(
    client: &PaymentRouterClient,
    relay: &RouterRelayClient<T>,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
    intent: Intent,
    route: RouteSelection<'_>,
    account: &AccountDeployment,
    authorization: Option<AuthorizationRequest>,
    now: &dyn Fn() -> u64,
    max_fee: U256,
    sign_authorization: impl FnOnce(&AuthorizationRequest) -> Result<SignedAuthorization>,
    sign_account: impl FnOnce(B256) -> Result<Bytes>,
) -> Result<serde_json::Value> {
    if intent.mode != SPONSORED_NATIVE {
        return Err(Error::Invalid("sponsored native mode required"));
    }
    let prepared = client.prepare_payment(sdk, wallet, preparation).await?;
    let draft = quote_route(
        client,
        prepared.broadcaster_intent().map_err(Error::Preparation)?,
        intent,
        &route,
    )
    .await?;
    let native = client
        .prepare_native_account(
            &draft,
            account,
            draft.intent().deadline,
            authorization.is_some(),
        )
        .await?;
    let unsigned_authorizations = authorization
        .as_ref()
        .map(AuthorizationRequest::draft)
        .transpose()?
        .into_iter()
        .collect();
    let unsigned = native.draft_envelope(unsigned_authorizations)?;
    let quote = signed_quote(relay, &draft, &unsigned, now(), max_fee)?.ok_or(Error::Invalid(
        "rebuild Core fee and route after reviewing new minimum",
    ))?;
    let ready = prepared.prove(prover, false).map_err(Error::Preparation)?;
    let payment = client
        .prepare_canonical(
            ready.export_transaction().map_err(Error::Preparation)?,
            draft.intent().clone(),
            draft.route().clone(),
        )
        .await?;
    let native = client
        .prepare_native_account(
            &payment,
            account,
            payment.intent().deadline,
            authorization.is_some(),
        )
        .await?;
    let signature = sign_account(native.digest(payment.chain_id()))?;
    let authorizations = authorization
        .as_ref()
        .map(sign_authorization)
        .transpose()?
        .into_iter()
        .collect();
    let envelope = native.envelope(signature, authorizations)?;
    relay.verify_quote(&payment, &envelope, &quote, now())?;
    // Outer value is zero. Principal comes from the payer EOA's native balance.
    simulate_envelope(client, &payment, &envelope, Some(account)).await?;
    relay.submit_transaction(&payment, &envelope, &quote, now(), &[])
}
