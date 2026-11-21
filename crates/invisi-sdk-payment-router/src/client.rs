use crate::*;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use invisi_sdk::sdk::{Fee, Invisi, NoteOutput, PreparedTransaction, TransferPreparation, Wallet};
use invisi_sdk_protocol::protocol::{InvisiCore, TransactionCall};
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct DeploymentFrame {
    pub block: RouterBlock,
    pub settler_address: Option<Address>,
}
#[derive(Clone)]
pub struct RouterPaymentPreparation {
    pub token: Address,
    pub outputs: Vec<NoteOutput>,
    pub fee: Fee,
    pub deadline: u64,
}
/// Owns a validated detached deployment; callers retain proof, wallet and submission capabilities.
pub struct PaymentRouterClient {
    deployment: PaymentRouterDeployment,
    provider: Arc<dyn RouterProvider>,
}
impl PaymentRouterClient {
    pub fn new(
        deployment: PaymentRouterDeployment,
        provider: Arc<dyn RouterProvider>,
    ) -> Result<Self> {
        deployment.validate()?;
        Ok(Self {
            deployment,
            provider,
        })
    }
    pub fn deployment(&self) -> &PaymentRouterDeployment {
        &self.deployment
    }
    pub async fn assert_frame(&self, frame: &DeploymentFrame) -> Result<()> {
        ensure(
            self.provider.block(Some(frame.block.number)).await?.hash == frame.block.hash,
            "canonical Router block changed",
        )
    }
    async fn read(&self, to: Address, data: Vec<u8>, block: u64) -> Result<Vec<u8>> {
        self.provider
            .call(
                TransactionCall {
                    to,
                    data,
                    value: U256::ZERO,
                },
                None,
                block,
            )
            .await
    }
    async fn code(&self, to: Address, block: u64) -> Result<Vec<u8>> {
        let code = self.provider.code(to, block).await?;
        ensure(!code.is_empty(), "missing contract code")?;
        Ok(code)
    }
    pub async fn frame(&self, zeroex: bool) -> Result<DeploymentFrame> {
        let d = &self.deployment;
        ensure(
            self.provider.chain_id().await? == d.chain_id,
            "payment Router chain mismatch",
        )?;
        let block = self.provider.block(None).await?;
        ensure(
            block.number < (1 << 53) && block.timestamp < (1 << 53),
            "missing canonical chain block",
        )?;
        let runtime = self.code(d.router_address, block.number).await?;
        if let Some(hash) = d.runtime_code_hash {
            ensure(
                keccak256(runtime) == hash,
                "Router runtime code hash mismatch",
            )?;
        }
        let mut pins = vec![
            ("core()", d.core_address),
            ("dex()", d.uniswap_router_address),
            ("weth()", d.weth_address),
        ];
        if let Some(z) = &d.zero_ex {
            pins.extend([
                ("allowanceHolder()", z.allowance_holder_address),
                ("settlerRegistry()", z.settler_registry_address),
            ]);
        }
        for (name, expected) in pins {
            let result = self
                .read(
                    d.router_address,
                    keccak256(name)[..4].to_vec(),
                    block.number,
                )
                .await?;
            ensure(
                Address::abi_decode_validate(&result)? == expected,
                "Router deployment getter mismatch",
            )?;
            self.code(expected, block.number).await?;
        }
        let id = self
            .read(
                d.router_address,
                keccak256("CHAIN_ID()")[..4].to_vec(),
                block.number,
            )
            .await?;
        ensure(
            U256::abi_decode_validate(&id)? == U256::from(d.chain_id),
            "Router deployment chain mismatch",
        )?;
        let settler_address = if zeroex {
            let z = d
                .zero_ex
                .as_ref()
                .ok_or(Error::Invalid("0x is not enabled for this deployment"))?;
            let result = self
                .read(
                    z.settler_registry_address,
                    abi::ownerOfCall { id: U256::from(2) }.abi_encode(),
                    block.number,
                )
                .await?;
            let settler = Address::abi_decode_validate(&result)?;
            nonzero(settler)?;
            ensure(
                settler != d.router_address && settler != z.allowance_holder_address,
                "invalid current Settler",
            )?;
            self.code(settler, block.number).await?;
            Some(settler)
        } else {
            None
        };
        let snapshot = DeploymentFrame {
            block,
            settler_address,
        };
        self.assert_frame(&snapshot).await?;
        Ok(snapshot)
    }
    /// Run the real SDK preparation with no private inputs and caller-authorized Router funding.
    pub async fn prepare_payment(
        &self,
        invisi: &Invisi,
        wallet: &Wallet,
        options: RouterPaymentPreparation,
    ) -> Result<PreparedTransaction> {
        self.frame(false).await?;
        let context = invisi.context();
        ensure(
            context.chain_id == self.deployment.chain_id
                && context.protocol_address
                    == invisi_sdk::sdk::address_word(self.deployment.core_address),
            "SDK protocol deployment mismatch",
        )?;
        ensure(
            options.outputs.len() >= 2,
            "pure funding requires at least two Note outputs",
        )?;

        let mut amount = options.fee.amount;
        for output in &options.outputs {
            uint(output.amount(), 128, true, "invalid output amount")?;
            amount = amount
                .checked_add(output.amount())
                .ok_or(Error::Invalid("funding amount overflow"))?;
        }
        uint(amount, 128, true, "invalid total funding amount")?;
        let mut funding = invisi_sdk::sdk::empty_funding();
        funding.payer = self.deployment.router_address;
        funding.amount = amount;
        invisi
            .prepare_transfer(
                wallet,
                TransferPreparation {
                    token: options.token,
                    inputs: vec![],
                    outputs: options.outputs,
                    withdrawal: None,
                    funding,
                    fee: options.fee,
                    deadline: options.deadline,
                    automatic_change: false,
                },
            )
            .map_err(|e| Error::Preparation(e.to_string()))
    }
    pub async fn quote(
        &self,
        adapter: &dyn SwapQuoteAdapter,
        options: QuoteParameters,
    ) -> Result<SwapQuote> {
        options.check()?;
        ensure(
            options.token_out != self.deployment.weth_address,
            "WETH output is not supported",
        )?;
        let snapshot = self.frame(adapter.channel() == SwapChannel::ZeroEx).await?;
        ensure(
            options.deadline >= snapshot.block.timestamp,
            "quote expired",
        )?;
        let quote = adapter
            .quote(SwapQuoteRequest {
                parameters: options.clone(),
                deployment: self.deployment.clone(),
                now: snapshot.block.timestamp,
                block_number: snapshot.block.number,
                settler_address: snapshot.settler_address,
            })
            .await?;
        ensure(
            quote.route.channel() == adapter.channel(),
            "quote channel mismatch",
        )?;
        self.check_quote(&quote, &snapshot)?;
        ensure(
            quote.token_out == options.token_out && quote.amount_out == options.amount_out,
            "quoted payment amount or token changed",
        )?;
        ensure(
            quote.max_input <= options.max_input && quote.deadline <= options.deadline,
            "quote exceeds authorized budget or deadline",
        )?;
        options.check()?;
        self.assert_frame(&snapshot).await?;
        let current = self
            .frame(quote.route.channel() == SwapChannel::ZeroEx)
            .await?;
        self.check_quote(&quote, &current)?;
        options.check()?;
        Ok(quote)
    }
    fn zeroex(
        &self,
        target: Address,
        data: Vec<u8>,
        token_out: Address,
        amount_out: U256,
        max_input: U256,
        snapshot: &DeploymentFrame,
    ) -> Result<CheckedZeroExPayload> {
        let z = self
            .deployment
            .zero_ex
            .as_ref()
            .ok_or(Error::Invalid("0x deployment required"))?;
        validate_zeroex_payload(&ZeroExPayloadOptions {
            target,
            data,
            router_address: self.deployment.router_address,
            token_out,
            amount_out,
            max_input,
            settler_address: snapshot
                .settler_address
                .ok_or(Error::Invalid("current Settler required"))?,
            allowance_holder_address: z.allowance_holder_address,
            now: snapshot.block.timestamp,
        })
    }
    fn check_quote(&self, q: &SwapQuote, s: &DeploymentFrame) -> Result<()> {
        ensure(
            q.chain_id == self.deployment.chain_id
                && q.router_address == self.deployment.router_address,
            "quote deployment mismatch",
        )?;
        uint(q.amount_out, 128, true, "invalid quote amount")?;
        uint(q.max_input, 256, true, "invalid quote budget")?;
        ensure(
            q.estimated_input <= q.max_input,
            "estimated input exceeds budget",
        )?;
        ensure(q.deadline >= s.block.timestamp, "quote expired")?;
        match &q.route {
            SwapRoute::UniswapV3 { reverse_path } => {
                validate_v3_path(reverse_path, self.deployment.weth_address, q.token_out)?
            }
            SwapRoute::ZeroEx {
                target,
                data,
                settler_address,
            } => {
                ensure(
                    Some(*settler_address) == s.settler_address,
                    "0x Settler changed; refresh the quote",
                )?;
                let checked = self.zeroex(
                    *target,
                    data.clone(),
                    q.token_out,
                    q.amount_out,
                    q.max_input,
                    s,
                )?;
                ensure(
                    U256::from(q.deadline) <= checked.native_deadline,
                    "quote outlives native guard",
                )?;
            }
        }
        Ok(())
    }
    /// Export the proved SDK call without requiring pre-swap Router token balances or allowances.
    pub async fn build_prepared_payment_transaction(
        &self,
        payment: &PreparedTransaction,
        quote: SwapQuote,
        refund_recipient: Address,
    ) -> Result<TransactionCall> {
        let call = payment
            .export_transaction()
            .map_err(|e| Error::Preparation(e.to_string()))?;
        self.build_payment_transaction(call, quote, refund_recipient)
            .await
    }
    pub async fn build_payment_transaction(
        &self,
        payment: TransactionCall,
        quote: SwapQuote,
        refund_recipient: Address,
    ) -> Result<TransactionCall> {
        nonzero(refund_recipient)?;
        ensure(
            refund_recipient != self.deployment.router_address,
            "refund recipient must differ from Router",
        )?;
        let snapshot = self
            .frame(quote.route.channel() == SwapChannel::ZeroEx)
            .await?;
        self.check_quote(&quote, &snapshot)?;
        let (proof, request) =
            inspect_core_payment(&payment, &self.deployment, snapshot.block.timestamp)?;
        ensure(
            request.params.token == quote.token_out,
            "quote output token mismatch",
        )?;
        ensure(
            request.funding.amount == quote.amount_out,
            "quote funding amount mismatch",
        )?;
        ensure(
            U256::from(quote.deadline) <= request.params.deadline,
            "quote outlives core proof deadline",
        )?;
        let data = match quote.route {
            SwapRoute::UniswapV3 { reverse_path } => abi::Router::payCall {
                proof,
                request,
                reversePath: reverse_path.into(),
                swapDeadline: U256::from(quote.deadline),
                refundRecipient: refund_recipient,
            }
            .abi_encode(),
            SwapRoute::ZeroEx { target, data, .. } => {
                let checked = self.zeroex(
                    target,
                    data,
                    quote.token_out,
                    quote.amount_out,
                    quote.max_input,
                    &snapshot,
                )?;
                abi::Router::payWithZeroExCall {
                    proof,
                    request,
                    target: checked.target,
                    data: checked.data.into(),
                    swapDeadline: U256::from(quote.deadline),
                    refundRecipient: refund_recipient,
                }
                .abi_encode()
            }
        };
        self.assert_frame(&snapshot).await?;
        Ok(TransactionCall {
            to: self.deployment.router_address,
            data,
            value: quote.max_input,
        })
    }
    /// Simulate the full payable outer call and estimate gas with the actual submitting sender.
    pub async fn simulate_payment(
        &self,
        call: TransactionCall,
        from: Address,
    ) -> Result<RouterSimulation> {
        nonzero(from)?;
        ensure(
            call.to == self.deployment.router_address,
            "simulation target must be the payment Router",
        )?;
        uint(call.value, 256, true, "invalid ETH budget")?;
        let zeroex = call
            .data
            .starts_with(&abi::Router::payWithZeroExCall::SELECTOR);
        let (proof, request, deadline, recipient, route) = if zeroex {
            let p = abi::Router::payWithZeroExCall::abi_decode_validate(&call.data)?;
            (
                p.proof,
                p.request,
                p.swapDeadline,
                p.refundRecipient,
                SwapRoute::ZeroEx {
                    target: p.target,
                    data: p.data.to_vec(),
                    settler_address: Address::ZERO,
                },
            )
        } else {
            ensure(
                call.data.starts_with(&abi::Router::payCall::SELECTOR),
                "unsupported Router call",
            )?;
            let p = abi::Router::payCall::abi_decode_validate(&call.data)?;
            (
                p.proof,
                p.request,
                p.swapDeadline,
                p.refundRecipient,
                SwapRoute::UniswapV3 {
                    reverse_path: p.reversePath.to_vec(),
                },
            )
        };
        let snapshot = self.frame(zeroex).await?;
        inspect_request(&proof, &request, &self.deployment, snapshot.block.timestamp)?;
        uint(deadline, 64, false, "invalid swap deadline")?;
        ensure(
            deadline >= U256::from(snapshot.block.timestamp),
            "Router swap expired",
        )?;
        nonzero(recipient)?;
        ensure(
            recipient != self.deployment.router_address,
            "invalid refund recipient",
        )?;
        match route {
            SwapRoute::UniswapV3 { reverse_path } => validate_v3_path(
                &reverse_path,
                self.deployment.weth_address,
                request.params.token,
            )?,
            SwapRoute::ZeroEx { target, data, .. } => {
                self.zeroex(
                    target,
                    data,
                    request.params.token,
                    request.funding.amount,
                    call.value,
                    &snapshot,
                )?;
            }
        }
        let result = self
            .provider
            .call(call.clone(), Some(from), snapshot.block.number)
            .await?;
        let gas_estimate = self
            .provider
            .estimate_gas(call.clone(), from, snapshot.block.number)
            .await?;
        let eth_spent = U256::abi_decode_validate(&result)?;
        ensure(
            eth_spent <= call.value,
            "simulated input exceeds ETH budget",
        )?;
        self.assert_frame(&snapshot).await?;
        Ok(RouterSimulation {
            gas_estimate,
            eth_spent,
            eth_refunded: call.value - eth_spent,
        })
    }
}
/// Inspect an exported core tuple without changing any proof-bound values.
pub fn inspect_core_payment(
    call: &TransactionCall,
    d: &PaymentRouterDeployment,
    now: u64,
) -> Result<(Bytes, abi::IInvisiCore::TransactRequest)> {
    ensure(
        call.to == d.core_address && call.value.is_zero(),
        "core payment deployment/value mismatch",
    )?;
    let core = InvisiCore::transact_0Call::abi_decode_validate(&call.data)?;
    ensure(core.abi_encode() == call.data, "noncanonical Core calldata")?;
    let request = abi::IInvisiCore::TransactRequest::abi_decode_validate(&core.r.abi_encode())?;
    inspect_request(&core._0, &request, d, now)?;
    Ok((core._0, request))
}
fn inspect_request(
    proof: &Bytes,
    r: &abi::IInvisiCore::TransactRequest,
    d: &PaymentRouterDeployment,
    now: u64,
) -> Result<()> {
    ensure(!proof.is_empty(), "core proof is required")?;
    let f = &r.funding;
    let p = &r.params;
    ensure(
        f.payer == d.router_address,
        "core proof funding payer must be the Router",
    )?;
    uint(f.amount, 128, true, "invalid funding amount")?;
    ensure(
        f.sigNonce.is_zero()
            && f.deadline.is_zero()
            && f.signature.is_empty()
            && f.permit.deadline.is_zero()
            && f.permit.v == 0
            && f.permit.r == B256::ZERO
            && f.permit.s == B256::ZERO,
        "canonical direct Router funding is required",
    )?;
    ensure(
        p.sources.is_empty()
            && p.nullifiers.is_empty()
            && p.withdrawalAmount.is_zero()
            && p.withdrawalAddress.is_zero(),
        "Router payment requires zero private inputs and no withdrawal",
    )?;
    nonzero(p.token)?;
    ensure(p.feeAmount <= f.amount, "fee exceeds funding")?;
    ensure(
        (2..=190).contains(&p.noteCommitments.len()),
        "unsupported transact shape",
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for note in &p.noteCommitments {
        let n = U256::from_be_slice(note.as_slice());
        ensure(
            !n.is_zero() && n < invisi_sdk::note::field_modulus() && seen.insert(*note),
            "duplicate, zero or invalid note commitment",
        )?;
    }
    ensure(
        r.deliveries.len() == p.noteCommitments.len(),
        "deliveries count mismatch",
    )?;
    for delivery in &r.deliveries {
        if delivery.ciphertext.is_empty() && delivery.clue.is_empty() {
            continue;
        }
        ensure(
            !delivery.ciphertext.is_empty()
                && delivery.ciphertext.len() <= 4096
                && delivery.clue.len() == 68,
            "invalid delivery encoding",
        )?;
        ensure(delivery.clue[64] == 24, "clue precision must be 24")?;
    }
    uint(p.feeAmount, 128, false, "invalid fee amount")?;
    ensure(
        p.feeAmount.is_zero() == p.feeRecipient.is_zero(),
        "invalid fee",
    )?;
    uint(p.deadline, 64, false, "invalid core deadline")?;
    ensure(p.deadline >= U256::from(now), "core deadline expired")?;
    Ok(())
}

/// Pinned EIP-7702 account implementation. Wallet delegation remains an explicit host action.
#[derive(Clone, Debug)]
pub struct AccountDeployment {
    pub implementation: Address,
    pub runtime_code_hash: B256,
}
#[derive(Clone, Debug)]
pub struct CanonicalSimulation {
    pub gas_estimate: U256,
    pub input_spent: U256,
    pub input_refunded: U256,
}
impl PaymentRouterClient {
    /// Prepare any canonical mode after deployment, current Router nonce and route validation.
    /// Use `prepare_payment` first to produce/prove the detached Core transaction.
    pub async fn prepare_canonical(
        &self,
        core: TransactionCall,
        intent: canonical::Intent,
        route: canonical::Route,
    ) -> Result<canonical::Payment> {
        let frame = self.frame(route.channel == 2).await?;
        let nonce = self
            .router_nonce_at(intent.payer, frame.block.number)
            .await?;
        ensure(intent.nonce == nonce, "stale Router nonce")?;
        let payment = canonical::Payment::prepare(
            &self.deployment,
            core,
            intent,
            route,
            frame.block.timestamp,
            frame.settler_address,
        )?;
        self.assert_frame(&frame).await?;
        Ok(payment)
    }
    async fn router_nonce_at(&self, payer: Address, block: u64) -> Result<U256> {
        U256::abi_decode_validate(
            &self
                .read(
                    self.deployment.router_address,
                    canonical::noncesCall { payer }.abi_encode(),
                    block,
                )
                .await?,
        )
        .map_err(Error::from)
    }
    pub async fn router_nonce(&self, payer: Address) -> Result<U256> {
        nonzero(payer)?;
        let f = self.frame(false).await?;
        let n = self.router_nonce_at(payer, f.block.number).await?;
        self.assert_frame(&f).await?;
        Ok(n)
    }
    pub async fn token_allowance(&self, token: Address, payer: Address) -> Result<U256> {
        nonzero(token)?;
        nonzero(payer)?;
        let f = self.frame(false).await?;
        let n = U256::abi_decode_validate(
            &self
                .read(
                    token,
                    canonical::allowanceCall {
                        owner: payer,
                        spender: self.deployment.router_address,
                    }
                    .abi_encode(),
                    f.block.number,
                )
                .await?,
        )?;
        self.assert_frame(&f).await?;
        Ok(n)
    }
    /// Quote an arbitrary ERC20 or wrapped-native exact-output V3 path at a pinned block.
    /// Returns the raw estimate; callers choose their signed maximum/slippage budget.
    pub async fn quote_canonical_v3(
        &self,
        quoter: Address,
        path: Bytes,
        token_in: Address,
        token_out: Address,
        amount: U256,
    ) -> Result<U256> {
        nonzero(quoter)?;
        nonzero(token_in)?;
        nonzero(token_out)?;
        uint(amount, 128, true, "invalid quote output")?;
        validate_v3_path(&path, token_in, token_out)?;
        let f = self.frame(false).await?;
        self.code(quoter, f.block.number).await?;
        let data = self
            .read(
                quoter,
                abi::quoteExactOutputCall {
                    path,
                    amountOut: amount,
                }
                .abi_encode(),
                f.block.number,
            )
            .await?;
        let result = abi::quoteExactOutputCall::abi_decode_returns_validate(&data)?;
        self.assert_frame(&f).await?;
        ensure(!result.amountIn.is_zero(), "invalid V3 quote")?;
        Ok(result.amountIn)
    }
    /// Inspect account deployment and installed delegation without replacing existing wallet code.
    async fn account_at(
        &self,
        payer: Address,
        d: &AccountDeployment,
        block: u64,
        allow_pending: bool,
    ) -> Result<U256> {
        nonzero(d.implementation)?;
        ensure(
            !d.runtime_code_hash.is_zero(),
            "account runtime pin required",
        )?;
        ensure(
            keccak256(self.code(d.implementation, block).await?) == d.runtime_code_hash,
            "account runtime mismatch",
        )?;
        for (name, expected) in [
            ("router()", self.deployment.router_address),
            ("implementation()", d.implementation),
        ] {
            ensure(
                Address::abi_decode_validate(
                    &self
                        .read(d.implementation, keccak256(name)[..4].to_vec(), block)
                        .await?,
                )? == expected,
                "account immutable mismatch",
            )?;
        }
        let router_hash = B256::abi_decode_validate(
            &self
                .read(
                    d.implementation,
                    keccak256("routerCodeHash()")[..4].to_vec(),
                    block,
                )
                .await?,
        )?;
        ensure(
            router_hash == keccak256(self.code(self.deployment.router_address, block).await?),
            "account Router runtime mismatch",
        )?;
        let installed = self.provider.code(payer, block).await?;
        let mut expected = vec![0xef, 0x01, 0x00];
        expected.extend_from_slice(d.implementation.as_slice());
        ensure(
            installed == expected || (allow_pending && installed.is_empty()),
            "incompatible existing account delegation",
        )?;
        if installed.is_empty() {
            // Revocation removes code, not storage. Reinstalling the implementation must
            // continue the account action nonce rather than reactivate nonce-zero actions.
            let slot = U256::from_be_slice(
                keccak256("invisi.payment-router.account.storage.v1").as_slice(),
            ) - U256::from(1);
            let word = self
                .provider
                .storage_at(payer, B256::from(slot.to_be_bytes::<32>()), block)
                .await?;
            return Ok(U256::from_be_slice(word.as_slice()));
        }
        Ok(U256::abi_decode_validate(
            &self
                .read(payer, keccak256("nonce()")[..4].to_vec(), block)
                .await?,
        )?)
    }
    /// Build a wallet-signable native payment after checking the actual account action nonce.
    pub async fn prepare_native_account(
        &self,
        p: &canonical::Payment,
        d: &AccountDeployment,
        deadline: U256,
        allow_pending_delegation: bool,
    ) -> Result<canonical::NativePayment> {
        let f = self.frame(p.route().channel == 2).await?;
        ensure(
            deadline >= U256::from(f.block.timestamp) && deadline <= p.intent().deadline,
            "invalid account deadline",
        )?;
        let checked = canonical::Payment::prepare(
            &self.deployment,
            p.core().clone(),
            p.intent().clone(),
            p.route().clone(),
            f.block.timestamp,
            f.settler_address,
        )?;
        ensure(
            checked.intent() == p.intent() && p.chain_id() == self.deployment.chain_id,
            "payment deployment mismatch",
        )?;
        let nonce = self
            .account_at(
                p.intent().payer,
                d,
                f.block.number,
                allow_pending_delegation,
            )
            .await?;
        let hash = keccak256(
            self.code(self.deployment.router_address, f.block.number)
                .await?,
        );
        let result = canonical::NativePayment::prepare(p, d.implementation, hash, nonce, deadline)?;
        self.assert_frame(&f).await?;
        Ok(result)
    }
    /// Simulate and estimate the exact outer call with its actual sender and signed authorizations.
    /// Pending delegation requires provider support for authorizationList (unsupported RPCs fail).
    pub async fn simulate_canonical(
        &self,
        p: &canonical::Payment,
        call: TransactionCall,
        from: Address,
        authorizations: &[canonical::SignedAuthorization],
        account: Option<&AccountDeployment>,
    ) -> Result<CanonicalSimulation> {
        nonzero(from)?;
        ensure(
            p.chain_id() == self.deployment.chain_id,
            "payment chain mismatch",
        )?;
        let i = p.intent();
        let f = self.frame(p.route().channel == 2).await?;
        let fresh = canonical::Payment::prepare(
            &self.deployment,
            p.core().clone(),
            i.clone(),
            p.route().clone(),
            f.block.timestamp,
            f.settler_address,
        )?;
        ensure(
            fresh.intent() == i && self.router_nonce_at(i.payer, f.block.number).await? == i.nonce,
            "stale payment intent/nonce",
        )?;
        if i.mode >= canonical::RELAYED_TOKEN {
            ensure(from == i.relayer, "wrong relayer sender")?;
            let env = canonical::RouterEnvelope {
                to: call.to,
                data: call.data.clone().into(),
                value: call.value.to_string(),
                authorization_list: authorizations.to_vec(),
            };
            p.check_envelope(&env)?;
            if i.mode == canonical::SPONSORED_NATIVE {
                let d = account.ok_or(Error::Invalid("account deployment required"))?;
                let nonce = self
                    .account_at(i.payer, d, f.block.number, !authorizations.is_empty())
                    .await?;
                let action =
                    canonical::PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(
                        &call.data,
                    )?;
                ensure(
                    action.nonce_ == nonce && action.deadline >= U256::from(f.block.timestamp),
                    "stale account nonce/deadline",
                )?;
                let native = canonical::NativePayment::prepare(
                    p,
                    d.implementation,
                    keccak256(
                        self.code(self.deployment.router_address, f.block.number)
                            .await?,
                    ),
                    nonce,
                    action.deadline,
                )?;
                native.verify_signature(self.deployment.chain_id, &action.signature)?;
                canonical::validate_authorizations(
                    self.deployment.chain_id,
                    i.payer,
                    d.implementation,
                    authorizations,
                )?;
            }
        } else {
            ensure(
                from == i.payer && authorizations.is_empty(),
                "invalid direct payment sender",
            )?;
            let expected = if i.mode == canonical::DIRECT_NATIVE {
                p.router_call(canonical::Permit::default(), Bytes::new())?
            } else {
                let parsed =
                    canonical::PaymentRouter::payTokenCall::abi_decode_validate(&call.data)?;
                p.router_call(parsed.permit, Bytes::new())?
            };
            ensure(
                call.to == expected.to
                    && call.value == expected.value
                    && call.data == expected.data,
                "direct call differs from payment",
            )?;
        }
        let result = self
            .provider
            .call_authorized(call.clone(), from, f.block.number, authorizations)
            .await?;
        let gas = self
            .provider
            .estimate_gas_authorized(call, from, f.block.number, authorizations)
            .await?;
        let spent = U256::abi_decode_validate(&result)?;
        ensure(spent <= i.amountInMaximum, "simulated input exceeds cap")?;
        self.assert_frame(&f).await?;
        Ok(CanonicalSimulation {
            gas_estimate: gas,
            input_spent: spent,
            input_refunded: i.amountInMaximum - spent,
        })
    }
}

impl PaymentRouterClient {
    /// Accept a host-fetched 0x exact-buy response for either native or ERC20 input.
    /// The host chooses API authentication/transport; the SDK binds its public economic fields
    /// and validates the Holder/Settler calldata against a fresh deployment frame.
    pub async fn prepare_canonical_zeroex_quote(
        &self,
        core: TransactionCall,
        intent: canonical::Intent,
        body: &serde_json::Value,
    ) -> Result<canonical::Payment> {
        use invisi_sdk_protocol::interfaces;
        let parse_amount = |v: &serde_json::Value| {
            interfaces::decimal(v).map_err(|_| Error::Invalid("invalid 0x amount"))
        };
        let parse_address = |v: &serde_json::Value| {
            interfaces::address(v).map_err(|_| Error::Invalid("invalid 0x address"))
        };
        let frame = self.frame(true).await?;
        let (_, r) = inspect_core_payment(&core, &self.deployment, frame.block.timestamp)?;
        let input = if intent.tokenIn.is_zero() {
            NATIVE_TOKEN
        } else {
            intent.tokenIn
        };
        ensure(
            body["liquidityAvailable"] == true
                && parse_address(&body["sellToken"])? == input
                && parse_address(&body["buyToken"])? == r.params.token
                && parse_amount(&body["buyAmount"])? == r.funding.amount,
            "0x quote token/output mismatch",
        )?;
        let maximum = parse_amount(&body["maxSellAmount"])?;
        ensure(
            !maximum.is_zero() && maximum <= intent.amountInMaximum,
            "0x quote exceeds input cap",
        )?;
        if let Some(amount) = body.get("sellAmount") {
            ensure(
                parse_amount(amount)? <= maximum,
                "0x estimated input exceeds cap",
            )?;
        }
        for field in ["taker", "recipient"] {
            if let Some(v) = body.get(field) {
                ensure(
                    parse_address(v)? == self.deployment.router_address,
                    "0x taker/recipient mismatch",
                )?;
            }
        }
        let tx = &body["transaction"];
        ensure(
            parse_amount(&tx["value"])?
                == if intent.tokenIn.is_zero() {
                    intent.amountInMaximum
                } else {
                    U256::ZERO
                },
            "0x transaction value mismatch",
        )?;
        for id in [body.get("chainId"), tx.get("chainId")]
            .into_iter()
            .flatten()
        {
            let chain = if let Some(n) = id.as_u64() {
                U256::from(n)
            } else {
                parse_amount(id)?
            };
            ensure(
                chain == U256::from(self.deployment.chain_id),
                "0x quote chain mismatch",
            )?;
        }
        let route = canonical::Route {
            channel: 2,
            path: Bytes::new(),
            target: parse_address(&tx["to"])?,
            data: crate::provider::bytes(&tx["data"])?.into(),
        };
        let payment = canonical::Payment::prepare(
            &self.deployment,
            core,
            intent,
            route,
            frame.block.timestamp,
            frame.settler_address,
        )?;
        ensure(
            self.router_nonce_at(payment.intent().payer, frame.block.number)
                .await?
                == payment.intent().nonce,
            "stale Router nonce",
        )?;
        self.assert_frame(&frame).await?;
        let current = self.frame(true).await?;
        ensure(
            current.settler_address == frame.settler_address,
            "0x Settler changed; refresh quote",
        )?;
        ensure(
            payment.intent().deadline >= U256::from(current.block.timestamp),
            "0x quote expired",
        )?;
        Ok(payment)
    }
}
