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
        ensure(
            options.token != self.deployment.weth_address,
            "WETH output is not supported",
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
    ensure(p.token != d.weth_address, "WETH output is not supported")?;
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
