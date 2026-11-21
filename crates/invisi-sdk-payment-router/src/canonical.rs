//! PaymentRouter contract bindings and detached wallet signing/call preparation.
use crate::{ensure, nonzero, validate_v3_path, PaymentRouterDeployment, Result};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{eip712_domain, SolCall, SolValue};
use invisi_sdk_protocol::protocol::TransactionCall;

alloy_sol_types::sol!(
    #[sol(all_derives)]
    PaymentRouter,
    "src/canonical.abi.json"
);
alloy_sol_types::sol!(
    #[sol(all_derives)]
    PaymentRouterAccount,
    "src/account.abi.json"
);
pub use IInvisiCore::TransactRequest;
pub use IPaymentRouter::{Intent, Permit, Route};

pub const DIRECT_NATIVE: u8 = 0;
pub const DIRECT_TOKEN: u8 = 1;
pub const RELAYED_TOKEN: u8 = 2;
pub const SPONSORED_NATIVE: u8 = 3;

pub fn core_request_hash(proof: &[u8], request: &TransactRequest) -> B256 {
    keccak256((keccak256(proof), request.clone()).abi_encode_params())
}
pub fn route_hash(route: &Route) -> B256 {
    keccak256(route.abi_encode())
}

pub fn intent_digest(chain_id: u64, router: Address, intent: &Intent) -> B256 {
    let domain = eip712_domain! {name:"PaymentRouter",version:"1",chain_id:chain_id,verifying_contract:router,};
    let hash=keccak256((keccak256("Intent(address payer,address tokenIn,uint256 amountInMaximum,address refundRecipient,address relayer,uint256 nonce,uint256 deadline,bytes32 coreRequestHash,bytes32 routeHash,uint8 mode)"),intent.clone()).abi_encode_params());
    typed_digest(domain.separator(), hash)
}

#[derive(Clone, Debug)]
pub struct Payment {
    chain_id: u64,
    router: Address,
    proof: Bytes,
    request: TransactRequest,
    intent: Intent,
    route: Route,
    core: TransactionCall,
}
impl Payment {
    /// Validate the detached proof and bind the intended route and external payer to it.
    pub fn prepare(
        deployment: &PaymentRouterDeployment,
        core: TransactionCall,
        intent: Intent,
        route: Route,
        now: u64,
        settler: Option<Address>,
    ) -> Result<Self> {
        crate::inspect_core_payment(&core, deployment, now)?;
        Self::prepare_draft(deployment, core, intent, route, now, settler)
    }
    /// Prepare finalized business fields before generating a proof or wallet signatures.
    /// Rebuild using `prepare` after proving; semantic quote identity is unchanged.
    pub fn prepare_draft(
        deployment: &PaymentRouterDeployment,
        core: TransactionCall,
        mut intent: Intent,
        route: Route,
        now: u64,
        settler: Option<Address>,
    ) -> Result<Self> {
        deployment.validate()?;
        let router = deployment.router_address;
        let (proof, r) = crate::client::inspect_core_draft(&core, deployment, now)?;
        let request = TransactRequest::abi_decode_validate(&r.abi_encode())?;
        nonzero(intent.payer)?;
        nonzero(intent.refundRecipient)?;
        ensure(
            intent.payer != router && intent.refundRecipient != router,
            "payer/refund cannot be Router",
        )?;
        ensure(
            !intent.amountInMaximum.is_zero()
                && intent.deadline >= U256::from(now)
                && intent.deadline <= request.params.deadline,
            "invalid input budget or intent deadline",
        )?;
        ensure(
            intent.mode <= SPONSORED_NATIVE
                && (intent.mode >= RELAYED_TOKEN) != intent.relayer.is_zero(),
            "invalid payment mode or relayer",
        )?;
        let native = matches!(intent.mode, DIRECT_NATIVE | SPONSORED_NATIVE);
        ensure(
            native == intent.tokenIn.is_zero(),
            "mode and input token disagree",
        )?;
        let input = if native {
            deployment.weth_address
        } else {
            intent.tokenIn
        };
        let output = request.params.token;
        ensure(
            (input == output) == (route.channel == 0),
            "same-token and wrap payments require an empty route",
        )?;
        match route.channel {
            0 => ensure(
                route.path.is_empty()
                    && route.target.is_zero()
                    && route.data.is_empty()
                    && intent.amountInMaximum >= request.funding.amount,
                "invalid no-swap route",
            )?,
            1 => {
                ensure(
                    route.target.is_zero() && route.data.is_empty(),
                    "unexpected V3 target/data",
                )?;
                validate_v3_path(&route.path, input, output)?;
            }
            2 => {
                ensure(route.path.is_empty(), "unexpected 0x path")?;
                let holder = deployment
                    .zero_ex
                    .as_ref()
                    .ok_or(crate::Error::Invalid("missing 0x deployment"))?
                    .allowance_holder_address;
                let current = settler.ok_or(crate::Error::Invalid("missing registry Settler"))?;
                if native {
                    let checked = crate::validate_zeroex_payload(&crate::ZeroExPayloadOptions {
                        target: route.target,
                        data: route.data.to_vec(),
                        router_address: router,
                        token_out: output,
                        amount_out: request.funding.amount,
                        max_input: intent.amountInMaximum,
                        settler_address: current,
                        allowance_holder_address: holder,
                        now,
                    })?;
                    ensure(
                        checked.data == route.data.as_ref()
                            && intent.deadline <= checked.native_deadline,
                        "noncanonical or expired native quote",
                    )?;
                } else {
                    nonzero(current)?;
                    ensure(
                        current != holder && current != router && route.target == holder,
                        "invalid 0x Holder/Settler",
                    )?;
                    let outer = crate::abi::execCall::abi_decode_validate(&route.data)?;
                    ensure(
                        outer.operator == current
                            && outer.target == current
                            && outer.token == input
                            && outer.amount <= intent.amountInMaximum
                            && outer.abi_encode() == route.data.as_ref(),
                        "invalid 0x token envelope",
                    )?;
                    let inner = crate::abi::executeCall::abi_decode_validate(&outer.data)?;
                    ensure(
                        inner.slippage.recipient == router
                            && inner.slippage.buyToken == output
                            && inner.slippage.minAmountOut == request.funding.amount
                            && inner.abi_encode() == outer.data.as_ref(),
                        "invalid 0x token settlement",
                    )?;
                }
            }
            _ => return Err(crate::Error::Invalid("invalid route channel")),
        }
        intent.coreRequestHash = core_request_hash(&proof, &request);
        intent.routeHash = route_hash(&route);
        Ok(Self {
            chain_id: deployment.chain_id,
            router,
            proof,
            request,
            intent,
            route,
            core,
        })
    }
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn core(&self) -> &TransactionCall {
        &self.core
    }
    /// For sponsored native payments this is the inner payable call to the Router.
    pub fn router_call(&self, permit: Permit, signature: Bytes) -> Result<TransactionCall> {
        ensure(!self.proof.is_empty(), "core proof is required")?;
        ensure(
            self.intent.mode != RELAYED_TOKEN || !signature.is_empty(),
            "relay signature required",
        )?;
        self.draft_router_call(permit, signature)
    }
    /// Encode a draft outer call; empty proof and wallet signatures are permitted.
    pub fn draft_router_call(&self, permit: Permit, signature: Bytes) -> Result<TransactionCall> {
        let Self {
            proof,
            request: r,
            intent: i,
            route,
            ..
        } = self.clone();
        ensure(
            !permit.deadline.is_zero() || permit == Permit::default(),
            "invalid disabled permit",
        )?;
        ensure(
            i.mode == RELAYED_TOKEN || signature.is_empty(),
            "unexpected Router signature",
        )?;
        let value = if matches!(i.mode, DIRECT_NATIVE | SPONSORED_NATIVE) {
            i.amountInMaximum
        } else {
            U256::ZERO
        };
        let data = match i.mode {
            DIRECT_NATIVE | SPONSORED_NATIVE => {
                ensure(
                    permit == Permit::default(),
                    "native funding cannot use permit",
                )?;
                PaymentRouter::payNativeCall { proof, r, i, route }.abi_encode()
            }
            DIRECT_TOKEN => PaymentRouter::payTokenCall {
                proof,
                r,
                i,
                route,
                permit,
            }
            .abi_encode(),
            RELAYED_TOKEN => PaymentRouter::payTokenForCall {
                proof,
                r,
                i,
                route,
                permit,
                signature,
            }
            .abi_encode(),
            _ => unreachable!(),
        };
        Ok(TransactionCall {
            to: self.router,
            data,
            value,
        })
    }
}

fn typed_digest(domain: B256, hash: B256) -> B256 {
    keccak256([b"\x19\x01".as_slice(), domain.as_slice(), hash.as_slice()].concat())
}
/// Wallet-signable account message. The account nonce is independent of Router and authorization nonces.
#[derive(Clone, Debug)]
pub struct NativePayment {
    router_call: TransactionCall,
    payer: Address,
    implementation: Address,
    code_hash: B256,
    relayer: Address,
    nonce: U256,
    deadline: U256,
}
impl NativePayment {
    pub fn prepare(
        payment: &Payment,
        implementation: Address,
        code_hash: B256,
        nonce: U256,
        deadline: U256,
    ) -> Result<Self> {
        ensure(
            payment.intent.mode == SPONSORED_NATIVE,
            "sponsored native mode required",
        )?;
        nonzero(implementation)?;
        ensure(
            implementation != payment.intent.payer
                && !code_hash.is_zero()
                && !deadline.is_zero()
                && deadline <= payment.intent.deadline,
            "invalid delegated account parameters",
        )?;
        Ok(Self {
            router_call: payment.draft_router_call(Permit::default(), Bytes::new())?,
            payer: payment.intent.payer,
            implementation,
            code_hash,
            relayer: payment.intent.relayer,
            nonce,
            deadline,
        })
    }
    pub fn digest(&self, chain_id: u64) -> B256 {
        let domain = eip712_domain! {name:"PaymentRouterAccount",version:"1",chain_id:chain_id,verifying_contract:self.payer,salt:self.implementation.into_word(),};
        let hash=keccak256((keccak256("NativePayment(bytes32 routerCalldataHash,uint256 value,uint256 nonce,uint256 deadline,address relayer,address router,bytes32 routerCodeHash)"),keccak256(&self.router_call.data),self.router_call.value,self.nonce,self.deadline,self.relayer,self.router_call.to,self.code_hash).abi_encode_params());
        typed_digest(domain.separator(), hash)
    }
    pub fn account_call(&self, signature: Bytes) -> Result<TransactionCall> {
        ensure(
            signature.len() == 65,
            "account requires a 65-byte EOA signature",
        )?;
        self.draft_account_call(signature)
    }
    /// Encode account metadata before obtaining the wallet execution signature.
    pub fn draft_account_call(&self, signature: Bytes) -> Result<TransactionCall> {
        Ok(TransactionCall {
            to: self.payer,
            value: U256::ZERO,
            data: PaymentRouterAccount::executeNativePaymentCall {
                routerCalldata: self.router_call.data.clone().into(),
                value: self.router_call.value,
                nonce_: self.nonce,
                deadline: self.deadline,
                relayer: self.relayer,
                signature,
            }
            .abi_encode(),
        })
    }
}

/// Recover an EOA signer from a canonical low-s Ethereum signature (v=27/28 or 0/1).
/// Contract-wallet Router intents use ERC1271 through full-call simulation instead.
pub fn recover_signer(digest: B256, bytes: &[u8]) -> Result<Address> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    ensure(bytes.len() == 65, "65-byte signature required")?;
    let v = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => return Err(crate::Error::Invalid("invalid recovery id")),
    };
    let sig = Signature::from_slice(&bytes[..64])
        .map_err(|_| crate::Error::Invalid("invalid ECDSA signature"))?;
    ensure(sig.normalize_s().is_none(), "high-s signature")?;
    let key = VerifyingKey::recover_from_prehash(
        digest.as_slice(),
        &sig,
        RecoveryId::try_from(v).map_err(|_| crate::Error::Invalid("invalid recovery id"))?,
    )
    .map_err(|_| crate::Error::Invalid("signature recovery failed"))?;
    Ok(Address::from_slice(
        &keccak256(&key.to_encoded_point(false).as_bytes()[1..])[12..],
    ))
}

alloy_sol_types::sol! {
    #[sol(all_derives)]
    struct EnvelopeAuthorization { uint256 chainId; address delegate; uint64 nonce; uint8 yParity; bytes32 r; bytes32 s; }
    function approve(address spender,uint256 amount) returns(bool);
    function nonces(address payer) view returns(uint256);
    function allowance(address owner,address spender) view returns(uint256);
}
/// Host-signed EIP-7702 authorization in geth JSON-RPC representation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAuthorization {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: alloy_primitives::U64,
    pub y_parity: alloy_primitives::U8,
    pub r: U256,
    pub s: U256,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterEnvelope {
    pub to: Address,
    pub data: Bytes,
    pub value: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorization_list: Vec<SignedAuthorization>,
}
pub const ENVELOPE_HASH_FORMAT: &str = "payment-router-envelope-v1";
/// Exact Go/Broadcaster envelope hash. The hash includes the signed authorization list order.
pub fn envelope_hash(chain_id: u64, core: Address, e: &RouterEnvelope) -> Result<B256> {
    ensure(
        chain_id > 0 && !core.is_zero() && !e.to.is_zero() && e.value == "0" && e.data.len() >= 4,
        "invalid relay envelope",
    )?;
    let auth: Vec<EnvelopeAuthorization> = e
        .authorization_list
        .iter()
        .map(|a| EnvelopeAuthorization {
            chainId: a.chain_id,
            delegate: a.address,
            nonce: a.nonce.to::<u64>(),
            yParity: a.y_parity.to::<u8>(),
            r: B256::from(a.r.to_be_bytes::<32>()),
            s: B256::from(a.s.to_be_bytes::<32>()),
        })
        .collect();
    let auth_hash = keccak256((auth,).abi_encode_params());
    Ok(keccak256((keccak256("InvisiPaymentRouterEnvelope(uint256 chainId,address core,address to,uint256 value,bytes32 dataHash,bytes32 authorizationListHash)"),U256::from(chain_id),core,e.to,U256::ZERO,keccak256(&e.data),auth_hash).abi_encode_params()))
}
pub fn approval(token: Address, router: Address, amount: U256) -> Result<TransactionCall> {
    nonzero(token)?;
    nonzero(router)?;
    Ok(TransactionCall {
        to: token,
        value: U256::ZERO,
        data: approveCall {
            spender: router,
            amount,
        }
        .abi_encode(),
    })
}
impl Payment {
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    pub fn route(&self) -> &Route {
        &self.route
    }
    pub fn request(&self) -> &TransactRequest {
        &self.request
    }
    pub fn digest(&self, chain_id: u64) -> B256 {
        intent_digest(chain_id, self.router, &self.intent)
    }
    /// Validate a relayed outer call against this immutable prepared payment.
    pub fn check_envelope(&self, e: &RouterEnvelope) -> Result<()> {
        ensure(e.value == "0", "relay principal must be zero")?;
        match self.intent.mode {
            RELAYED_TOKEN => {
                ensure(
                    e.to == self.router && e.authorization_list.is_empty(),
                    "invalid token relay target/authorization",
                )?;
                let c = PaymentRouter::payTokenForCall::abi_decode_validate(&e.data)?;
                ensure(
                    self.draft_router_call(c.permit, c.signature)?.data == e.data.as_ref(),
                    "relay calldata differs from payment",
                )
            }
            SPONSORED_NATIVE => {
                ensure(e.to == self.intent.payer, "invalid account relay target")?;
                let c =
                    PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&e.data)?;
                ensure(
                    c.abi_encode() == e.data.as_ref()
                        && c.routerCalldata.as_ref()
                            == self
                                .draft_router_call(Permit::default(), Bytes::new())?
                                .data
                        && c.value == self.intent.amountInMaximum
                        && c.relayer == self.intent.relayer
                        && c.deadline <= self.intent.deadline,
                    "invalid account relay action",
                )
            }
            _ => Err(crate::Error::Invalid("relay mode required")),
        }
    }
    pub fn relay_envelope(&self, permit: Permit, signature: Bytes) -> Result<RouterEnvelope> {
        ensure(
            self.intent.mode == RELAYED_TOKEN,
            "relayed token mode required",
        )?;
        let c = self.router_call(permit, signature)?;
        Ok(RouterEnvelope {
            to: c.to,
            data: c.data.into(),
            value: "0".into(),
            authorization_list: vec![],
        })
    }
}
impl NativePayment {
    pub fn envelope(
        &self,
        signature: Bytes,
        authorization_list: Vec<SignedAuthorization>,
    ) -> Result<RouterEnvelope> {
        let c = self.account_call(signature)?;
        for a in &authorization_list {
            ensure(
                a.address == self.implementation,
                "authorization implementation mismatch",
            )?;
        }
        Ok(RouterEnvelope {
            to: c.to,
            data: c.data.into(),
            value: "0".into(),
            authorization_list,
        })
    }
    pub fn verify_signature(&self, chain_id: u64, signature: &[u8]) -> Result<()> {
        ensure(
            recover_signer(self.digest(chain_id), signature)? == self.payer,
            "wrong native payment signer",
        )
    }
}

/// EIP-7702 signing request: wallet must explicitly authorize this persistent delegation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub chain_id: u64,
    pub implementation: Address,
    pub nonce: u64,
}
impl AuthorizationRequest {
    pub fn digest(&self) -> Result<B256> {
        ensure(
            self.chain_id > 0 && !self.implementation.is_zero() && self.nonce < u64::MAX,
            "invalid authorization request",
        )?;
        fn scalar(n: u64) -> Vec<u8> {
            if n == 0 {
                return vec![0x80];
            };
            if n < 128 {
                return vec![n as u8];
            };
            let b = n.to_be_bytes();
            let data = &b[b.iter().position(|x| *x != 0).unwrap()..];
            let mut out = vec![0x80 + data.len() as u8];
            out.extend_from_slice(data);
            out
        }
        let mut list = scalar(self.chain_id);
        list.push(0x94);
        list.extend_from_slice(self.implementation.as_slice());
        list.extend(scalar(self.nonce));
        let mut message = vec![0x05, 0xc0 + list.len() as u8];
        message.extend(list);
        Ok(keccak256(message))
    }
}
/// Validate exact-chain, single-payer authorization. Empty means delegation is already installed.
pub fn validate_authorizations(
    chain_id: u64,
    payer: Address,
    implementation: Address,
    list: &[SignedAuthorization],
) -> Result<()> {
    ensure(list.len() <= 1, "one payer authorization expected")?;
    for a in list {
        ensure(
            a.chain_id == U256::from(chain_id)
                && a.address == implementation
                && a.y_parity <= alloy_primitives::U8::from(1),
            "authorization chain/delegate mismatch",
        )?;
        let request = AuthorizationRequest {
            chain_id,
            implementation,
            nonce: a.nonce.to::<u64>(),
        };
        let mut sig = a.r.to_be_bytes::<32>().to_vec();
        sig.extend_from_slice(&a.s.to_be_bytes::<32>());
        sig.push(a.y_parity.to::<u8>());
        ensure(
            recover_signer(request.digest()?, &sig)? == payer,
            "authorization signer mismatch",
        )?;
    }
    Ok(())
}

/// ERC-2612 permit digest for the token's independently verified domain separator.
/// Approval is to the Router; permit does not authorize the payment intent itself.
pub fn permit_digest(
    domain_separator: B256,
    owner: Address,
    router: Address,
    amount: U256,
    nonce: U256,
    deadline: U256,
) -> Result<B256> {
    nonzero(owner)?;
    nonzero(router)?;
    ensure(
        !domain_separator.is_zero() && !deadline.is_zero(),
        "invalid permit domain/deadline",
    )?;
    Ok(typed_digest(domain_separator,keccak256((keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),owner,router,amount,nonce,deadline).abi_encode_params())))
}

/// Quote identity excludes only proof and wallet signature material.
pub const ROUTER_INTENT_HASH_FORMAT: &str = "payment-router-intent-v1";
pub fn router_intent_hash(chain_id: u64, core: Address, envelope: &RouterEnvelope) -> Result<B256> {
    let mut normalized = envelope.clone();
    if envelope
        .data
        .starts_with(&PaymentRouter::payTokenForCall::SELECTOR)
    {
        let mut call = PaymentRouter::payTokenForCall::abi_decode_validate(&envelope.data)?;
        ensure(
            call.abi_encode() == envelope.data.as_ref(),
            "noncanonical Router calldata",
        )?;
        ensure(
            call.i.mode == RELAYED_TOKEN && envelope.authorization_list.is_empty(),
            "invalid token relay mode/authorizations",
        )?;
        normalize_intent(&call.proof, &call.r, &call.route, &mut call.i)?;
        call.proof = Bytes::new();
        call.signature = Bytes::new();
        call.permit.v = 0;
        call.permit.r = B256::ZERO;
        call.permit.s = B256::ZERO;
        normalized.data = call.abi_encode().into();
    } else {
        let mut action =
            PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&envelope.data)?;
        ensure(
            action.abi_encode() == envelope.data.as_ref(),
            "noncanonical account calldata",
        )?;
        let mut call = PaymentRouter::payNativeCall::abi_decode_validate(&action.routerCalldata)?;
        ensure(
            call.abi_encode() == action.routerCalldata.as_ref()
                && call.i.mode == SPONSORED_NATIVE
                && envelope.to == call.i.payer
                && action.value == call.i.amountInMaximum
                && action.relayer == call.i.relayer
                && action.deadline <= call.i.deadline,
            "invalid native account envelope",
        )?;
        normalize_intent(&call.proof, &call.r, &call.route, &mut call.i)?;
        call.proof = Bytes::new();
        action.routerCalldata = call.abi_encode().into();
        action.signature = Bytes::new();
        normalized.data = action.abi_encode().into();
    }
    for a in &mut normalized.authorization_list {
        a.y_parity = alloy_primitives::U8::ZERO;
        a.r = U256::ZERO;
        a.s = U256::ZERO;
    }
    Ok(keccak256(
        (
            keccak256("InvisiPaymentRouterIntentV1"),
            envelope_hash(chain_id, core, &normalized)?,
        )
            .abi_encode_params(),
    ))
}
fn normalize_intent(
    proof: &[u8],
    request: &TransactRequest,
    route: &Route,
    intent: &mut Intent,
) -> Result<()> {
    ensure(
        intent.coreRequestHash == core_request_hash(proof, request)
            && intent.routeHash == route_hash(route),
        "invalid actual Core/route hash",
    )?;
    intent.coreRequestHash = core_request_hash(&[], request);
    Ok(())
}
impl Payment {
    pub fn draft_relay_envelope(&self, permit: Permit) -> Result<RouterEnvelope> {
        ensure(
            self.intent.mode == RELAYED_TOKEN,
            "relayed token mode required",
        )?;
        let call = self.draft_router_call(permit, Bytes::new())?;
        Ok(RouterEnvelope {
            to: call.to,
            data: call.data.into(),
            value: "0".into(),
            authorization_list: vec![],
        })
    }
    /// Final submission still requires proof and actual wallet authorization material.
    /// The provider-backed client additionally verifies pinned runtime, live counters and simulates.
    pub fn check_final_envelope(&self, envelope: &RouterEnvelope) -> Result<()> {
        self.check_envelope(envelope)?;
        ensure(!self.proof.is_empty(), "core proof is required")?;
        if self.intent.mode == RELAYED_TOKEN {
            let c = PaymentRouter::payTokenForCall::abi_decode_validate(&envelope.data)?;
            ensure(!c.signature.is_empty(), "relay signature required")?;
            ensure(
                c.permit.deadline.is_zero()
                    || (matches!(c.permit.v, 27 | 28)
                        && c.permit.r != B256::ZERO
                        && c.permit.s != B256::ZERO),
                "permit signature required",
            )?;
        } else {
            let c = PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(
                &envelope.data,
            )?;
            ensure(c.signature.len() == 65, "account signature required")?;
            ensure(
                envelope.authorization_list.len() <= 1,
                "one payer authorization expected",
            )?;
            for a in &envelope.authorization_list {
                validate_authorizations(
                    self.chain_id,
                    self.intent.payer,
                    a.address,
                    std::slice::from_ref(a),
                )?;
            }
        }
        router_intent_hash(self.chain_id, self.core.to, envelope)?;
        Ok(())
    }
}
impl NativePayment {
    pub fn draft_envelope(
        &self,
        authorization_list: Vec<SignedAuthorization>,
    ) -> Result<RouterEnvelope> {
        ensure(
            authorization_list.len() <= 1,
            "one payer authorization expected",
        )?;
        for a in &authorization_list {
            ensure(
                a.address == self.implementation,
                "authorization implementation mismatch",
            )?;
        }
        let call = self.draft_account_call(Bytes::new())?;
        Ok(RouterEnvelope {
            to: call.to,
            data: call.data.into(),
            value: "0".into(),
            authorization_list,
        })
    }
}
impl AuthorizationRequest {
    /// Unsigned tuple metadata to bind before the wallet signs the 7702 authorization.
    pub fn draft(&self) -> Result<SignedAuthorization> {
        self.digest()?;
        Ok(SignedAuthorization {
            chain_id: U256::from(self.chain_id),
            address: self.implementation,
            nonce: alloy_primitives::U64::from(self.nonce),
            y_parity: alloy_primitives::U8::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        })
    }
}
