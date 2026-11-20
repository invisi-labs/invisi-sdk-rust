use crate::*;
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use invisi_sdk_protocol::{interfaces, protocol::TransactionCall};
use serde_json::Value;
use std::sync::Arc;
#[derive(Clone, Debug)]
pub struct V3Route {
    pub tokens: Vec<Address>,
    pub fees: Vec<u32>,
}
pub struct UniswapV3Adapter {
    provider: Arc<dyn RouterProvider>,
    quoter: Address,
    routes: Vec<V3Route>,
}
impl UniswapV3Adapter {
    pub fn new(
        provider: Arc<dyn RouterProvider>,
        quoter: Address,
        routes: Vec<V3Route>,
    ) -> Result<Self> {
        nonzero(quoter)?;
        ensure(!routes.is_empty(), "at least one V3 route is required")?;
        for route in &routes {
            encode_v3_exact_output_path(&route.tokens, &route.fees)?;
        }
        Ok(Self {
            provider,
            quoter,
            routes,
        })
    }
}
impl SwapQuoteAdapter for UniswapV3Adapter {
    fn channel(&self) -> SwapChannel {
        SwapChannel::UniswapV3
    }
    fn quote(&self, r: SwapQuoteRequest) -> BoxFuture<'_, Result<SwapQuote>> {
        Box::pin(async move {
            let p = &r.parameters;
            p.check()?;
            ensure(
                self.provider.chain_id().await? == r.deployment.chain_id,
                "V3 quoter chain mismatch",
            )?;
            ensure(p.deadline >= r.now, "quote expired")?;
            ensure(
                !self
                    .provider
                    .code(self.quoter, r.block_number)
                    .await?
                    .is_empty(),
                "missing QuoterV2 code",
            )?;
            let mut best: Option<SwapQuote> = None;
            for route in &self.routes {
                if route.tokens.first() != Some(&r.deployment.weth_address)
                    || route.tokens.last() != Some(&p.token_out)
                {
                    continue;
                }
                let path = encode_v3_exact_output_path(&route.tokens, &route.fees)?;
                let result = self
                    .provider
                    .call(
                        TransactionCall {
                            to: self.quoter,
                            value: U256::ZERO,
                            data: abi::quoteExactOutputCall {
                                path: path.clone().into(),
                                amountOut: p.amount_out,
                            }
                            .abi_encode(),
                        },
                        None,
                        r.block_number,
                    )
                    .await;
                let amount = match result.and_then(|data| {
                    Ok(abi::quoteExactOutputCall::abi_decode_returns_validate(&data)?.amountIn)
                }) {
                    Ok(n) if n > U256::ZERO => n,
                    _ => continue,
                };
                // Division before multiplication keeps intermediate arithmetic within uint256.
                let bps = U256::from(10000 + p.slippage_bps.unwrap_or(50) as u32);
                let divisor = U256::from(10000);
                let whole = (amount / divisor).checked_mul(bps);
                let remainder = ((amount % divisor) * bps + U256::from(9999)) / divisor;
                let max_input = match whole.and_then(|x| x.checked_add(remainder)) {
                    Some(n) if n <= p.max_input => n,
                    _ => continue,
                };
                let q = SwapQuote {
                    chain_id: r.deployment.chain_id,
                    router_address: r.deployment.router_address,
                    token_out: p.token_out,
                    amount_out: p.amount_out,
                    estimated_input: amount,
                    max_input,
                    deadline: p.deadline,
                    route: SwapRoute::UniswapV3 { reverse_path: path },
                };
                if best
                    .as_ref()
                    .is_none_or(|b| q.estimated_input < b.estimated_input)
                {
                    best = Some(q);
                }
            }
            p.check()?;
            best.ok_or(Error::Invalid(
                "No executable V3 route within the ETH budget",
            ))
        })
    }
}
pub trait ZeroExQuoteTransport: Send + Sync {
    fn fetch(&self, request: SwapQuoteRequest) -> BoxFuture<'_, Result<Value>>;
}
impl<F, Fut> ZeroExQuoteTransport for F
where
    F: Fn(SwapQuoteRequest) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<Value>> + Send + 'static,
{
    fn fetch(&self, request: SwapQuoteRequest) -> BoxFuture<'_, Result<Value>> {
        Box::pin((self)(request))
    }
}
pub struct ZeroExAdapter<T> {
    transport: T,
}
impl<T: ZeroExQuoteTransport> ZeroExAdapter<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}
fn decimal(v: &Value) -> Result<U256> {
    interfaces::decimal(v).map_err(|_| Error::Invalid("invalid canonical decimal"))
}
fn address(v: &Value) -> Result<Address> {
    interfaces::address(v).map_err(|_| Error::Invalid("invalid quote address"))
}
impl<T: ZeroExQuoteTransport> SwapQuoteAdapter for ZeroExAdapter<T> {
    fn channel(&self) -> SwapChannel {
        SwapChannel::ZeroEx
    }
    fn quote(&self, r: SwapQuoteRequest) -> BoxFuture<'_, Result<SwapQuote>> {
        Box::pin(async move {
            let p = &r.parameters;
            p.check()?;
            ensure(p.deadline >= r.now, "quote expired")?;
            let z = r
                .deployment
                .zero_ex
                .as_ref()
                .ok_or(Error::Invalid("0x deployment required"))?;
            let settler = r
                .settler_address
                .ok_or(Error::Invalid("current Settler required"))?;
            let body = self.transport.fetch(r.clone()).await?;
            p.check()?;
            ensure(body.is_object(), "invalid 0x quote")?;
            ensure(
                body["liquidityAvailable"] == true,
                "0x liquidity is unavailable",
            )?;
            ensure(
                address(&body["buyToken"])? == p.token_out,
                "0x buy token mismatch",
            )?;
            ensure(
                address(&body["sellToken"])? == NATIVE_TOKEN,
                "0x sell token must be native ETH",
            )?;
            ensure(
                decimal(&body["buyAmount"])? == p.amount_out,
                "0x buy amount mismatch",
            )?;
            let max_input = decimal(&body["maxSellAmount"])?;
            ensure(
                max_input > U256::ZERO && max_input <= p.max_input,
                "0x quote exceeds ETH budget",
            )?;
            let tx = &body["transaction"];
            ensure(tx.is_object(), "invalid 0x transaction")?;
            ensure(
                decimal(&tx["value"])? == max_input,
                "0x native transaction value mismatch",
            )?;
            for field in ["taker", "recipient"] {
                if let Some(v) = body.get(field) {
                    ensure(
                        address(v)? == r.deployment.router_address,
                        "0x taker or recipient mismatch",
                    )?;
                }
            }
            for id in [body.get("chainId"), tx.get("chainId")]
                .into_iter()
                .flatten()
            {
                let id = if id.is_number() {
                    let n = id.as_f64().ok_or(Error::Invalid("invalid chain ID"))?;
                    ensure(
                        n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n < (1u64 << 53) as f64,
                        "unsafe chain ID",
                    )?;
                    U256::from(n as u64)
                } else {
                    decimal(id)?
                };
                ensure(
                    id == U256::from(r.deployment.chain_id),
                    "0x quote chain mismatch",
                )?;
            }
            let checked = validate_zeroex_payload(&ZeroExPayloadOptions {
                target: address(&tx["to"])?,
                data: crate::provider::bytes(&tx["data"])?,
                router_address: r.deployment.router_address,
                token_out: p.token_out,
                amount_out: p.amount_out,
                max_input,
                settler_address: settler,
                allowance_holder_address: z.allowance_holder_address,
                now: r.now,
            })?;
            let estimated_input = body
                .get("sellAmount")
                .map(decimal)
                .transpose()?
                .unwrap_or(max_input);
            ensure(
                estimated_input <= max_input,
                "0x estimated input exceeds budget",
            )?;
            let deadline = U256::from(p.deadline)
                .min(checked.native_deadline)
                .to::<u64>();
            Ok(SwapQuote {
                chain_id: r.deployment.chain_id,
                router_address: r.deployment.router_address,
                token_out: p.token_out,
                amount_out: p.amount_out,
                estimated_input,
                max_input,
                deadline,
                route: SwapRoute::ZeroEx {
                    target: checked.target,
                    data: checked.data,
                    settler_address: checked.settler_address,
                },
            })
        })
    }
}
/// Injectable backend for hosts with their own HTTP stack. Implementations must not follow redirects.
/// Requests carry an explicitly supplied API header and must never be logged.
pub trait ZeroExHttpBackend: Send + Sync {
    fn execute(&self, request: reqwest::Request) -> BoxFuture<'_, Result<ZeroExHttpResponse>>;
}
pub struct ZeroExHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
struct ReqwestZeroExHttp(reqwest::Client);
impl ZeroExHttpBackend for ReqwestZeroExHttp {
    fn execute(&self, request: reqwest::Request) -> BoxFuture<'_, Result<ZeroExHttpResponse>> {
        Box::pin(async move {
            let response = self
                .0
                .execute(request)
                .await
                .map_err(|_| Error::Invalid("0x quote request failed"))?;
            let status = response.status().as_u16();
            // Error bodies can contain secrets or upstream diagnostics; do not read them.
            if !(200..300).contains(&status) {
                return Ok(ZeroExHttpResponse {
                    status,
                    body: vec![],
                });
            }
            let body = response
                .bytes()
                .await
                .map_err(|_| Error::Invalid("0x quote request failed"))?
                .to_vec();
            Ok(ZeroExHttpResponse { status, body })
        })
    }
}
/// Backend-only native exact-buy HTTP transport. Credentials must be supplied explicitly.
pub struct ZeroExHttpTransport {
    backend: Arc<dyn ZeroExHttpBackend>,
    endpoint: reqwest::Url,
    key: reqwest::header::HeaderValue,
}
impl ZeroExHttpTransport {
    pub fn new(api_key: &str, endpoint: Option<&str>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Invalid("0x HTTP transport unavailable"))?;
        Self::with_backend(api_key, endpoint, Arc::new(ReqwestZeroExHttp(client)))
    }
    pub fn with_backend(
        api_key: &str,
        endpoint: Option<&str>,
        backend: Arc<dyn ZeroExHttpBackend>,
    ) -> Result<Self> {
        ensure(!api_key.trim().is_empty(), "0x API key required")?;
        let mut key = reqwest::header::HeaderValue::from_str(api_key)
            .map_err(|_| Error::Invalid("invalid 0x API key"))?;
        key.set_sensitive(true);
        let endpoint = reqwest::Url::parse(
            endpoint.unwrap_or("https://api.0x.org/swap/allowance-holder/quote"),
        )
        .map_err(|_| Error::Invalid("invalid 0x endpoint"))?;
        ensure(
            endpoint.scheme() == "https"
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "0x endpoint must be an HTTPS URL without credentials or query parameters",
        )?;
        Ok(Self {
            backend,
            endpoint,
            key,
        })
    }
    /// Request metadata is public; the explicit API credential is kept outside the URL.
    pub fn request_url(&self, r: &SwapQuoteRequest) -> reqwest::Url {
        let mut url = self.endpoint.clone();
        url.query_pairs_mut().extend_pairs([
            ("chainId", r.deployment.chain_id.to_string()),
            ("sellToken", format!("{NATIVE_TOKEN:#x}")),
            ("buyToken", format!("{:#x}", r.parameters.token_out)),
            ("buyAmount", r.parameters.amount_out.to_string()),
            ("taker", format!("{:#x}", r.deployment.router_address)),
            ("recipient", format!("{:#x}", r.deployment.router_address)),
            (
                "slippageBps",
                r.parameters.slippage_bps.unwrap_or(50).to_string(),
            ),
        ]);
        url
    }
}
impl ZeroExQuoteTransport for ZeroExHttpTransport {
    fn fetch(&self, r: SwapQuoteRequest) -> BoxFuture<'_, Result<Value>> {
        Box::pin(async move {
            r.parameters.check()?;
            let request = async {
                let mut request = reqwest::Request::new(reqwest::Method::GET, self.request_url(&r));
                request.headers_mut().insert("0x-api-key", self.key.clone());
                request.headers_mut().insert(
                    "0x-version",
                    reqwest::header::HeaderValue::from_static("v2"),
                );
                let response = self
                    .backend
                    .execute(request)
                    .await
                    .map_err(|_| Error::Invalid("0x quote request failed"))?;
                if !(200..300).contains(&response.status) {
                    return Err(Error::Http(response.status));
                }
                serde_json::from_slice(&response.body)
                    .map_err(|_| Error::Invalid("Invalid 0x quote JSON response"))
            };
            match &r.parameters.cancellation {
                Some(token) => {
                    tokio::select! {result=request=>{token.check()?;result},_=token.cancelled()=>Err(Error::Cancelled)}
                }
                None => request.await,
            }
        })
    }
}
