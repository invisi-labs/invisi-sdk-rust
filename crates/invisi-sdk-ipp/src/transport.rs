use crate::{validation::*, *};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};
#[derive(Default, Clone)]
pub struct Cancellation(Arc<(AtomicBool, tokio::sync::Notify)>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0 .0.store(true, Ordering::SeqCst);
        self.0 .1.notify_waiters();
    }
    pub async fn cancelled(&self) {
        let notified = self.0 .1.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.0 .0.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'a>>;
/// Custom transports must disable redirects and cookie handling. Responses are revalidated.
pub trait Transport: Send + Sync {
    fn send<'a>(&'a self, request: HttpRequest) -> TransportFuture<'a>;
}
pub struct ReqwestTransport(reqwest::Client);
impl ReqwestTransport {
    pub fn new() -> Result<Self> {
        Ok(Self(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .https_only(true)
                .build()
                .map_err(|_| Error::Transport)?,
        ))
    }
}
impl Transport for ReqwestTransport {
    fn send<'a>(&'a self, r: HttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            let method = reqwest::Method::from_bytes(r.method.as_bytes())
                .map_err(|_| Error::InvalidMessage)?;
            let mut req = self.0.request(method, &r.url);
            for (k, v) in r.headers {
                req = req.header(k, v);
            }
            if let Some(body) = r.body {
                req = req.body(body);
            }
            let mut response = req.send().await.map_err(|_| Error::Transport)?;
            check(
                response
                    .content_length()
                    .is_none_or(|n| n <= MAX_BODY_BYTES as u64),
            )?;
            let status = response.status().as_u16();
            let mut headers = BTreeMap::new();
            for (k, v) in response.headers() {
                let key = k.as_str().to_string();
                if key == "set-cookie" || key == "set-cookie2" {
                    continue;
                }
                check(!headers.contains_key(&key))?;
                headers.insert(
                    key,
                    v.to_str().map_err(|_| Error::InvalidMessage)?.to_string(),
                );
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
                check(body.len() + chunk.len() <= MAX_BODY_BYTES)?;
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}
#[derive(Clone)]
pub(crate) struct Http {
    pub transport: Arc<dyn Transport>,
    pub timeout: Duration,
}
fn duration(d: Duration) -> Result<Duration> {
    check(!d.is_zero() && d <= Duration::from_millis(2147483647))?;
    Ok(d)
}
pub fn retry_after(s: Option<&str>) -> Option<Duration> {
    let s = s?;
    if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
        let ms = s.parse::<f64>().ok()? * 1000.0;
        return ms
            .is_finite()
            .then(|| Duration::from_millis(ms.clamp(0.0, 2147483647.0) as u64));
    }
    httpdate::parse_http_date(s).ok().map(|d| {
        d.duration_since(SystemTime::now())
            .unwrap_or_default()
            .min(Duration::from_millis(2147483647))
    })
}
impl Http {
    pub async fn send(
        &self,
        url: &str,
        token: &str,
        method: &str,
        body: Option<&Value>,
        key: Option<&str>,
        cancel: Option<&Cancellation>,
        statuses: &[u16],
    ) -> Result<(Value, HttpResponse)> {
        api_url(url, None)?;
        no_secret(url, token)?;
        bearer(token)?;
        if let Some(k) = key {
            idempotency(k)?;
        }
        let mut headers = BTreeMap::from([
            ("authorization".into(), format!("Bearer {token}")),
            ("accept".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
        ]);
        if body.is_some() {
            headers.insert("content-type".into(), "application/json".into());
        }
        if let Some(k) = key {
            headers.insert("idempotency-key".into(), k.into());
        }
        let request = HttpRequest {
            method: method.into(),
            url: url.into(),
            headers,
            body: body
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|_| Error::InvalidMessage)?,
        };
        let operation = tokio::time::timeout(self.timeout, self.transport.send(request));
        let response = if let Some(c) = cancel {
            tokio::select! {biased;_=c.cancelled()=>return Err(Error::Cancelled),r=operation=>r}
        } else {
            operation.await
        }
        .map_err(|_| Error::Timeout)??;
        check(response.body.len() <= MAX_BODY_BYTES && !(300..400).contains(&response.status))?;
        let get = |k: &str| {
            response
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.as_str())
        };
        let ct = get("content-type")
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        check(ct.eq_ignore_ascii_case("application/json"))?;
        let value = parse_json(&response.body)?;
        if !statuses.contains(&response.status) {
            check(!(200..300).contains(&response.status))?;
            object(&value, &["ippVersion", "type", "error"], &[])?;
            check(value["ippVersion"] == 1 && value["type"] == "error")?;
            object(&value["error"], &["code", "message", "retryable"], &[])?;
            text(&value["error"]["code"])?;
            text(&value["error"]["message"])?;
            let retryable = value["error"]["retryable"]
                .as_bool()
                .ok_or(Error::InvalidMessage)?;
            return Err(Error::Service {
                code: service_code(text(&value["error"]["code"])?, token)?,
                status: response.status,
                retryable,
                retry_after: retry_after(get("retry-after")),
            });
        }
        Ok((value, response))
    }
}
pub struct IppClient {
    url: String,
    token: String,
    origin: String,
    http: Http,
    session: Option<PaymentSession>,
    request: Option<Request>,
    request_url: Option<String>,
    option: Option<String>,
    retry_after: Option<Duration>,
}
impl std::fmt::Debug for IppClient {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("IppClient")
    }
}
impl IppClient {
    pub fn new(session_url: &str, token: &str) -> Result<Self> {
        Self::with_transport(
            session_url,
            token,
            Arc::new(ReqwestTransport::new()?),
            Duration::from_secs(15),
        )
    }
    pub fn with_transport(
        url: &str,
        token: &str,
        transport: Arc<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self> {
        let origin = api_url(url, None)?.origin().ascii_serialization();
        bearer(token)?;
        no_secret(url, token)?;
        Ok(Self {
            url: url.into(),
            token: token.into(),
            origin,
            http: Http {
                transport,
                timeout: duration(timeout)?,
            },
            session: None,
            request: None,
            request_url: None,
            option: None,
            retry_after: None,
        })
    }
    pub fn from_checkout(checkout: &Checkout) -> Result<Self> {
        Self::from_checkout_with_transport(
            checkout,
            Arc::new(ReqwestTransport::new()?),
            Duration::from_secs(15),
        )
    }
    pub fn from_checkout_with_transport(
        checkout: &Checkout,
        transport: Arc<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self> {
        let (url, token) = parse_checkout_entry(text(&checkout.0["checkoutUrl"])?)?;
        Self::with_transport(&url, &token, transport, timeout)
    }
    pub fn from_payment_required(response: HttpResponse) -> Result<Self> {
        Self::from_payment_required_with_transport(
            response,
            Arc::new(ReqwestTransport::new()?),
            Duration::from_secs(15),
        )
    }
    pub fn from_payment_required_with_transport(
        response: HttpResponse,
        transport: Arc<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self> {
        check(response.status == 402 && response.body.len() <= MAX_BODY_BYTES)?;
        let ct = header(&response.headers, "content-type").ok_or(Error::InvalidMessage)?;
        check(
            ct.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json"),
        )?;
        let links = header(&response.headers, "link").ok_or(Error::InvalidMessage)?;
        let find = |rel: &str| -> Result<String> {
            let mut rest = links.as_str();
            let mut found = Vec::new();
            while let Some(start) = rest.find('<') {
                rest = &rest[start + 1..];
                let Some(end) = rest.find('>') else { break };
                let href = &rest[..end];
                rest = &rest[end + 1..];
                if let Some(tail) = rest.trim_start().strip_prefix(';') {
                    if let Some(tail) = tail.trim_start().strip_prefix("rel=\"") {
                        if let Some((name, _)) = tail.split_once('"') {
                            if name == rel {
                                found.push(href);
                            }
                        }
                    }
                }
            }
            check(found.len() == 1)?;
            Ok(found[0].into())
        };
        let session_url = find("ipp-session")?;
        let checkout = find("ipp-checkout")?;
        let (url, token) = parse_checkout_entry(&checkout)?;
        check(url == session_url)?;
        let mut c = Self::with_transport(&url, &token, transport, timeout)?;
        let session = parse_payment_session(parse_json(&response.body)?, Some(&c.origin))?;
        c.safe_session(&session)?;
        c.request_url = session.0["links"]["request"]["href"]
            .as_str()
            .map(str::to_owned);
        c.session = Some(session);
        Ok(c)
    }
    fn safe_url(&self, url: &str, request: Option<&Request>) -> Result<()> {
        no_secret(url, &self.token)?;
        if let Some(secret) = request.and_then(|r| r.0["credit"]["creditSharedKey"].as_str()) {
            no_secret(url, secret)?;
        }
        Ok(())
    }
    fn safe_session(&self, s: &PaymentSession) -> Result<()> {
        self.safe_url(
            text(&s.0["links"]["confirm"]["href"])?,
            self.request.as_ref(),
        )?;
        if let Some(url) = s.0["links"]["request"]["href"].as_str() {
            self.safe_url(url, self.request.as_ref())?;
        }
        Ok(())
    }
    pub async fn read_session(&mut self, cancel: Option<&Cancellation>) -> Result<PaymentSession> {
        let (value, response) = self
            .http
            .send(&self.url, &self.token, "GET", None, None, cancel, &[200])
            .await?;
        let s = parse_payment_session(value, Some(&self.origin))?;
        self.safe_session(&s)?;
        if let Some(old) = &self.session {
            for k in [
                "sessionId",
                "mode",
                "createdAt",
                "expiresAt",
                "merchant",
                "description",
                "options",
            ] {
                check(old.0.get(k) == s.0.get(k))?;
            }
            if !old.0["activeRequestId"].is_null() {
                check(old.0["activeRequestId"] == s.0["activeRequestId"])?;
            }
            terminal(&old.0, &s.0)?;
            if !old.0["receipt"].is_null() {
                check(old.0["receipt"] == s.0["receipt"])?;
            }
        }
        if let Some(r) = &self.request {
            assert_request_matches_session(r, &s)?;
            check(s.0["activeRequestId"] == r.0["requestId"])?;
            if !s.0["receipt"].is_null() {
                let d = &r.0[text(&r.0["mode"])?];
                for k in ["network", "protocolAddress"] {
                    check(d[k] == s.0["receipt"][k])?;
                }
            }
        }
        self.retry_after =
            retry_after(header(&response.headers, "retry-after").map(String::as_str));
        self.request_url = s.0["links"]["request"]["href"]
            .as_str()
            .map(str::to_owned)
            .or(self.request_url.take());
        self.session = Some(s.clone());
        Ok(s)
    }
    fn accept(&mut self, value: Value) -> Result<Request> {
        let r = parse_payment_request(value, Some(&self.origin))?;
        let url = text(&r.0["links"]["credentials"]["href"])?;
        self.safe_url(url, Some(&r))?;
        self.safe_url(&self.url, Some(&r))?;
        if let Some(url) = &self.request_url {
            self.safe_url(url, Some(&r))?;
        }
        let session = self.session.as_ref().ok_or(Error::InvalidMessage)?;
        self.safe_url(text(&session.0["links"]["confirm"]["href"])?, Some(&r))?;
        if let Some(url) = session.0["links"]["request"]["href"].as_str() {
            self.safe_url(url, Some(&r))?;
        }
        assert_request_matches_session(&r, session)?;
        if !session.0["receipt"].is_null() {
            let details = &r.0[text(&r.0["mode"])?];
            for key in ["network", "protocolAddress"] {
                check(details[key] == session.0["receipt"][key])?;
            }
        }
        if let Some(option) = &self.option {
            check(r.0["optionId"] == *option)?;
        }
        if let Some(old) = &self.request {
            for (k, v) in old.0.as_object().ok_or(Error::InvalidMessage)? {
                if !["status", "failureReason", "links"].contains(&k.as_str()) {
                    check(r.0[k] == *v)?;
                }
            }
            terminal(&old.0, &r.0)?;
        }
        self.option = Some(text(&r.0["optionId"])?.into());
        self.request = Some(r.clone());
        Ok(r)
    }
    pub async fn confirm(
        &mut self,
        option_id: &str,
        key: &str,
        cancel: Option<&Cancellation>,
    ) -> Result<Request> {
        idempotency(key)?;
        if self.session.is_none() {
            self.read_session(cancel).await?;
        }
        let s = self.session.as_ref().ok_or(Error::InvalidMessage)?;
        check(
            s.0["options"]
                .as_array()
                .is_some_and(|a| a.iter().any(|o| o["id"] == option_id))
                && self.option.as_ref().is_none_or(|o| o == option_id),
        )?;
        let (value, response) = self
            .http
            .send(
                text(&s.0["links"]["confirm"]["href"])?,
                &self.token,
                "POST",
                Some(&json!({"optionId":option_id})),
                Some(key),
                cancel,
                &[200, 201],
            )
            .await?;
        let location = header(&response.headers, "location").ok_or(Error::InvalidMessage)?;
        api_url(location, Some(&self.origin))?;
        let candidate = parse_payment_request(value.clone(), Some(&self.origin))?;
        self.safe_url(location, Some(&candidate))?;
        check(value["optionId"] == option_id)?;
        let r = self.accept(value)?;
        self.request_url = Some(location.clone());
        Ok(r)
    }
    pub async fn read_request(&mut self, cancel: Option<&Cancellation>) -> Result<Request> {
        if self.session.is_none() {
            self.read_session(cancel).await?;
        }
        let url = self.request_url.as_ref().ok_or(Error::InvalidMessage)?;
        let (value, _) = self
            .http
            .send(url, &self.token, "GET", None, None, cancel, &[200])
            .await?;
        self.accept(value)
    }
    pub async fn submit_credential(
        &mut self,
        credential: &Credential,
        key: Option<&str>,
        cancel: Option<&Cancellation>,
    ) -> Result<CredentialAcknowledgement> {
        if self.request.is_none() {
            self.read_request(cancel).await?;
        }
        let r = self.request.as_ref().ok_or(Error::InvalidMessage)?;
        parse_credential(credential.0.clone(), Some(r))?;
        let (v, _) = self
            .http
            .send(
                text(&r.0["links"]["credentials"]["href"])?,
                &self.token,
                "POST",
                Some(&credential.0),
                key,
                cancel,
                &[202],
            )
            .await?;
        object(
            &v,
            &["ippVersion", "type", "sessionId", "requestId", "status"],
            &[],
        )?;
        check(
            v["ippVersion"] == 1
                && v["type"] == "credential_acknowledgement"
                && v["status"] == "accepted"
                && v["sessionId"] == r.0["sessionId"]
                && v["requestId"] == r.0["requestId"],
        )?;
        Ok(CredentialAcknowledgement(v))
    }
    pub async fn wait_for_result(
        &mut self,
        interval: Duration,
        timeout: Duration,
        cancel: Option<&Cancellation>,
    ) -> Result<PaymentSession> {
        duration(interval)?;
        duration(timeout)?;
        let polling = async {
            loop {
                let wait = match self.read_session(cancel).await {
                    Ok(s) => {
                        if s.0["status"] == "succeeded" || s.0["status"] == "failed" {
                            return Ok(s);
                        }
                        self.retry_after.unwrap_or(interval)
                    }
                    Err(Error::Service {
                        status,
                        retryable: true,
                        retry_after,
                        ..
                    }) if status == 429 || status == 503 => retry_after.unwrap_or(interval),
                    Err(e) => return Err(e),
                };
                tokio::time::sleep(wait).await;
            }
        };
        if let Some(c) = cancel {
            tokio::select! {biased;_=c.cancelled()=>Err(Error::Cancelled),r=tokio::time::timeout(timeout,polling)=>r.map_err(|_|Error::Timeout)?}
        } else {
            tokio::time::timeout(timeout, polling)
                .await
                .map_err(|_| Error::Timeout)?
        }
    }
}
fn terminal(old: &Value, new: &Value) -> Result<()> {
    if old["status"] == "succeeded" || old["status"] == "failed" {
        check(old["status"] == new["status"] && old["failureReason"] == new["failureReason"])?;
    }
    Ok(())
}
pub fn create_checkout_url(session_url: &str, token: &str, page: &str) -> Result<String> {
    api_url(session_url, None)?;
    api_url(page, None)?;
    bearer(token)?;
    no_secret(session_url, token)?;
    no_secret(page, token)?;
    let fragment = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("sessionUrl", session_url)
        .append_pair("token", token)
        .finish();
    Ok(format!("{page}#{fragment}"))
}
pub fn payment_required_response(
    session: &PaymentSession,
    checkout: &Checkout,
) -> Result<HttpResponse> {
    let c = parse_checkout(checkout.0.clone())?;
    let origin = api_url(text(&c.0["sessionUrl"])?, None)?
        .origin()
        .ascii_serialization();
    let s = parse_payment_session(session.0.clone(), Some(&origin))?;
    check(
        s.0["expiresAt"] == c.0["expiresAt"]
            && s.0["status"] != "succeeded"
            && s.0["status"] != "failed",
    )?;
    Ok(HttpResponse {
        status: 402,
        headers: BTreeMap::from([
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
            (
                "link".into(),
                format!(
                    "<{}>; rel=\"ipp-session\", <{}>; rel=\"ipp-checkout\"",
                    text(&c.0["sessionUrl"])?,
                    text(&c.0["checkoutUrl"])?
                ),
            ),
        ]),
        body: serde_json::to_vec(&s).map_err(|_| Error::InvalidMessage)?,
    })
}
pub struct IppMerchantClient {
    url: String,
    token: String,
    http: Http,
}
impl std::fmt::Debug for IppMerchantClient {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("IppMerchantClient")
    }
}
impl IppMerchantClient {
    pub fn new(create_url: &str, token: &str) -> Result<Self> {
        Self::with_transport(
            create_url,
            token,
            Arc::new(ReqwestTransport::new()?),
            Duration::from_secs(15),
        )
    }
    pub fn with_transport(
        url: &str,
        token: &str,
        transport: Arc<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self> {
        api_url(url, None)?;
        bearer(token)?;
        no_secret(url, token)?;
        Ok(Self {
            url: url.into(),
            token: token.into(),
            http: Http {
                transport,
                timeout: duration(timeout)?,
            },
        })
    }
    pub async fn create_checkout(
        &self,
        input: &CheckoutInput,
        key: &str,
        cancel: Option<&Cancellation>,
    ) -> Result<Checkout> {
        parse_checkout_input(input.0.clone())?;
        let (value, _) = self
            .http
            .send(
                &self.url,
                &self.token,
                "POST",
                Some(&input.0),
                Some(key),
                cancel,
                &[200, 201],
            )
            .await?;
        let checkout = parse_checkout(value)?;
        check(checkout.0["expiresAt"] == input.0["expiresAt"])?;
        Ok(checkout)
    }
}

fn service_code(s: &str, token: &str) -> Result<String> {
    check(
        s.len() <= 64
            && s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
    )?;
    Ok(if s.contains(token) {
        "service_error".into()
    } else {
        s.into()
    })
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}
