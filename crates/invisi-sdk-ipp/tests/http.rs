use invisi_sdk_ipp::*;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<HttpRequest>>,
    replies: Mutex<VecDeque<HttpResponse>>,
}
impl Transport for Fake {
    fn send<'a>(&'a self, r: HttpRequest) -> TransportFuture<'a> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(r);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(Error::Transport)
        })
    }
}
fn fixture(kind: &str) -> Value {
    let c: Value = serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let case = c["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kind"] == kind && c["valid"] == true)
        .unwrap();
    serde_json::from_str(case["json"].as_str().unwrap()).unwrap()
}
fn reply(v: Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
        body: serde_json::to_vec(&v).unwrap(),
    }
}
#[tokio::test]
async fn session_changes_are_rejected_and_transport_uses_exact_get_url() {
    let fake = Arc::new(Fake::default());
    let session = fixture("session");
    let url = "https://connect.invisipay.fi/custom/session?view=1";
    fake.replies
        .lock()
        .unwrap()
        .push_back(reply(session.clone()));
    let mut client =
        IppClient::with_transport(url, "opaque-secret", fake.clone(), Duration::from_secs(1))
            .unwrap();
    client.read_session(None).await.unwrap();
    let mut changed = session;
    changed["merchant"]["name"] = json!("Changed");
    fake.replies.lock().unwrap().push_back(reply(changed));
    assert!(client.read_session(None).await.is_err());
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls[0].url, url);
    assert_eq!(calls[0].method, "GET");
    assert_eq!(calls[0].headers["authorization"], "Bearer opaque-secret");
}
#[tokio::test]
async fn cancellation_redirects_and_body_limits_are_enforced() {
    let fake = Arc::new(Fake::default());
    let mut client = IppClient::with_transport(
        "https://pay.example.test/session",
        "opaque",
        fake.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(
        client.read_session(Some(&cancel)).await,
        Err(Error::Cancelled)
    ));
    for response in [
        HttpResponse {
            status: 302,
            headers: BTreeMap::new(),
            body: vec![],
        },
        HttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: vec![b'a'; MAX_BODY_BYTES + 1],
        },
    ] {
        fake.replies.lock().unwrap().push_back(response);
        assert!(client.read_session(None).await.is_err());
    }
    assert!(!format!("{client:?}").contains("opaque"));
}
#[test]
fn checkout_entry_roundtrips_and_402_is_no_store() {
    let session = fixture("session");
    let checkout_url = create_checkout_url(
        "https://connect.invisipay.fi/session",
        "opaque+token/==",
        "https://wallet.example.test/checkout",
    )
    .unwrap();
    let (url, token) = parse_checkout_entry(&checkout_url).unwrap();
    assert_eq!(token, "opaque+token/==");
    let checkout=parse_checkout(json!({"ippVersion":1,"type":"checkout","sessionUrl":url,"checkoutUrl":checkout_url,"expiresAt":session["expiresAt"]})).unwrap();
    let session = parse_payment_session(session, None).unwrap();
    let response = payment_required_response(&session, &checkout).unwrap();
    assert_eq!(response.status, 402);
    assert_eq!(response.headers["cache-control"], "no-store");
}
#[tokio::test]
async fn confirm_credential_and_recovery_keep_original_links_and_terms() {
    let fake = Arc::new(Fake::default());
    let session = fixture("session");
    let request = fixture("request");
    fake.replies.lock().unwrap().push_back(reply(session));
    let mut confirmed = reply(request.clone());
    confirmed.status = 201;
    confirmed.headers.insert(
        "LoCaTiOn".into(),
        "https://connect.invisipay.fi/arbitrary/request?revision=1".into(),
    );
    fake.replies.lock().unwrap().push_back(confirmed);
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        fake.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    let r = client
        .confirm("base_usdc", "confirm-1", None)
        .await
        .unwrap();
    assert_eq!(r.request_id(), "req_test");
    assert_eq!(r.mode(), Mode::Payment);
    assert!(client
        .confirm("another-option", "confirm-2", None)
        .await
        .is_err());
    let credential = parse_credential(fixture("credential"), Some(&r)).unwrap();
    let mut ack = reply(
        json!({"ippVersion":1,"type":"credential_acknowledgement","status":"accepted","sessionId":"ses_test","requestId":"req_test"}),
    );
    ack.status = 202;
    fake.replies.lock().unwrap().push_back(ack);
    client
        .submit_credential(&credential, Some("credential-1"), None)
        .await
        .unwrap();
    let mut processing = request.clone();
    processing["status"] = json!("processing");
    fake.replies.lock().unwrap().push_back(reply(processing));
    client.read_request(None).await.unwrap();
    let mut changed = request;
    changed["expiresAt"] = json!("2026-11-17T09:00:00Z");
    fake.replies.lock().unwrap().push_back(reply(changed));
    assert!(client.read_request(None).await.is_err());
    let calls = fake.calls.lock().unwrap();
    assert_eq!(calls.len(), 5);
    assert_eq!(calls[1].method, "POST");
    assert_eq!(calls[1].headers["idempotency-key"], "confirm-1");
    assert_eq!(calls[1].url, "https://connect.invisipay.fi/custom/confirm");
    assert_eq!(calls[2].url, "https://connect.invisipay.fi/custom/hints");
    assert_eq!(calls[3].method, "GET");
    assert_eq!(
        calls[3].url,
        "https://connect.invisipay.fi/arbitrary/request?revision=1"
    );
}
#[tokio::test]
async fn polling_honors_success_and_error_retry_after_and_deadline() {
    for error in [false, true] {
        let fake = Arc::new(Fake::default());
        let mut first = if error {
            let mut r = reply(
                json!({"ippVersion":1,"type":"error","error":{"code":"busy","message":"opaque credential must not leak","retryable":true}}),
            );
            r.status = 503;
            r
        } else {
            reply(fixture("session"))
        };
        first.headers.insert("ReTrY-AfTeR".into(), "1".into());
        fake.replies.lock().unwrap().push_back(first);
        let mut client = IppClient::with_transport(
            "https://connect.invisipay.fi/session",
            "opaque",
            fake.clone(),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client
                .wait_for_result(Duration::from_millis(1), Duration::from_millis(30), None)
                .await,
            Err(Error::Timeout)
        ));
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn merchant_creation_replays_expired_input_across_service_origins() {
    let fake = Arc::new(Fake::default());
    let mut input = fixture("input");
    input["expiresAt"] = json!("2000-01-01T00:00:00Z");
    let input = parse_checkout_input(input).unwrap();
    let checkout = json!({"ippVersion":1,"type":"checkout","sessionUrl":"https://connect.invisipay.fi/session","checkoutUrl":create_checkout_url("https://connect.invisipay.fi/session","wallet-token","https://wallet.example.test/checkout").unwrap(),"expiresAt":input.expires_at()});
    for _ in 0..2 {
        let mut response = reply(checkout.clone());
        response.status = 201;
        fake.replies.lock().unwrap().push_back(response);
    }
    let merchant = IppMerchantClient::with_transport(
        "https://merchant.example.test/create?version=1",
        "merchant-token",
        fake.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    for _ in 0..2 {
        let c = merchant
            .create_checkout(&input, "same-key", None)
            .await
            .unwrap();
        assert_eq!(c.session_url(), "https://connect.invisipay.fi/session");
    }
    let calls = fake.calls.lock().unwrap();
    assert_eq!(
        calls[0].url,
        "https://merchant.example.test/create?version=1"
    );
    assert_eq!(calls[0].body, calls[1].body);
    assert_eq!(
        calls[0].headers["idempotency-key"],
        calls[1].headers["idempotency-key"]
    );
}
#[tokio::test]
async fn service_errors_are_sanitized_and_cookies_are_not_sent() {
    let fake = Arc::new(Fake::default());
    let mut response = reply(fixture("session"));
    response
        .headers
        .insert("Set-Cookie".into(), "credential=opaque; Secure".into());
    fake.replies.lock().unwrap().push_back(response);
    let mut error = reply(
        json!({"ippVersion":1,"type":"error","error":{"code":"temporarily_unavailable","message":"secret opaque echoed","retryable":true}}),
    );
    error.status = 503;
    error.headers.insert("Retry-After".into(), "5".into());
    fake.replies.lock().unwrap().push_back(error);
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        fake.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    client.read_session(None).await.unwrap();
    let err = client.read_session(None).await.unwrap_err();
    assert!(!format!("{err:?}").contains("opaque"));
    assert!(!err.to_string().contains("opaque"));
    match err {
        Error::Service {
            code,
            status,
            retryable,
            retry_after,
        } => {
            assert_eq!(code, "temporarily_unavailable");
            assert_eq!(status, 503);
            assert!(retryable);
            assert_eq!(retry_after, Some(Duration::from_secs(5)));
        }
        _ => panic!("unexpected error"),
    };
    assert!(fake
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|r| !r.headers.contains_key("cookie")));
}
#[test]
fn payment_required_accepts_mixed_case_headers() {
    let session = parse_payment_session(fixture("session"), None).unwrap();
    let checkout=parse_checkout(json!({"ippVersion":1,"type":"checkout","sessionUrl":"https://connect.invisipay.fi/session","checkoutUrl":create_checkout_url("https://connect.invisipay.fi/session","wallet-token","https://wallet.example.test/checkout").unwrap(),"expiresAt":session.expires_at()})).unwrap();
    let mut response = payment_required_response(&session, &checkout).unwrap();
    let ct = response.headers.remove("content-type").unwrap();
    let link = response.headers.remove("link").unwrap();
    response.headers.insert("Content-Type".into(), ct);
    response.headers.insert("Link".into(), link);
    IppClient::from_payment_required(response).unwrap();
}
#[test]
fn retry_after_is_bounded_before_constructing_a_timer() {
    assert_eq!(
        retry_after(Some("18446744073709551615")),
        Some(Duration::from_millis(2147483647))
    );
    assert_eq!(
        retry_after(Some("Fri, 01 Jan 9999 00:00:00 GMT")),
        Some(Duration::from_millis(2147483647))
    );
}
struct Never;
impl Transport for Never {
    fn send<'a>(&'a self, _: HttpRequest) -> TransportFuture<'a> {
        Box::pin(std::future::pending())
    }
}
#[tokio::test]
async fn request_timeout_and_poll_deadline_cover_stalled_reads() {
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        Arc::new(Never),
        Duration::from_millis(10),
    )
    .unwrap();
    assert!(matches!(
        client.read_session(None).await,
        Err(Error::Timeout)
    ));
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        Arc::new(Never),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(matches!(
        client
            .wait_for_result(Duration::from_millis(1), Duration::from_millis(10), None)
            .await,
        Err(Error::Timeout)
    ));
    let cancel = Cancellation::default();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        trigger.cancel();
    });
    assert!(matches!(
        client
            .wait_for_result(
                Duration::from_secs(10),
                Duration::from_secs(60),
                Some(&cancel)
            )
            .await,
        Err(Error::Cancelled)
    ));
}
#[test]
fn payment_required_link_parser_handles_whitespace_and_commas_in_urls() {
    let session = parse_payment_session(fixture("session"), None).unwrap();
    let checkout=parse_checkout(json!({"ippVersion":1,"type":"checkout","sessionUrl":"https://connect.invisipay.fi/session?a=one,two","checkoutUrl":create_checkout_url("https://connect.invisipay.fi/session?a=one,two","wallet-token","https://wallet.example.test/checkout").unwrap(),"expiresAt":session.expires_at()})).unwrap();
    let mut response = payment_required_response(&session, &checkout).unwrap();
    let links = response.headers["link"]
        .replace(">; rel=", "> \t;\t rel=")
        .replace(", <", ",<");
    response.headers.insert("link".into(), links);
    IppClient::from_payment_required(response).unwrap();
}
#[tokio::test]
async fn payment_required_recovery_retains_initial_terms_with_custom_transport() {
    let session = parse_payment_session(fixture("session"), None).unwrap();
    let checkout=parse_checkout(json!({"ippVersion":1,"type":"checkout","sessionUrl":"https://connect.invisipay.fi/session","checkoutUrl":create_checkout_url("https://connect.invisipay.fi/session","wallet-token","https://wallet.example.test/checkout").unwrap(),"expiresAt":session.expires_at()})).unwrap();
    let response = payment_required_response(&session, &checkout).unwrap();
    let fake = Arc::new(Fake::default());
    let mut changed = session.into_value();
    changed["options"][0]["amount"] = json!("2");
    fake.replies.lock().unwrap().push_back(reply(changed));
    let mut client =
        IppClient::from_payment_required_with_transport(response, fake, Duration::from_secs(1))
            .unwrap();
    assert!(matches!(
        client.read_session(None).await,
        Err(Error::InvalidMessage)
    ));
}
#[tokio::test]
async fn malformed_service_codes_and_unexpected_success_statuses_are_rejected() {
    for (status, code) in [(503, "Bad_Code"), (503, "1bad"), (201, "valid_code")] {
        let fake = Arc::new(Fake::default());
        let mut error = reply(
            json!({"ippVersion":1,"type":"error","error":{"code":code,"message":"service error","retryable":true}}),
        );
        error.status = status;
        fake.replies.lock().unwrap().push_back(error);
        let mut client = IppClient::with_transport(
            "https://connect.invisipay.fi/session",
            "opaque",
            fake,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(
            client.read_session(None).await,
            Err(Error::InvalidMessage)
        ));
    }
    assert_eq!(
        retry_after(Some("1000000000000000000000000")),
        Some(Duration::from_millis(2147483647))
    );
}
fn named_fixture(name: &str) -> Value {
    let corpus: Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap();
    serde_json::from_str(case["json"].as_str().unwrap()).unwrap()
}
#[tokio::test]
async fn credit_key_in_confirm_location_is_rejected_before_caching() {
    let fake = Arc::new(Fake::default());
    let request = named_fixture("credit-request");
    let secret = request["credit"]["creditSharedKey"].as_str().unwrap();
    fake.replies
        .lock()
        .unwrap()
        .push_back(reply(named_fixture("credit-open")));
    let mut response = reply(request.clone());
    response.status = 201;
    response.headers.insert(
        "Location".into(),
        format!("https://connect.invisipay.fi/request/{secret}"),
    );
    fake.replies.lock().unwrap().push_back(response);
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        fake.clone(),
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(matches!(
        client.confirm("base_usdc", "confirm-1", None).await,
        Err(Error::InvalidMessage)
    ));
    assert!(client.read_request(None).await.is_err());
    assert_eq!(fake.calls.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn credit_key_in_later_session_links_is_rejected_and_original_url_is_retained() {
    for field in ["confirm", "request"] {
        let fake = Arc::new(Fake::default());
        let mut session = named_fixture("credit-open");
        let request = named_fixture("credit-request");
        let secret = request["credit"]["creditSharedKey"].as_str().unwrap();
        fake.replies
            .lock()
            .unwrap()
            .push_back(reply(session.clone()));
        let mut response = reply(request.clone());
        response.status = 201;
        response.headers.insert(
            "Location".into(),
            "https://connect.invisipay.fi/original-request".into(),
        );
        fake.replies.lock().unwrap().push_back(response);
        let mut client = IppClient::with_transport(
            "https://connect.invisipay.fi/session",
            "opaque",
            fake.clone(),
            Duration::from_secs(1),
        )
        .unwrap();
        client
            .confirm("base_usdc", "confirm-1", None)
            .await
            .unwrap();
        session["status"] = json!("requires_action");
        session["activeRequestId"] = json!("req_test");
        session["links"]["request"] =
            json!({"href":"https://connect.invisipay.fi/original-request","method":"GET"});
        session["links"][field]["href"] =
            json!(format!("https://connect.invisipay.fi/private/{secret}"));
        fake.replies.lock().unwrap().push_back(reply(session));
        assert!(matches!(
            client.read_session(None).await,
            Err(Error::InvalidMessage)
        ));
        fake.replies.lock().unwrap().push_back(reply(request));
        client.read_request(None).await.unwrap();
        assert_eq!(
            fake.calls.lock().unwrap().last().unwrap().url,
            "https://connect.invisipay.fi/original-request"
        );
    }
}
#[tokio::test]
async fn cached_successful_receipt_must_match_a_request_read_after_recovery() {
    let fake = Arc::new(Fake::default());
    fake.replies
        .lock()
        .unwrap()
        .push_back(reply(named_fixture("succeeded")));
    let mut request = fixture("request");
    request["payment"]["protocolAddress"] = json!(format!("0x{}", "44".repeat(20)));
    fake.replies.lock().unwrap().push_back(reply(request));
    let mut client = IppClient::with_transport(
        "https://connect.invisipay.fi/session",
        "opaque",
        fake,
        Duration::from_secs(1),
    )
    .unwrap();
    client.read_session(None).await.unwrap();
    assert!(matches!(
        client.read_request(None).await,
        Err(Error::InvalidMessage)
    ));
}
