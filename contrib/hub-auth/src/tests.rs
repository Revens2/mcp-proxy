use super::*;
use axum::http::Request as HttpRequest;
use http_body_util::BodyExt;
use tower::ServiceExt;

const ISSUER: &str = "https://hub.example/oauth/hub-staging";
const RESOURCE: &str = "https://hub.example/hub-staging/mcp";
const CLIENT: &str = "mcp-proxy-hub";
const SECRET: &str = "synthetic-introspection-secret-0123456789";
const PHRASE: &str = "synthetic consent phrase";
const REDIRECT: &str = "https://chatgpt.com/connector_platform_oauth_redirect";
// PKCE pair from RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn settings() -> Settings {
    Settings::new(
        ISSUER,
        RESOURCE,
        &mcp_auth::consent::hash_phrase_with_salt(PHRASE, b"0123456789abcdef", 1000),
        CLIENT,
        SECRET,
        "https://chatgpt.com/",
    )
    .unwrap()
}

async fn send(app: &Router, request: HttpRequest<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn form(uri: &str, body: String) -> HttpRequest<Body> {
    HttpRequest::post(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

fn basic(id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

async fn introspect_as(app: &Router, auth: &str, token: &str) -> (StatusCode, serde_json::Value) {
    let mut request = form("/introspect", format!("token={token}"));
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, auth.parse().unwrap());
    let (status, _, body) = send(app, request).await;
    (status, serde_json::from_str(&body).unwrap_or_default())
}

async fn register(app: &Router, redirect: &str) -> (StatusCode, String) {
    let request = HttpRequest::post("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "redirect_uris": [redirect], "scope": HUB_SCOPE }).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(app, request).await;
    (status, body)
}

fn authorize_uri(client_id: &str, extra: &str) -> String {
    format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope={HUB_SCOPE}&state=xyz{extra}",
        url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect::<String>()
    )
}

/// Runs the full authorization-code flow and returns the token response body.
async fn obtain_token_response(app: &Router) -> String {
    let (status, body) = register(app, REDIRECT).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let client_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let pkce = format!(
        "&code_challenge={CHALLENGE}&code_challenge_method=S256&resource={}",
        url::form_urlencoded::byte_serialize(RESOURCE.as_bytes()).collect::<String>()
    );
    let (status, headers, _) = send(
        app,
        HttpRequest::get(authorize_uri(&client_id, &pkce))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(status.is_redirection(), "{status}");
    let location = headers[header::LOCATION].to_str().unwrap();
    let demande = location.split("demande=").nth(1).unwrap().to_string();

    let (status, headers, _) = send(
        app,
        form(
            "/consentement",
            format!(
                "demande={demande}&phrase={}",
                url::form_urlencoded::byte_serialize(PHRASE.as_bytes()).collect::<String>()
            ),
        ),
    )
    .await;
    assert!(status.is_redirection(), "{status}");
    let location = headers[header::LOCATION].to_str().unwrap();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .to_string();

    let (status, _, body) = send(
        app,
        form(
            "/token",
            format!(
                "grant_type=authorization_code&code={code}&client_id={client_id}&redirect_uri={}&code_verifier={VERIFIER}&resource={}",
                url::form_urlencoded::byte_serialize(REDIRECT.as_bytes()).collect::<String>(),
                url::form_urlencoded::byte_serialize(RESOURCE.as_bytes()).collect::<String>()
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn obtain_token(app: &Router) -> String {
    let body = obtain_token_response(app).await;
    serde_json::from_str::<serde_json::Value>(&body).unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn full_flow_issues_token_bound_to_issuer_audience_and_scope() {
    let app = app(settings());
    let token = obtain_token(&app).await;

    let (status, claims) = introspect_as(&app, &basic(CLIENT, SECRET), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(claims["active"], true);
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], RESOURCE);
    assert_eq!(claims["scope"], HUB_SCOPE);
    assert!(claims["exp"].as_u64().unwrap() > now_s());

    let (_, claims) = introspect_as(&app, &basic(CLIENT, SECRET), "not-a-token").await;
    assert_eq!(claims, serde_json::json!({ "active": false }));
}

#[tokio::test]
async fn refresh_tokens_are_never_accepted_as_access_tokens() {
    let app = app(settings());
    let body = obtain_token_response(&app).await;
    let refresh = serde_json::from_str::<serde_json::Value>(&body).unwrap()["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, claims) = introspect_as(&app, &basic(CLIENT, SECRET), &refresh).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(claims, serde_json::json!({ "active": false }));
}

#[tokio::test]
async fn introspection_requires_the_dedicated_client_credential() {
    let app = app(settings());
    let token = obtain_token(&app).await;

    let (status, _) = introspect_as(&app, &basic(CLIENT, "wrong-secret"), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = introspect_as(&app, &basic("other", SECRET), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // The access token itself is not a credential for introspection.
    let (status, _) = introspect_as(&app, &format!("Bearer {token}"), &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, _) = send(&app, form("/introspect", format!("token={token}"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, body) = send(
        &app,
        form(
            "/introspect",
            format!("token={token}&client_id={CLIENT}&client_secret={SECRET}"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"active\":true"));
}

#[tokio::test]
async fn authorize_requires_pkce_s256_known_resource_and_scope() {
    let app = app(settings());
    let (_, body) = register(&app, REDIRECT).await;
    let client_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    for extra in [
        String::new(),
        format!("&code_challenge={CHALLENGE}"),
        format!("&code_challenge={CHALLENGE}&code_challenge_method=plain"),
        format!(
            "&code_challenge={CHALLENGE}&code_challenge_method=S256&resource=https%3A%2F%2Fother.example%2Fmcp"
        ),
    ] {
        let (status, _, _) = send(
            &app,
            HttpRequest::get(authorize_uri(&client_id, &extra))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra}");
    }
    let wide_scope = authorize_uri(&client_id, "")
        .replace(&format!("scope={HUB_SCOPE}"), "scope=hub%3Aecriture")
        + &format!("&code_challenge={CHALLENGE}&code_challenge_method=S256");
    let (status, _, _) = send(
        &app,
        HttpRequest::get(wide_scope).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn registration_rejects_unlisted_redirect_uris() {
    let app = app(settings());
    for redirect in [
        "https://evil.example/callback",
        "https://chatgpt.com.evil.example/cb",
        "http://chatgpt.com/cb",
        "https://chatgpt.com:8443/cb",
        "https://user@chatgpt.com/cb",
        "https://chatgpt.com/cb#fragment",
        "not a url",
    ] {
        let (status, _) = register(&app, redirect).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{redirect}");
    }
}

#[tokio::test]
async fn consent_attempts_are_limited() {
    let app = app(settings());
    for _ in 0..CONSENT_ATTEMPTS {
        let (status, _, _) = send(
            &app,
            form("/consentement", "demande=x&phrase=wrong".to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, _, _) = send(
        &app,
        form("/consentement", "demande=x&phrase=wrong".to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn metadata_is_served_at_the_rfc8414_path() {
    let app = app(settings());
    let (status, _, body) = send(
        &app,
        HttpRequest::get("/.well-known/oauth-authorization-server/oauth/hub-staging")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(metadata["code_challenge_methods_supported"][0], "S256");
    // The introspection endpoint is private and never advertised.
    assert!(metadata.get("introspection_endpoint").is_none());
}

#[test]
fn settings_reject_weak_or_insecure_values() {
    let hash = "pbkdf2:1:00:00";
    assert!(Settings::new(
        "http://h/oauth",
        RESOURCE,
        hash,
        CLIENT,
        SECRET,
        "https://chatgpt.com/"
    )
    .is_err());
    assert!(Settings::new(
        ISSUER,
        RESOURCE,
        "plain",
        CLIENT,
        SECRET,
        "https://chatgpt.com/"
    )
    .is_err());
    assert!(Settings::new(
        ISSUER,
        RESOURCE,
        hash,
        CLIENT,
        "short",
        "https://chatgpt.com/"
    )
    .is_err());
    assert!(Settings::new(
        ISSUER,
        RESOURCE,
        hash,
        CLIENT,
        SECRET,
        "https://chatgpt.com"
    )
    .is_err());
    assert!(Settings::new(ISSUER, RESOURCE, hash, "", SECRET, "https://chatgpt.com/").is_err());
}
