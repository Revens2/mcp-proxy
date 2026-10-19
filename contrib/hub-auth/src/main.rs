//! `hub-auth` -- OAuth 2.1 authorization server for an mcp-proxy hub.
//!
//! ChatGPT (or any MCP client) registers dynamically, obtains consent with the
//! operator's passphrase, and exchanges an authorization code with PKCE S256.
//! The issued tokens are opaque; `mcp-proxy` validates every request through
//! the private RFC 7662 `/introspect` endpoint served here, authenticated with a
//! dedicated client credential. The client token is never forwarded further.
//!
//! The authorization server itself is `mcp-auth` from mcp-framework-rs, the
//! same component the existing gateways use. This binary only adds:
//!
//! * RFC 7662 introspection bound to one issuer, audience, and scope set;
//! * PKCE S256 and RFC 8707 resource checks on `/authorize`;
//! * a redirect URI allowlist on dynamic client registration;
//! * a global attempt limit on the consent passphrase.
//!
//! Configuration (environment, secrets as files):
//!
//! | Variable | Meaning |
//! |---|---|
//! | `HUB_AUTH_ISSUER` | public HTTPS issuer, e.g. `https://host/oauth/hub-staging` |
//! | `HUB_AUTH_RESOURCE` | public HTTPS MCP URL, e.g. `https://host/hub-staging/mcp` |
//! | `HUB_AUTH_PORT` | loopback port (default 18983) |
//! | `HUB_AUTH_CONSENT_HASH_FILE` | file holding `pbkdf2:...` (see `hash-phrase`) |
//! | `HUB_AUTH_INTROSPECTION_CLIENT_ID` | client id used by mcp-proxy |
//! | `HUB_AUTH_INTROSPECTION_SECRET_FILE` | file holding that client's secret (>= 32 chars) |
//! | `HUB_AUTH_REDIRECT_PREFIXES` | comma-separated allowed redirect URI prefixes (default `https://chatgpt.com/`) |
//!
//! `hub-auth hash-phrase` reads a passphrase on stdin and prints its hash.
//!
//! Tokens live in memory: restarting `hub-auth` revokes every grant and the
//! client must reconnect. Restarting `mcp-proxy` does not.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine;
use mcp_auth::consent::tokens_equal;
use mcp_auth::oauth::{auth_router, MemoryStore, OAuthConfig, OAuthState};
use serde::Deserialize;
use tokio::sync::Mutex;

/// The only scope this hub issues: discovery and read-only invocation.
pub const HUB_SCOPE: &str = "hub:lecture";
const DEFAULT_PORT: u16 = 18983;
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Consent passphrase attempts accepted per window, for all clients together.
const CONSENT_ATTEMPTS: u32 = 10;
const CONSENT_WINDOW: Duration = Duration::from_secs(60);

/// Validated runtime settings.
#[derive(Clone)]
pub struct Settings {
    pub issuer: String,
    pub resource: String,
    pub consent_hash: String,
    pub introspection_client_id: String,
    pub introspection_secret: String,
    pub redirect_prefixes: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    settings: Arc<Settings>,
    store: Arc<MemoryStore>,
    consent: Arc<Mutex<(Instant, u32)>>,
}

fn https_url(value: &str, name: &str) -> Result<String, String> {
    let parsed = url::Url::parse(value).map_err(|_| format!("{name} must be an absolute URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
    {
        return Err(format!(
            "{name} must be an HTTPS URL without query, fragment, or user info"
        ));
    }
    Ok(value.trim_end_matches('/').to_string())
}

impl Settings {
    /// Validate settings; every failure is fatal at startup.
    pub fn new(
        issuer: &str,
        resource: &str,
        consent_hash: &str,
        introspection_client_id: &str,
        introspection_secret: &str,
        redirect_prefixes: &str,
    ) -> Result<Self, String> {
        let issuer = https_url(issuer, "HUB_AUTH_ISSUER")?;
        let resource = https_url(resource, "HUB_AUTH_RESOURCE")?;
        if !consent_hash.starts_with("pbkdf2:") {
            return Err("consent hash must be a pbkdf2:... value (use hash-phrase)".into());
        }
        if introspection_client_id.trim().is_empty() {
            return Err("HUB_AUTH_INTROSPECTION_CLIENT_ID is required".into());
        }
        if introspection_secret.len() < 32 {
            return Err("introspection secret must be at least 32 characters".into());
        }
        let redirect_prefixes: Vec<String> = redirect_prefixes
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        if redirect_prefixes.is_empty()
            || redirect_prefixes
                .iter()
                .any(|p| !p.starts_with("https://") || p.matches('/').count() < 3)
        {
            return Err(
                "HUB_AUTH_REDIRECT_PREFIXES must list https://host/ prefixes ending at a path"
                    .into(),
            );
        }
        Ok(Self {
            issuer,
            resource,
            consent_hash: consent_hash.to_string(),
            introspection_client_id: introspection_client_id.to_string(),
            introspection_secret: introspection_secret.to_string(),
            redirect_prefixes,
        })
    }
}

/// Build the HTTP application (also used by tests).
pub fn app(settings: Settings) -> Router {
    let settings = Arc::new(settings);
    let store = Arc::new(MemoryStore::default());
    let oauth = OAuthState {
        config: Arc::new(OAuthConfig {
            issuer: settings.issuer.clone(),
            resource_url: settings.resource.clone(),
            resource_name: "MCP hub (read-only)".to_string(),
            default_scope: HUB_SCOPE.to_string(),
            valid_scopes: vec![HUB_SCOPE.to_string()],
            extra_submit_scopes: Vec::new(),
            consent_hash: settings.consent_hash.clone(),
            static_client_id: "hub-auth".to_string(),
        }),
        store: Arc::clone(&store),
    };
    let state = AppState {
        settings: Arc::clone(&settings),
        store,
        consent: Arc::new(Mutex::new((Instant::now(), 0))),
    };

    // RFC 8414 path-aware location of the metadata for an issuer with a path.
    let issuer_path = url::Url::parse(&settings.issuer)
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();
    let metadata = mcp_auth::oauth::authorization_server_metadata(&oauth.config);
    let mut router = Router::new()
        .route("/introspect", post(introspect))
        .with_state(state.clone())
        .merge(auth_router(oauth))
        .route("/healthz", get(|| async { "ok" }));
    if !issuer_path.is_empty() {
        let path = format!("/.well-known/oauth-authorization-server{issuer_path}");
        router = router.route(
            &path,
            get(move || {
                let metadata = metadata.clone();
                async move { Json(metadata) }
            }),
        );
    }
    let router = router.layer(middleware::from_fn_with_state(state, guard));
    mcp_http::hardening::harden(router, MAX_BODY_BYTES)
}

fn reject(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

fn query_pairs(request: &Request) -> Vec<(String, String)> {
    request
        .uri()
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

/// Hardening applied in front of the `mcp-auth` routes.
async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    match (request.method().as_str(), request.uri().path()) {
        ("GET", "/authorize") => {
            let pairs = query_pairs(&request);
            let value = |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.as_str())
            };
            if value("response_type") != Some("code") {
                return reject(StatusCode::BAD_REQUEST, "response_type=code required");
            }
            if value("code_challenge").is_none_or(str::is_empty)
                || value("code_challenge_method") != Some("S256")
            {
                return reject(StatusCode::BAD_REQUEST, "PKCE S256 required");
            }
            if value("resource").is_some_and(|r| r.trim_end_matches('/') != state.settings.resource)
            {
                return reject(StatusCode::BAD_REQUEST, "unknown resource");
            }
            if value("scope").is_some_and(|s| s.split_whitespace().any(|s| s != HUB_SCOPE)) {
                return reject(StatusCode::BAD_REQUEST, "unknown scope");
            }
            next.run(request).await
        }
        ("POST", "/register") => {
            let (parts, body) = request.into_parts();
            let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
                return reject(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
            };
            let uris = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("redirect_uris").cloned())
                .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                .unwrap_or_default();
            if uris.is_empty() || !uris.iter().all(|u| redirect_allowed(&state.settings, u)) {
                return reject(StatusCode::BAD_REQUEST, "redirect_uri not allowed");
            }
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        ("POST", "/consentement") => {
            {
                let mut window = state.consent.lock().await;
                if window.0.elapsed() >= CONSENT_WINDOW {
                    *window = (Instant::now(), 0);
                }
                if window.1 >= CONSENT_ATTEMPTS {
                    tracing::warn!("consent attempt limit reached");
                    return reject(StatusCode::TOO_MANY_REQUESTS, "too many attempts");
                }
                window.1 += 1;
            }
            let response = next.run(request).await;
            tracing::info!(status = response.status().as_u16(), "consent submitted");
            response
        }
        _ => next.run(request).await,
    }
}

/// A redirect URI is allowed when it parses to the same HTTPS origin as a
/// configured prefix (exact host, default port, no user info or fragment) and
/// its path starts with the prefix path.
fn redirect_allowed(settings: &Settings, uri: &str) -> bool {
    let Ok(candidate) = url::Url::parse(uri) else {
        return false;
    };
    if candidate.scheme() != "https"
        || candidate.port().is_some()
        || !candidate.username().is_empty()
        || candidate.password().is_some()
        || candidate.fragment().is_some()
    {
        return false;
    }
    settings.redirect_prefixes.iter().any(|prefix| {
        url::Url::parse(prefix).is_ok_and(|allowed| {
            allowed.host_str() == candidate.host_str()
                && allowed.port().is_none()
                && candidate.path().starts_with(allowed.path())
        })
    })
}

#[derive(Deserialize)]
struct IntrospectForm {
    token: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Client credentials from HTTP Basic or the form body (RFC 7662 section 2.1).
fn client_credentials(headers: &HeaderMap, form: &IntrospectForm) -> Option<(String, String)> {
    if let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
    {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        // Compared verbatim: mcp-proxy sends the configured values unencoded,
        // and generated credentials use the URL-safe alphabet.
        let (id, secret) = decoded.split_once(':')?;
        return Some((id.to_string(), secret.to_string()));
    }
    Some((form.client_id.clone()?, form.client_secret.clone()?))
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Response {
    let authenticated = client_credentials(&headers, &form).is_some_and(|(id, secret)| {
        // Evaluate both comparisons; neither short-circuits on content.
        let id_ok = tokens_equal(&id, &state.settings.introspection_client_id);
        let secret_ok = tokens_equal(&secret, &state.settings.introspection_secret);
        id_ok & secret_ok
    });
    if !authenticated {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"introspection\"")],
            "client authentication required",
        )
            .into_response();
    }
    let inactive = || Json(serde_json::json!({ "active": false })).into_response();
    let Some(entry) = state.store.get_access(&form.token).await else {
        return inactive();
    };
    let scopes: HashSet<&str> = entry
        .scopes
        .iter()
        .map(String::as_str)
        .filter(|s| *s == HUB_SCOPE)
        .collect();
    if scopes.is_empty() {
        return inactive();
    }
    Json(serde_json::json!({
        "active": true,
        "token_type": "Bearer",
        "client_id": entry.client_id,
        "sub": entry.client_id,
        "scope": HUB_SCOPE,
        "iss": state.settings.issuer,
        "aud": state.settings.resource,
        "exp": entry.expires_at,
        "iat": now_s(),
    }))
    .into_response()
}

fn read_secret_file(var: &str) -> Result<String, String> {
    let path = std::env::var(var).map_err(|_| format!("{var} is required"))?;
    let value = std::fs::read_to_string(&path).map_err(|_| format!("cannot read {var}"))?;
    Ok(value.trim().to_string())
}

fn settings_from_env() -> Result<Settings, String> {
    let env = |name: &str| std::env::var(name).map_err(|_| format!("{name} is required"));
    Settings::new(
        &env("HUB_AUTH_ISSUER")?,
        &env("HUB_AUTH_RESOURCE")?,
        &read_secret_file("HUB_AUTH_CONSENT_HASH_FILE")?,
        &env("HUB_AUTH_INTROSPECTION_CLIENT_ID")?,
        &read_secret_file("HUB_AUTH_INTROSPECTION_SECRET_FILE")?,
        &std::env::var("HUB_AUTH_REDIRECT_PREFIXES")
            .unwrap_or_else(|_| "https://chatgpt.com/".to_string()),
    )
}

async fn hash_phrase_command() -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    let mut phrase = String::new();
    tokio::io::stdin()
        .read_to_string(&mut phrase)
        .await
        .map_err(|_| "cannot read stdin".to_string())?;
    let phrase = phrase.trim_end_matches(['\r', '\n']);
    if phrase.chars().count() < 20 {
        return Err("passphrase must be at least 20 characters (use several random words)".into());
    }
    println!("{}", mcp_auth::consent::hash_phrase(phrase));
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    if std::env::args().nth(1).as_deref() == Some("hash-phrase") {
        return hash_phrase_command().await;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();
    let settings = settings_from_env()?;
    let port = match std::env::var("HUB_AUTH_PORT") {
        Ok(p) => p.parse::<u16>().map_err(|_| "invalid HUB_AUTH_PORT")?,
        Err(_) => DEFAULT_PORT,
    };
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("bind failed: {e}"))?;
    tracing::info!(port, "hub-auth listening on loopback");
    axum::serve(listener, app(settings))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server error: {e}"))
}

#[cfg(test)]
mod tests;
