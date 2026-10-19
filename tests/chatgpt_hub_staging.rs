//! Staging contract for the ChatGPT web hub: search exposure, schema lookup,
//! fail-closed read-only allowlist, no downstream token passthrough, and the
//! loopback/auth boundary.
#![cfg(feature = "discovery")]

use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use reqwest::Client;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tower_mcp::{CallToolResult, HttpTransport, McpRouter, ToolBuilder};

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: axum::Router) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Server { url, task }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReadNoteInput {
    id: String,
}

struct Fixture {
    server: Server,
    _backend: Server,
    _second: Option<Server>,
    calls: Arc<Mutex<Vec<String>>>,
    headers: Arc<Mutex<Vec<HeaderMap>>>,
}

/// A second gateway with one read and one destructive tool.
async fn second_backend(calls: Arc<Mutex<Vec<String>>>) -> Server {
    let mut router = McpRouter::new();
    for name in ["get_file_contents", "delete_file"] {
        let calls = calls.clone();
        router = router.tool(
            ToolBuilder::new(name)
                .description(format!("{name} repository operation"))
                .handler(move |arguments: Value| {
                    calls.lock().unwrap().push(name.to_string());
                    async move { Ok(CallToolResult::json(arguments)) }
                })
                .build(),
        );
    }
    serve(HttpTransport::new(router).into_router()).await
}

impl Fixture {
    async fn new() -> Self {
        Self::build(false).await
    }

    /// Hub mode: `security.default_deny`, two allowlisted gateways, and one
    /// configured gateway that is down at startup.
    async fn hub() -> Self {
        Self::build(true).await
    }

    async fn build(hub: bool) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let headers = Arc::new(Mutex::new(Vec::new()));
        let mut backend = McpRouter::new();
        for name in ["read_note", "list_notes", "write_note", "execute"] {
            let calls = calls.clone();
            backend = backend.tool(
                ToolBuilder::new(name)
                    .description(format!("{name} staging operation"))
                    .handler(move |arguments: Value| {
                        calls.lock().unwrap().push(name.to_string());
                        async move { Ok(CallToolResult::json(arguments)) }
                    })
                    .build(),
            );
        }
        // A typed read tool proves schema retrieval is not just a name lookup.
        let calls_for_read = calls.clone();
        backend = backend.tool(
            ToolBuilder::new("read_typed_note")
                .description("Read a note by id")
                .handler(move |input: ReadNoteInput| {
                    calls_for_read
                        .lock()
                        .unwrap()
                        .push("read_typed_note".into());
                    async move { Ok(CallToolResult::text(input.id)) }
                })
                .build(),
        );
        let captured = headers.clone();
        let app = HttpTransport::new(backend)
            .into_router()
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().unwrap().push(req.headers().clone());
                        next.run(req).await
                    }
                },
            ));
        let backend = serve(app).await;
        let second = if hub {
            Some(second_backend(calls.clone()).await)
        } else {
            None
        };
        // Port 9 (discard) is closed on test hosts: a gateway down at startup.
        let hub_config = second
            .as_ref()
            .map(|second| {
                format!(
                    r#"
[[backends]]
name = "repo"
transport = "http"
url = "{}/"
read_only_targets = ["get_file_contents"]
[[backends]]
name = "offline"
transport = "http"
url = "http://127.0.0.1:9/mcp"
read_only_targets = ["read_note"]
"#,
                    second.url
                )
            })
            .unwrap_or_default();
        let security = if hub { "default_deny = true\n" } else { "" };
        let config = mcp_proxy::ProxyConfig::parse(&format!(
            r#"
[proxy]
name = "chatgpt-hub-staging-test"
separator = "_"
hot_reload = true
tool_discovery = true
tool_exposure = "search"
[proxy.listen]
host = "127.0.0.1"
[security]
require_auth_outside_loopback = true
admin_token = "manager"
{security}[auth]
type = "bearer"
tokens = ["downstream-token"]
[[backends]]
name = "staging"
transport = "http"
url = "{backend_url}/"
forward_auth = false
read_only_targets = ["read_note", "list_notes", "read_typed_note"]
{hub_config}"#,
            backend_url = backend.url
        ))
        .unwrap();
        assert!(config.proxy.hot_reload);
        assert!(config.security.require_auth_outside_loopback);
        assert_eq!(config.proxy.separator, "_");
        assert!(!config.backends[0].forward_auth);
        let proxy = mcp_proxy::Proxy::from_config(config).await.unwrap();
        Self {
            server: serve(proxy.into_router().0).await,
            _backend: backend,
            _second: second,
            calls,
            headers,
        }
    }
}

struct Session {
    client: Client,
    url: String,
    token: String,
    id: Option<String>,
}

impl Session {
    async fn new(url: &str, token: &str) -> Self {
        let mut session = Self {
            client: Client::new(),
            url: format!("{url}/"),
            token: token.into(),
            id: None,
        };
        let response = session.request("initialize", json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"chatgpt-hub-test","version":"1"}})).await;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        session.id = Some(
            response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .into(),
        );
        success(&payload(response).await);
        assert!(
            session
                .request("notifications/initialized", json!({}))
                .await
                .status()
                .is_success()
        );
        session
    }

    async fn request(&self, method: &str, params: Value) -> reqwest::Response {
        let mut request = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-11-25");
        if let Some(id) = &self.id {
            request = request.header("mcp-session-id", id);
        }
        let mut rpc = json!({"jsonrpc":"2.0","method":method,"params":params});
        if !method.starts_with("notifications/") {
            rpc["id"] = json!(42);
        }
        request.json(&rpc).send().await.unwrap()
    }

    async fn call(&self, name: &str, arguments: Value) -> Value {
        payload(
            self.request("tools/call", json!({"name":name,"arguments":arguments}))
                .await,
        )
        .await
    }

    async fn list_tools(&self) -> Value {
        payload(self.request("tools/list", json!({})).await).await
    }

    async fn wrapped(&self, separator: &str, name: &str, arguments: Value) -> Value {
        self.call(
            &format!("proxy{separator}call_tool"),
            json!({"name":name,"arguments":arguments}),
        )
        .await
    }
}

async fn payload(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap();
    let json = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&text);
    serde_json::from_str(json).unwrap()
}

fn success(value: &Value) {
    assert!(value.get("error").is_none(), "{value}");
    assert_ne!(value["result"]["isError"], true, "{value}");
}

fn denied(value: &Value) {
    assert!(
        value.get("error").is_some() || value["result"]["isError"] == true,
        "{value}"
    );
}

fn search_ids(value: &Value) -> Vec<String> {
    let results: Value = serde_json::from_str(&text_result(value)).unwrap();
    results
        .as_array()
        .unwrap_or_else(|| panic!("{results}"))
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_string))
        .collect()
}

fn text_result(value: &Value) -> String {
    value["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("missing text result: {value}"))
        .to_string()
}

#[tokio::test]
async fn gateway_search_schema_read_route_and_fail_closed_denials() {
    let fixture = Fixture::new().await;
    let session = Session::new(&fixture.server.url, "downstream-token").await;

    let listed = session.list_tools().await;
    success(&listed);
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"proxy_search_tools"), "{names:?}");
    assert!(names.contains(&"proxy_get_tool"), "{names:?}");
    assert!(names.contains(&"proxy_call_tool"), "{names:?}");
    assert!(!names.contains(&"staging_read_note"), "{names:?}");
    assert!(!names.contains(&"staging_write_note"), "{names:?}");

    // Search and schema lookup never reveal a tool the allowlist rejects.
    for query in ["write note", "execute", "staging"] {
        let found = session
            .call("proxy_search_tools", json!({"query": query}))
            .await;
        success(&found);
        let ids = search_ids(&found);
        assert!(
            !ids.iter()
                .any(|id| id == "staging:write_note" || id == "staging:execute"),
            "{query}: {ids:?}"
        );
    }
    denied(
        &session
            .call("proxy_get_tool", json!({"tool_id":"staging:write_note"}))
            .await,
    );

    let found = session
        .call("proxy_search_tools", json!({"query":"read note"}))
        .await;
    success(&found);
    let results: Value = serde_json::from_str(&text_result(&found)).unwrap();
    let result_rows = results.as_array().unwrap_or_else(|| panic!("{results}"));
    let read_id = result_rows
        .iter()
        .find_map(|row| row["id"].as_str().filter(|id| *id == "staging:read_note"))
        .expect("read_note must be discoverable");
    assert_eq!(read_id, "staging:read_note");

    let schema = session
        .call(
            "proxy_get_tool",
            json!({"tool_id":"staging:read_typed_note"}),
        )
        .await;
    success(&schema);
    let schema: Value = serde_json::from_str(&text_result(&schema)).unwrap();
    assert_eq!(schema["name"], "staging_read_typed_note");
    assert_eq!(schema["input_schema"]["properties"]["id"]["type"], "string");

    let read = session
        .wrapped("_", "staging_read_note", json!({"id":"note-1"}))
        .await;
    success(&read);
    assert_eq!(fixture.calls.lock().unwrap().as_slice(), ["read_note"]);

    for target in ["staging_write_note", "staging_execute"] {
        denied(
            &session
                .wrapped("_", target, json!({"value":"blocked"}))
                .await,
        );
        denied(&session.call(target, json!({"value":"blocked"})).await);
    }
    assert_eq!(
        fixture.calls.lock().unwrap().as_slice(),
        ["read_note"],
        "denied targets must never reach the backend"
    );

    for headers in fixture.headers.lock().unwrap().iter() {
        assert!(
            !headers.contains_key("authorization"),
            "downstream token was forwarded to the backend"
        );
    }
}

#[tokio::test]
async fn unauthenticated_or_unknown_token_is_rejected() {
    let fixture = Fixture::new().await;
    let client = Client::new();
    for token in [None, Some("wrong-token")] {
        let mut request = client
            .post(format!("{}/", fixture.server.url))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn hub_discovers_multiple_gateways_and_fails_closed() {
    let fixture = Fixture::hub().await;
    let session = Session::new(&fixture.server.url, "downstream-token").await;

    // One stable public surface: meta-tools only, whatever the backends.
    let listed = session.list_tools().await;
    success(&listed);
    let mut names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "proxy_backend_status",
            "proxy_call_tool",
            "proxy_get_tool",
            "proxy_search_tools"
        ]
    );

    // Discovery spans both live gateways; denied tools stay invisible.
    let found = session
        .call("proxy_search_tools", json!({"query":"file contents note"}))
        .await;
    success(&found);
    let ids = search_ids(&found);
    assert!(
        ids.iter().any(|id| id == "repo:get_file_contents"),
        "{ids:?}"
    );
    assert!(ids.iter().any(|id| id == "staging:read_note"), "{ids:?}");
    for query in ["delete file", "write note", "execute"] {
        let found = session
            .call("proxy_search_tools", json!({"query": query}))
            .await;
        let ids = search_ids(&found);
        assert!(
            !ids.iter().any(|id| matches!(
                id.as_str(),
                "repo:delete_file" | "staging:write_note" | "staging:execute"
            )),
            "{query}: {ids:?}"
        );
    }

    // A gateway down at startup does not take the hub down.
    success(
        &session
            .wrapped("_", "repo_get_file_contents", json!({"path":"README.md"}))
            .await,
    );
    success(
        &session
            .wrapped("_", "staging_read_note", json!({"id":"n"}))
            .await,
    );
    denied(
        &session
            .wrapped("_", "offline_read_note", json!({"id":"n"}))
            .await,
    );

    // Writes, unknown namespaces, and meta-tool recursion are refused.
    for target in [
        "repo_delete_file",
        "staging_write_note",
        "staging_execute",
        "unknown_tool",
        "proxy_backend_status",
        "proxy_add_backend",
    ] {
        denied(&session.wrapped("_", target, json!({})).await);
    }
    for target in ["repo_delete_file", "staging_write_note", "unknown_tool"] {
        denied(&session.call(target, json!({})).await);
    }
    assert_eq!(
        fixture.calls.lock().unwrap().as_slice(),
        ["get_file_contents", "read_note"],
        "denied targets must never reach a backend"
    );

    // Non-tool capabilities are closed for allowlisted gateways.
    denied(
        &payload(
            session
                .request("resources/read", json!({"uri":"staging_note://1"}))
                .await,
        )
        .await,
    );
    denied(
        &payload(
            session
                .request(
                    "prompts/get",
                    json!({"name":"staging_summary","arguments":{}}),
                )
                .await,
        )
        .await,
    );
    denied(
        &payload(
            session
                .request(
                    "completion/complete",
                    json!({"ref":{"type":"ref/prompt","name":"staging_summary"},
                           "argument":{"name":"a","value":"b"}}),
                )
                .await,
        )
        .await,
    );

    // Limited diagnostic: names and health, nothing about endpoints.
    let status = session.call("proxy_backend_status", json!({})).await;
    success(&status);
    let text = text_result(&status);
    assert!(text.contains("\"healthy\""), "{text}");
    assert!(
        !text.contains("127.0.0.1") && !text.contains("http"),
        "{text}"
    );

    for headers in fixture.headers.lock().unwrap().iter() {
        assert!(!headers.contains_key("authorization"));
    }
}

#[tokio::test]
async fn hub_keeps_runtime_added_backends_dark() {
    let fixture = Fixture::hub().await;
    let extra_calls = Arc::new(Mutex::new(Vec::new()));
    let extra = second_backend(extra_calls.clone()).await;

    // The management plane can attach a backend at runtime...
    let admin = Session::new(&fixture.server.url, "manager").await;
    success(
        &admin
            .call(
                "proxy_add_backend",
                json!({"name":"extra","url":format!("{}/", extra.url)}),
            )
            .await,
    );

    // ...but without an allowlist it is neither listed, searchable, nor callable.
    let session = Session::new(&fixture.server.url, "downstream-token").await;
    let found = session
        .call("proxy_search_tools", json!({"query":"file contents"}))
        .await;
    assert!(!search_ids(&found).iter().any(|id| id.starts_with("extra:")));
    denied(&session.call("extra_get_file_contents", json!({})).await);
    denied(
        &session
            .wrapped("_", "extra_get_file_contents", json!({}))
            .await,
    );
    assert!(extra_calls.lock().unwrap().is_empty());
}

#[test]
fn shipped_hub_configs_fail_closed_without_secrets() {
    for path in [
        "examples/chatgpt-hub-staging.toml",
        "deploy/hub-staging/mcp-hub-staging.toml",
    ] {
        let text = std::fs::read_to_string(path).unwrap();
        let config = mcp_proxy::ProxyConfig::load(std::path::Path::new(path))
            .unwrap_or_else(|e| panic!("{path}: {e:#}"));
        assert!(config.security.default_deny, "{path}");
        assert!(config.security.require_auth_outside_loopback, "{path}");
        assert_eq!(config.proxy.listen.host, "127.0.0.1", "{path}");
        assert!(config.auth.is_some(), "{path}");
        for backend in &config.backends {
            assert!(!backend.forward_auth, "{path}: {}", backend.name);
            assert!(!backend.read_only_targets.is_empty(), "{path}");
        }
        // Credentials are environment references only.
        for line in text.lines().filter(|l| {
            let key = l.split('=').next().unwrap_or("").trim();
            matches!(
                key,
                "client_secret" | "bearer_token" | "admin_token" | "tokens"
            )
        }) {
            assert!(line.contains("${"), "{path}: literal secret in {line:?}");
        }
    }
    let deployed = mcp_proxy::ProxyConfig::load(std::path::Path::new(
        "deploy/hub-staging/mcp-hub-staging.toml",
    ))
    .unwrap();
    // Management is off: no static credential is accepted on the public endpoint.
    assert!(deployed.security.admin_token.is_none());
}
