//! Resolve search-mode calls without crossing the backend transport boundary.
//!
//! Rewriting the original request preserves identity, cancellation, continuation,
//! task, and progress context. The inner service is the ordinary invocation
//! stack, excluding this resolver, so wrappers cannot recursively invoke it.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tower::Service;
use tower_mcp::{McpRequest, RouterRequest, RouterResponse};
use tower_mcp_types::JsonRpcError;

#[derive(Clone)]
pub(crate) struct SearchInvocation<S> {
    inner: S,
    prefix: String,
    separator: String,
    wrapper: String,
    write_wrapper: String,
    writes: Option<crate::filter::WritePolicy>,
}

impl<S> SearchInvocation<S> {
    pub(crate) fn new(inner: S, separator: &str) -> Self {
        let prefix = format!("proxy{separator}");
        let wrapper = format!("{prefix}call_tool");
        let write_wrapper = format!("{prefix}call_write_tool");
        Self {
            inner,
            prefix,
            separator: separator.to_string(),
            wrapper,
            write_wrapper,
            writes: None,
        }
    }

    /// Route write targets only through `call_write_tool`, and reads only
    /// through `call_tool`.
    pub(crate) fn with_writes(mut self, writes: crate::filter::WritePolicy) -> Self {
        self.writes = Some(writes);
        self
    }
}

fn refuse(
    id: tower_mcp::RequestId,
    message: String,
) -> Pin<Box<dyn Future<Output = Result<RouterResponse, Infallible>> + Send>> {
    Box::pin(async move {
        Ok(RouterResponse {
            id,
            inner: Err(JsonRpcError::invalid_params(message)),
        })
    })
}

fn normalize_target_name(name: &str, separator: &str) -> String {
    let trimmed = name.trim();
    if separator.is_empty() {
        return trimmed.to_owned();
    }
    match trimmed.find(':') {
        Some(colon) if trimmed.find(separator).is_none_or(|sep| colon < sep) => {
            trimmed.replace(':', separator)
        }
        _ => trimmed.to_owned(),
    }
}

impl<S> Service<RouterRequest> for SearchInvocation<S>
where
    S: Service<RouterRequest, Response = RouterResponse, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = RouterResponse;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<RouterResponse, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: RouterRequest) -> Self::Future {
        if let McpRequest::CallTool(params) = &mut req.inner {
            let is_write_wrapper = self.writes.is_some() && params.name == self.write_wrapper;
            if params.name == self.wrapper || is_write_wrapper {
                let wrapper = params.name.clone();
                let input = serde_json::from_value::<crate::admin_tools::CallToolInput>(
                    params.arguments.clone(),
                );
                let Ok(input) = input else {
                    return refuse(
                        req.id,
                        format!("{wrapper} requires an ordinary target name and object arguments"),
                    );
                };
                let target = normalize_target_name(&input.name, &self.separator);
                if target.is_empty() || target.starts_with(&self.prefix) {
                    return refuse(
                        req.id,
                        format!("{wrapper} requires an ordinary target name and object arguments"),
                    );
                }
                if let Some(writes) = &self.writes {
                    let is_write = writes.is_write(&target);
                    if is_write && !is_write_wrapper {
                        return refuse(
                            req.id,
                            format!(
                                "{target} changes state: call it with {} instead",
                                self.write_wrapper
                            ),
                        );
                    }
                    if !is_write && is_write_wrapper {
                        return refuse(
                            req.id,
                            format!(
                                "{target} is not a write tool: call it with {}",
                                self.wrapper
                            ),
                        );
                    }
                    if is_write {
                        // Audit the real target and argument names, never values.
                        let mut keys: Vec<&str> = input
                            .arguments
                            .as_ref()
                            .map(|a| a.keys().map(String::as_str).collect())
                            .unwrap_or_default();
                        keys.sort_unstable();
                        tracing::info!(
                            target: "mcp_proxy::write_audit",
                            tool = %target,
                            argument_names = ?keys,
                            "write tool invoked"
                        );
                    }
                }
                params.name = target;
                params.arguments = input.arguments.unwrap_or_default().into();
            }
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tower::ServiceExt;
    use tower_mcp::{Extensions, McpResponse, RequestId};

    #[tokio::test]
    async fn preserves_request_context_and_continuation_fields() {
        let context = tower_mcp::RequestContext::new(RequestId::Number(42));
        let cancellation = context.cancellation_token();
        let expected = json!({
            "name":"api/echo", "arguments":{"value":1},
            "inputResponses":{}, "requestState":"resume-state",
            "_meta":{"progressToken":"progress-42"}, "task":{"ttl":60000}
        });
        let inner = tower::service_fn(move |req: RouterRequest| {
            let expected = expected.clone();
            async move {
                assert_eq!(req.id, RequestId::Number(42));
                assert_eq!(req.extensions.get::<String>().unwrap(), "verified-caller");
                assert!(
                    req.extensions
                        .get::<tower_mcp::RequestContext>()
                        .unwrap()
                        .is_cancelled()
                );
                let McpRequest::CallTool(params) = req.inner else {
                    panic!("expected call")
                };
                assert_eq!(serde_json::to_value(params).unwrap(), expected);
                Ok::<_, Infallible>(RouterResponse {
                    id: req.id,
                    inner: Ok(McpResponse::CallTool(tower_mcp::CallToolResult::text("ok"))),
                })
            }
        });
        let mut extensions = Extensions::new();
        extensions.insert(String::from("verified-caller"));
        extensions.insert(context);
        cancellation.cancel();
        let params = serde_json::from_value(json!({
            "name":"proxy/call_tool", "arguments":{"name":"api/echo","arguments":{"value":1}},
            "inputResponses":{}, "requestState":"resume-state",
            "_meta":{"progressToken":"progress-42"}, "task":{"ttl":60000}
        }))
        .unwrap();
        SearchInvocation::new(inner, "/")
            .oneshot(RouterRequest {
                id: RequestId::Number(42),
                inner: McpRequest::CallTool(params),
                extensions,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_and_recursive_targets_before_dispatch() {
        let inner = tower::service_fn(
            |_: RouterRequest| -> std::future::Ready<Result<RouterResponse, Infallible>> {
                panic!("invalid wrapper must never dispatch")
            },
        );
        for arguments in [
            json!({}),
            json!({"name":""}),
            json!({"name":"api/echo","arguments":[]}),
            json!({"name":"proxy::call_tool"}),
            json!({"name":"proxy::config"}),
            json!({"name":"proxy::search_tools"}),
        ] {
            let params =
                serde_json::from_value(json!({"name":"proxy::call_tool","arguments":arguments}))
                    .unwrap();
            let result = SearchInvocation::new(inner, "::")
                .oneshot(RouterRequest {
                    id: RequestId::Number(1),
                    inner: McpRequest::CallTool(params),
                    extensions: Extensions::new(),
                })
                .await
                .unwrap();
            assert!(result.inner.is_err());
        }
    }

    #[tokio::test]
    async fn resolves_discovery_ids_to_public_names() {
        for (separator, requested, expected) in [
            ("/", "api:echo", "api/echo"),
            ("::", "api:echo", "api::echo"),
            ("/", "api/echo", "api/echo"),
            ("::", "api::echo", "api::echo"),
            ("_", "api:read_note", "api_read_note"),
            ("_", "api_read_note", "api_read_note"),
        ] {
            let expected = expected.to_string();
            let inner = tower::service_fn(move |req: RouterRequest| {
                let expected = expected.clone();
                async move {
                    let McpRequest::CallTool(params) = req.inner else {
                        panic!("expected call")
                    };
                    assert_eq!(params.name, expected);
                    Ok::<_, Infallible>(RouterResponse {
                        id: req.id,
                        inner: Ok(McpResponse::CallTool(tower_mcp::CallToolResult::text("ok"))),
                    })
                }
            });
            let params = serde_json::from_value(json!({
                "name": format!("proxy{separator}call_tool"),
                "arguments": {"name": requested, "arguments": {}},
            }))
            .unwrap();
            SearchInvocation::new(inner, separator)
                .oneshot(RouterRequest {
                    id: RequestId::Number(1),
                    inner: McpRequest::CallTool(params),
                    extensions: Extensions::new(),
                })
                .await
                .unwrap();
        }
    }
}
