//! Fail-closed invariants for the opt-in, read-only ChatGPT Hub profile.
//!
//! The existing Rust proxy keeps its normal behavior for all other profiles.
//! This is a staging guard, not a replacement for upstream authorization,
//! validated JWT claims, or a separate confirmation path for writes.

use anyhow::{Result, ensure};
use mcp_proxy::config::{AuthConfig, ProxyConfig, ToolExposure, TransportType};

/// Applied automatically when the proxy is named `chatgpt-hub`.
pub fn validate(config: &ProxyConfig) -> Result<()> {
    ensure!(config.proxy.listen.host == "127.0.0.1", "hub must listen on IPv4 loopback only");
    ensure!(config.proxy.separator == "__", "hub requires a ChatGPT-friendly namespace separator");
    ensure!(
        config.proxy.tool_discovery && config.proxy.tool_exposure == ToolExposure::Search,
        "hub requires server-side tool discovery and search-only exposure"
    );
    // A bearer token without an identity claim cannot establish a mono-user Hub.
    // Authenticated users must map to exactly one explicitly permitted subject.
    let (roles, mapping) = match config.auth.as_ref() {
        Some(AuthConfig::Jwt { roles, role_mapping, .. })
        | Some(AuthConfig::OAuth { roles, role_mapping, .. }) => {
            (roles, role_mapping.as_ref())
        }
        _ => anyhow::bail!("hub requires JWT/OAuth identity-bound authentication"),
    };
    let mapping = mapping.ok_or_else(|| anyhow::anyhow!("hub requires an explicit RBAC role mapping"))?;
    ensure!(
        mapping.claim == "sub" && mapping.default_deny && mapping.mapping.len() == 1,
        "hub requires one allowlisted subject and default-deny identity mapping"
    );
    ensure!(!roles.is_empty(), "hub requires explicit RBAC roles");
    ensure!(roles.iter().all(|role| !role.allow_tools.is_empty()), "hub roles cannot grant all tools");
    ensure!(!config.proxy.hot_reload, "hub staging forbids unreviewed dynamic policy expansion; restart after reviewed config changes");
    ensure!(config.composite_tools.is_empty(), "hub disallows composite tool fan-out");
    ensure!(!config.backends.is_empty(), "hub requires an explicit allowlisted backend");

    for backend in &config.backends {
        ensure!(matches!(&backend.transport, TransportType::Http), "hub permits only HTTP backends in staging: {}", backend.name);
        ensure!(safe_identifier(&backend.name), "unsafe backend namespace: {}", backend.name);
        ensure!(!backend.forward_auth, "upstream token passthrough forbidden: {}", backend.name);
        ensure!(backend.expose_tools.len() > 0, "backend requires an explicit tool allowlist: {}", backend.name);
        ensure!(
            backend.expose_tools.iter().all(|tool| safe_identifier(tool)),
            "wildcards, regex, and invalid tool names forbidden in allowlist: {}",
            backend.name
        );
        ensure!(
            backend.read_only_only && backend.hide_destructive,
            "backend must enforce read-only and hide destructive annotations: {}",
            backend.name
        );
        ensure!(
            backend.mirror_of.is_none() && backend.canary_of.is_none() && backend.failover_for.is_none(),
            "staging hub disables shadow traffic, canary, and failover: {}",
            backend.name
        );
    }
    // A role may only grant names present in the explicit upstream allowlists.
    let allowed: std::collections::HashSet<String> = config.backends.iter()
        .flat_map(|backend| backend.expose_tools.iter().map(move |tool| {
            format!("{}{}{}", backend.name, config.proxy.separator, tool)
        }))
        .collect();
    for role in roles {
        for tool in &role.allow_tools {
            ensure!(allowed.contains(tool), "RBAC grants unlisted tool: {}", tool);
        }
    }
    Ok(())
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> ProxyConfig {
        toml::from_str(include_str!("../examples/chatgpt-hub-staging.toml"))
            .expect("staging profile must parse")
    }

    #[test]
    fn example_profile_is_fail_closed() {
        validate(&example()).expect("staging profile must pass hub guard");
    }

    #[test]
    fn reject_upstream_token_passthrough() {
        let mut config = example();
        config.backends[0].forward_auth = true;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn reject_wildcard_tool_permissions() {
        let mut config = example();
        config.backends[0].expose_tools = vec!["*".into()];
        assert!(validate(&config).is_err());
    }

    #[test]
    fn reject_proxy_exposure() {
        let mut config = example();
        config.proxy.tool_exposure = ToolExposure::Direct;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn reject_network_listener() {
        let mut config = example();
        config.proxy.listen.host = "0.0.0.0".to_owned();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn reject_missing_readonly_filter() {
        let mut config = example();
        config.backends[0].read_only_only = false;
        assert!(validate(&config).is_err());
    }

    #[test]
    fn reject_missing_inbound_auth() {
        let mut config = example();
        config.auth = None;
        assert!(validate(&config).is_err());
    }
}
