# ChatGPT hub -- one connector, many MCP gateways

This fork can run as a single MCP endpoint for ChatGPT web (custom connector)
in front of existing MCP gateways. ChatGPT connects once; gateways are added
behind the hub without reconnecting, as long as the public meta-tools stay the
same. Version 1 is strictly read-only.

Status: code, configuration, and tests are in this repository. A live ChatGPT
session has to be validated separately (see "Verification status").

## Topology

```
ChatGPT web
   |  HTTPS  (OAuth 2.1: DCR + PKCE S256 + consent passphrase)
   v
nginx  mymcps.duckdns.org
   |-- /oauth/hub-staging/*                --> hub-auth   127.0.0.1:18983
   |-- /.well-known/oauth-*/...hub-staging  --> hub-auth / mcp-proxy
   '-- /hub-staging/mcp (exact)             --> mcp-proxy  127.0.0.1:18984
                                                 |  each request: RFC 7662
                                                 |  introspection --> hub-auth
                                                 |  (private, client secret)
         own credential per gateway, ChatGPT token never forwarded
                                                 |
          +--------------------------------------+------------------+
          v                                                         v
   vault-ro 127.0.0.1:8811/mcp                     github-gateway-rs (staging
   (dedicated token, read-only server)             instance) 127.0.0.1:18985/mcp
                                                   token scope github:lecture
                                                   --> github-mcp-upstream :8800
```

Rules:

- **One public surface.** In `tool_exposure = "search"` ChatGPT sees only
  `proxy_search_tools`, `proxy_list_tools` (full inventory: tool_id and
  one-line description of every allowed tool), `proxy_get_tool`,
  `proxy_call_tool`, and `proxy_backend_status`. Backend tools never appear in
  `tools/list`, so
  hundreds of tools do not enter the model context.
- **The hub is a router, not a bypass.** It reaches gateways only through
  their normal MCP endpoint with its own credential; each gateway keeps
  enforcing its own policy. Never point a backend at a gateway's internal
  upstream.
- **Token separation.** ChatGPT's token is validated by the hub and never
  forwarded (`forward_auth = false`, the default; no backend receives the
  inbound `Authorization` header). Downstream credentials are dedicated to the
  hub and revocable on their own.
- **No unauthenticated hop.** mcp-proxy validates every request itself
  (introspection), so nothing on loopback accepts requests on ChatGPT's behalf
  without a valid token.

## Components

### mcp-proxy changes (this fork)

| Feature | Where | Effect |
|---|---|---|
| `security.default_deny` | `src/config.rs` (`validate_default_deny`), `src/filter.rs` (`CapabilityFilterService::with_default_deny`) | Every backend must declare `read_only_targets`. Any tool, resource, or prompt outside a configured allowlist -- including a backend attached at runtime -- is hidden and refused. `completion/complete` and resource subscriptions are refused. Failover, canary, mirror, and composite tools are rejected at load time. Backend names must be `[A-Za-z0-9_-]`, may not contain the separator, may not be `proxy`, and every public name must fit `^[A-Za-z0-9_-]{1,64}$`. Inbound auth is mandatory. |
| `read_only_targets` | `BackendConfig::check_read_only_targets`, `build_filter` | Exact-name allowlist, the backend's whole policy. Glob (`* ? [ ] { } !`), `re:` patterns, and whitespace are rejected. Annotations (`read_only_hint`) are never trusted. Resources and prompts are closed unless listed exactly in `expose_resources` / `expose_prompts`. Cannot be combined with other filters. |
| Filtered discovery | `ToolVisibility`, `discovery::build_index_with_visibility`, `reindex_with_visibility` | The BM25 index and schema store contain only tools the capability filter allows; `proxy_search_tools` and `proxy_get_tool` cannot reveal a refused tool. Reindex after hot reload keeps the startup policy. |
| `proxy_backend_status` | `src/admin_tools.rs` | Ordinary-caller diagnostic in `default_deny` mode: backend names and `healthy` only. No URL, error text, transport, or timing. |
| `require_auth_outside_loopback` | `ProxyConfig::validate` | A non-loopback bind without `[auth]` fails to load. |

The policy is evaluated on the real target: `proxy_call_tool` is rewritten to
the target tool outside the middleware stack, then passes RBAC, scopes, the
capability filter, and validation like a direct call. Targets under `proxy_`
are refused.

### hub-auth (`contrib/hub-auth`)

A small Rust binary built on `mcp-auth` from mcp-framework-rs -- the same
authorization server the existing gateways run. It adds:

- RFC 7662 `/introspect`, authenticated with a dedicated client id/secret
  (HTTP Basic or form), returning `iss`, `aud` (the hub resource URL), `scope`,
  `exp`. It is not advertised and nginx does not publish it.
- `/authorize` requires `response_type=code`, PKCE `S256`, the hub resource
  (RFC 8707) when present, and only the `hub:lecture` scope.
- Dynamic client registration only accepts redirect URIs under
  `HUB_AUTH_REDIRECT_PREFIXES` (default `https://chatgpt.com/`).
- At most 10 consent passphrase attempts per minute (all clients).
- RFC 8414 metadata at the path-aware location.

Grants live in memory. Restarting **hub-auth** revokes every token and ChatGPT
must reconnect; restarting **mcp-proxy** does not.

## Permissions model (V1)

- One scope, `hub:lecture`. No write scope exists on the hub.
- Callable = listed in `read_only_targets` **and** allowed by the gateway
  itself. Unknown or unclassified tools are refused by default.
- MCP annotations are not used as proof of safety.
- No generic shell, execute, delete, or write wrapper may be listed. A tool is
  only added after reading its implementation or the gateway's own policy.
- Gateway layer: vault-ro has no write tool; the staging GitHub facade only
  holds `github:lecture`, so its fail-closed policy refuses all 35 write tools
  even if the hub were misconfigured.

Later phase (not implemented): controlled writes with a separate scope, an
explicit per-tool allowlist, human confirmation, an audit trail, and
idempotency keys.

## OAuth and consent, what to expect

- ChatGPT discovers `/.well-known/oauth-protected-resource/hub-staging/mcp`,
  then the authorization server, registers itself (DCR), and opens the consent
  page, where you type the hub passphrase once.
- Access tokens last 1 hour; refresh tokens 30 days with rotation, handled by
  ChatGPT.
- This single login replaces per-gateway connectors in ChatGPT, but it does
  not remove consent elsewhere: a gateway whose own credential expires (for
  example a future OAuth-based downstream) still needs its own renewal.

## Adding a gateway (no ChatGPT reconnection)

1. Pick a gateway that has a stable MCP endpoint and supports a credential
   dedicated to the hub (separate token, minimal scope). Never reuse a
   write-capable or shared token; never target an internal upstream.
2. Read the gateway's tool implementations or policy and list the read-only
   tools to expose, by exact name.
3. Create the credential, store it in `/etc/mcp-hub-staging/hub.env`
   (`chmod 600`, owner `mcp-hub`) as a new `MCP_HUB_<NAME>_TOKEN` variable.
4. Append to `mcp-hub-staging.toml`:

   ```toml
   [[backends]]
   name = "tasks"                     # [A-Za-z0-9-], no "_"
   transport = "http"
   url = "http://127.0.0.1:18992/mcp"
   bearer_token = "${MCP_HUB_TASKS_TOKEN}"
   forward_auth = false
   read_only_targets = ["list_tasks", "get_task"]

   [backends.timeout]
   seconds = 30
   ```

5. Validate, then restart the hub only:

   ```bash
   sudo -u mcp-hub env $(sudo cat /etc/mcp-hub-staging/hub.env | xargs) \
     /opt/mcp-hub-staging/mcp-proxy --check --config /opt/mcp-hub-staging/mcp-hub-staging.toml
   sudo systemctl restart mcp-hub-staging
   ```

6. In ChatGPT, ask for something the new gateway does; the model finds it
   with `proxy_search_tools`. Existing MCP sessions get a fresh session after
   the restart.

Removing a gateway: delete its block and restart. Its tools disappear from
search immediately.

### What reloads live

`hot_reload = true` applies connection-only changes (URL, timeouts) of
existing backends and reindexes search. Anything policy-bearing --
`read_only_targets`, adding or removing a backend with an allowlist, auth,
security -- is refused by the reload policy and needs the restart above. A
backend attached at runtime without an allowlist (admin API) stays dark under
`default_deny`. The staging config sets no `security.admin_token`
(allowed only with `default_deny`), so management is disabled and the public
endpoint accepts nothing but introspected hub-auth tokens.

### Schema and tool changes

The index is rebuilt at startup and after each accepted reload. If a gateway
renames or removes a tool, calls fail at the gateway and search keeps the old
entry until the next hub restart. Restart after gateway upgrades.

## Failure isolation

A gateway that is down at startup is skipped with a warning; the hub serves the
others and `proxy_backend_status` reports `degraded`. Each backend has its own
timeout and concurrency cap; a slow gateway does not block the others.
Gateways skipped at startup are not retried until the hub restarts.

The proxy does not reconnect an HTTP backend whose transport dropped (for
example vault-ro's nightly restart). `mcp-hub-staging-watchdog.timer` checks
every 2 minutes for `Transport send error` / `SSE connection failed` logged
since the hub's last start and restarts the hub once; ChatGPT keeps its grant
because tokens live in hub-auth. A native reconnect in the engine is the
proper fix and remains to do.

The file watcher (`hot_reload`) is off in the staging config: on this host it
retriggered on its own reads (one reload every ~2 s). Changes are applied with
`systemctl restart mcp-hub-staging`.

## Staging deployment (VPS Étude)

Files: `deploy/hub-staging/`.

| Item | Value |
|---|---|
| Service user | `mcp-hub` (system, no shell) |
| Binaries, config | `/opt/mcp-hub-staging/{mcp-proxy,hub-auth,mcp-hub-staging.toml}` |
| Secrets | `/etc/mcp-hub-staging/{hub.env,consent.hash,introspection.secret}` (0600 `mcp-hub`), `github-facade.token` (0400 `github-app`) |
| Units | `hub-auth-staging`, `mcp-hub-staging`, `mcp-hub-staging-watchdog.timer`, `{github,tasks,calendar,orch}-gateway-hub-staging` |
| Ports (loopback) | 18983 hub-auth, 18984 hub, 18985 GitHub, 18986 tasks, 18982 calendar, 18977 orch |
| Read-only facades | `facade-hub-staging.sh <name> <prod-unit> <env-prefix> <port> <read-scope>` clones a production mcp-framework-rs facade with only its read scope |
| nginx | `snippets/hub-staging-mcp.conf` included in the mymcps vhost |

Install (aarch64, built on the VPS with low priority):

```bash
# 1. Build (nice, one job: the VPS also runs NetBird and the gateways).
nice -n 19 cargo build --release -j 1                                  # mcp-proxy
nice -n 19 cargo build --release -j 1 --manifest-path contrib/hub-auth/Cargo.toml

# 2. Layout.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcp-hub
sudo install -d -o root -g mcp-hub -m 0750 /opt/mcp-hub-staging /etc/mcp-hub-staging
sudo install -o root -g root -m 0755 target/release/mcp-proxy contrib/hub-auth/target/release/hub-auth /opt/mcp-hub-staging/
sudo install -o root -g mcp-hub -m 0640 deploy/hub-staging/mcp-hub-staging.toml /opt/mcp-hub-staging/

# 3. Secrets (generated on the VPS, never printed or committed).
#    introspection secret -> introspection.secret and MCP_HUB_INTROSPECTION_SECRET
#    vault token          -> MCP_HUB_VAULT_TOKEN; its sha256 + label appended
#                            to /opt/vault-mcp/context-extra-tokens (reread per request)
#    github facade token  -> github-facade.token and MCP_HUB_GITHUB_TOKEN
#    consent passphrase   -> `hub-auth hash-phrase` < passphrase > consent.hash

# 4. Units, then start bottom-up and check each port.
sudo install -m 0644 deploy/hub-staging/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now github-gateway-hub-staging hub-auth-staging mcp-hub-staging

# 5. nginx (backup the *sites-enabled* file, it diverges from sites-available).
sudo cp -a /etc/nginx/sites-enabled/mymcps.duckdns.org.conf \
  /etc/nginx/sites-enabled/mymcps.duckdns.org.conf.bak-$(date +%Y%m%d-%H%M)
sudo install -m 0644 deploy/hub-staging/nginx-hub-staging.conf /etc/nginx/snippets/hub-staging-mcp.conf
#    add `include snippets/hub-staging-mcp.conf;` next to the other snippet includes
sudo nginx -t && sudo systemctl reload nginx      # reload, never restart
```

Smoke checks:

```bash
curl -s http://127.0.0.1:18983/healthz                       # ok
curl -s http://127.0.0.1:18984/livez                         # ok
curl -si https://mymcps.duckdns.org/hub-staging/mcp -X POST  # 401 + resource_metadata
curl -s https://mymcps.duckdns.org/.well-known/oauth-protected-resource/hub-staging/mcp
curl -s https://mymcps.duckdns.org/.well-known/oauth-authorization-server/oauth/hub-staging
curl -si https://mymcps.duckdns.org/oauth/hub-staging/introspect -X POST   # 404
for u in github vault orch tasks calendar sandbox; do                      # unchanged
  curl -s -o /dev/null -w "$u %{http_code}\n" -X POST https://mymcps.duckdns.org/$u/mcp; done
```

### Rollback

Nothing existing is modified except two additive lines (the nginx `include`,
one hash line in `context-extra-tokens`). In order:

1. Remove the `include snippets/hub-staging-mcp.conf;` line (or restore the
   `.bak-*` copy), `nginx -t`, `systemctl reload nginx`.
2. `systemctl disable --now mcp-hub-staging hub-auth-staging github-gateway-hub-staging`.
3. Delete the hub line (label `mcp-hub-staging`) from
   `/opt/vault-mcp/context-extra-tokens`; vault-ro rereads it per request.
4. Optionally remove the units, `/opt/mcp-hub-staging`, `/etc/mcp-hub-staging`,
   and the `mcp-hub` user.

Never touch NetBird, SSH, UFW, `wt0`, or DNS for this service.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --test chatgpt_hub_staging
cargo test --lib
(cd contrib/hub-auth && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

`tests/chatgpt_hub_staging.rs` covers: search-only surface, discovery across
two gateways, schema retrieval, read calls routed to the right gateway, writes
and unknown tools refused directly and through `proxy_call_tool`, meta-tool
recursion refused, refused tools absent from search and `get_tool`, resources,
prompts, and completion closed, a gateway down at startup isolated, a runtime
added backend kept dark, `proxy_backend_status` leaking no endpoint, and no
`Authorization` header reaching any gateway. `contrib/hub-auth` tests cover the
full DCR + PKCE + consent + token + introspection flow and every refusal path.

### Verification status

Never call the ChatGPT integration operational without a real end-to-end run:
connect `https://mymcps.duckdns.org/hub-staging/mcp` in ChatGPT, type the
passphrase on the consent page, then ask for a vault search and a GitHub file
read, and confirm a write request is refused.
