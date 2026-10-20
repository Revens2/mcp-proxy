#!/usr/bin/env python3
"""End-to-end smoke test of the MCP hub staging, on loopback, as root.

Runs the real OAuth flow against hub-auth (DCR, PKCE S256, consent with the
operator passphrase, token), then drives the hub over MCP: discovery, schema,
read calls on two gateways, refusals, and diagnostics. Prints results only,
never a token or the passphrase.

    sudo python3 deploy/hub-staging/smoke.py [--public https://mymcps.duckdns.org]
"""

import base64
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

AUTH = "http://127.0.0.1:18983"
HUB = "http://127.0.0.1:18984/"
REDIRECT = "https://chatgpt.com/hub-staging-smoke"
RESOURCE = "https://mymcps.duckdns.org/hub-staging/mcp"
FAILURES = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def request(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with OPENER.open(req, timeout=60) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode()


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}{('  ' + detail) if detail and not ok else ''}")
    if not ok:
        FAILURES.append(name)


def form(fields):
    return urllib.parse.urlencode(fields).encode()


def obtain_token():
    status, _, body = request(
        "POST", f"{AUTH}/register",
        json.dumps({"redirect_uris": [REDIRECT], "scope": "hub:lecture"}).encode(),
        {"Content-Type": "application/json"},
    )
    check("DCR registration", status == 201, str(status))
    client_id = json.loads(body)["client_id"]

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "scope": "hub:lecture", "state": "smoke", "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": RESOURCE,
    })
    status, _, _ = request("GET", f"{AUTH}/authorize?{query.replace('S256', 'plain')}")
    check("authorize refuses PKCE plain", status == 400, str(status))
    status, headers, _ = request("GET", f"{AUTH}/authorize?{query}")
    check("authorize redirects to consent", status in (302, 303, 307), str(status))
    demande = headers["location"].split("demande=")[1]

    phrase = open("/root/mcp-hub-staging-passphrase", encoding="utf-8").read().strip()
    status, headers, _ = request(
        "POST", f"{AUTH}/consentement", form({"demande": demande, "phrase": phrase}),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    del phrase
    check("consent accepted", status in (302, 303, 307), str(status))
    code = urllib.parse.parse_qs(urllib.parse.urlparse(headers["location"]).query)["code"][0]

    status, _, body = request(
        "POST", f"{AUTH}/token",
        form({"grant_type": "authorization_code", "code": code, "client_id": client_id,
              "redirect_uri": REDIRECT, "code_verifier": verifier, "resource": RESOURCE}),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    check("token issued", status == 200, str(status))
    return json.loads(body)["access_token"]


class Session:
    def __init__(self, url, token):
        self.url, self.token, self.sid = url, token, None
        status, headers, body = self.rpc("initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "hub-smoke", "version": "1"},
        }, raw=True)
        check("MCP initialize", status == 200, str(status))
        self.sid = {k.lower(): v for k, v in headers.items()}.get("mcp-session-id")
        self.rpc("notifications/initialized", {}, raw=True)

    def rpc(self, method, params, raw=False):
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if not method.startswith("notifications/"):
            payload["id"] = 1
        headers = {
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25",
        }
        if self.sid:
            headers["Mcp-Session-Id"] = self.sid
        status, resp_headers, body = request("POST", self.url, json.dumps(payload).encode(), headers)
        if raw:
            return status, resp_headers, body
        line = next((l[6:] for l in body.splitlines() if l.startswith("data: ")), body)
        return json.loads(line) if line else {}

    def tool(self, name, args):
        return self.rpc("tools/call", {"name": name, "arguments": args})

    def wrapped(self, name, args):
        return self.tool("proxy_call_tool", {"name": name, "arguments": args})


def ok(result):
    return "error" not in result and not result.get("result", {}).get("isError")


def text(result):
    return result.get("result", {}).get("content", [{}])[0].get("text", "")


def main():
    url = HUB
    if "--public" in sys.argv:
        url = sys.argv[sys.argv.index("--public") + 1].rstrip("/") + "/hub-staging/mcp"

    status, headers, _ = request("POST", url, b"{}", {"Content-Type": "application/json"})
    check("unauthenticated request refused", status == 401, str(status))
    check("challenge advertises resource metadata",
          "resource_metadata" in {k.lower(): v for k, v in headers.items()}.get("www-authenticate", ""))

    token = obtain_token()
    s = Session(url, token)

    names = sorted(t["name"] for t in s.rpc("tools/list", {})["result"]["tools"])
    check("public surface is meta-tools only",
          names == ["proxy_backend_status", "proxy_call_tool", "proxy_get_tool", "proxy_list_tools", "proxy_search_tools"],
          str(names))

    ids = [r["id"] for r in json.loads(text(s.tool("proxy_search_tools", {"query": "search vault notes"})))]
    check("search finds vault tools", any(i.startswith("vault:") for i in ids), str(ids))
    ids = [r["id"] for r in json.loads(text(s.tool("proxy_search_tools", {"query": "repository file contents"})))]
    check("search finds github tools", any(i.startswith("github:") for i in ids), str(ids))
    ids = [r["id"] for r in json.loads(text(s.tool("proxy_search_tools", {"query": "delete file merge push"})))]
    check("search hides write tools",
          not any(i in ("github:delete_file", "github:merge_pull_request", "github:push_files") for i in ids), str(ids))

    schema = json.loads(text(s.tool("proxy_get_tool", {"tool_id": "vault:read_note"})))
    check("schema retrieval", "path" in json.dumps(schema.get("input_schema", {})))

    check("vault read through hub", ok(s.wrapped("vault_context_status", {})))
    check("call_tool accepts a discovery id", ok(s.wrapped("vault:context_status", {})))
    check("discovery id cannot reach meta-tools", not ok(s.wrapped("proxy:add_backend", {})))
    check("github read through hub", ok(s.wrapped("github_get_me", {})))
    for target in ("github_delete_file", "github_create_or_update_file", "github_merge_pull_request",
                   "vault_append_note", "unknown_tool", "proxy_add_backend"):
        check(f"refused via call_tool: {target}", not ok(s.wrapped(target, {})))
        check(f"refused direct: {target}", not ok(s.tool(target, {})))

    inventory = json.loads(text(s.tool("proxy_list_tools", {})))
    backends = sorted(b["backend"] for b in inventory["backends"])
    ids = [t["tool_id"] for b in inventory["backends"] for t in b["tools"]]
    check("inventory covers every gateway",
          backends == ["calendar", "github", "orch", "tasks", "vault"], str(backends))
    check("inventory hides write tools",
          not any(i.split(":", 1)[1] in ("delete_file", "push_files", "append_note", "tasks_create")
                  for i in ids), str(len(ids)))
    print(f"      inventory: {inventory['total_tools']} tools")

    status = s.tool("proxy_backend_status", {})
    body = text(status)
    check("backend status", ok(status) and "vault" in body and "github" in body, body[:200])
    check("backend status leaks no endpoint", "127.0.0.1" not in body and "http" not in body)

    print(f"\n{'ALL PASS' if not FAILURES else str(len(FAILURES)) + ' FAILURE(S)'}")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
