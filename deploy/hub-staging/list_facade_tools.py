#!/usr/bin/env python3
"""List the tools a staging facade exposes to its hub token (run as root).

    sudo python3 list_facade_tools.py <name> <port>

The facade filters tools/list by the token's scopes, so with a read-only token
the output is exactly the set its own policy classifies as read. Prints tool
names and the first line of each description, never the token.
"""
import json
import sys
import urllib.request

name, port = sys.argv[1], int(sys.argv[2])  # loopback port number only
env = dict(l.strip().split("=", 1) for l in open("/etc/mcp-hub-staging/hub.env") if "=" in l)
token = env["MCP_HUB_" + name.upper().replace("-", "_") + "_TOKEN"]


def rpc(method, params, sid=None):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    url = f"http://127.0.0.1:{port}/mcp"  # fixed scheme and host; port is an int
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    resp = urllib.request.urlopen(urllib.request.Request(url, body, headers), timeout=60)
    text = resp.read().decode()
    line = next((l[6:] for l in text.splitlines() if l.startswith("data: ")), text)
    return resp.headers.get("mcp-session-id"), (json.loads(line) if line else {})


sid, _ = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                            "clientInfo": {"name": "hub-inventory", "version": "1"}})
_, result = rpc("tools/list", {}, sid)
tools = result.get("result", {}).get("tools", [])
print(f"{name}: {len(tools)} tools")
for tool in tools:
    print(f"  {tool['name']} | {(tool.get('description') or '').splitlines()[0][:90] if tool.get('description') else ''}")
