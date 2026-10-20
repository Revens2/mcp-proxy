#!/bin/sh
# Restart the hub when it lost a backend transport (a gateway restarted, e.g.
# vault-ro's nightly restart). The proxy does not reconnect HTTP backends by
# itself; a restart is cheap and keeps ChatGPT's grants (they live in
# hub-auth). Only errors logged after the hub's last start count, so one
# failure triggers at most one restart. EOF on close is normal and ignored.
set -eu
UNIT=mcp-hub-staging
start=$(systemctl show -p ActiveEnterTimestamp --value "$UNIT")
[ -n "$start" ] || exit 0
# Skip the shutdown lines of the previous process, logged in the same second.
since=$(date -d "@$(($(date -d "$start" +%s) + 5))" '+%Y-%m-%d %H:%M:%S')
if journalctl -u "$UNIT" --since "$since" -o cat --no-pager 2>/dev/null |
    grep -qE '"(Transport send error|SSE connection failed)"'; then
    logger -t mcp-hub-watchdog "backend transport lost since $start: restarting $UNIT"
    systemctl restart "$UNIT"
fi
