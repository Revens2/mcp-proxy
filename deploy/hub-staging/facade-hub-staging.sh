#!/bin/sh
# Create a read-only staging instance of an existing mcp-framework-rs facade
# for the hub: same binary and fail-closed tool policy as production, one
# static token restricted to the service's read scope, loopback only, never
# routed by nginx. Idempotent; never prints a secret. Run as root:
#
#   sudo sh facade-hub-staging.sh <name> <unit> <env-prefix> <port> <read-scope>
#   sudo sh facade-hub-staging.sh tasks tasks-gateway-rs TASKS_MCP_RS 18986 tasks:lecture
#
# Copies the production unit's Environment (minus token, scopes, port, and
# OAuth store) so the upstream and its credentials stay exactly the same.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
NAME=$1 PROD=$2 PREFIX=$3 PORT=$4 SCOPE=$5
ETC=/etc/mcp-hub-staging
UNIT=/etc/systemd/system/$NAME-gateway-hub-staging.service
VAR=MCP_HUB_$(echo "$NAME" | tr 'a-z-' 'A-Z_')_TOKEN
umask 077

user=$(systemctl show -p User --value "$PROD")
group=$(systemctl show -p Group --value "$PROD")
workdir=$(systemctl show -p WorkingDirectory --value "$PROD")
exec_start=$(systemctl cat "$PROD" | sed -n 's/^ExecStart=\(.\+\)/\1/p' | tail -1)
[ -n "$user" ] && [ -n "$exec_start" ] || { echo "cannot read $PROD" >&2; exit 1; }

token_file=$ETC/$NAME-facade.token
if [ ! -s "$token_file" ]; then
    head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$token_file"
fi
chown "$user:${group:-$user}" "$token_file"
chmod 0400 "$token_file"
setfacl -m "u:$user:x" "$ETC" 2>/dev/null || chmod 0751 "$ETC"
if ! grep -q "^$VAR=" "$ETC/hub.env"; then
    printf '%s=%s\n' "$VAR" "$(cat "$token_file")" >> "$ETC/hub.env"
fi

{
    printf '[Unit]\nDescription=%s MCP facade for the MCP hub staging (%s only, loopback %s)\n' "$NAME" "$SCOPE" "$PORT"
    printf 'After=network-online.target %s.service\nWants=network-online.target\n\n[Service]\n' "$PROD"
    printf 'User=%s\nGroup=%s\nWorkingDirectory=%s\n' "$user" "${group:-$user}" "$workdir"
    systemctl cat "$PROD" | grep '^Environment=' \
        | grep -vE "${PREFIX}_(TOKEN_FILE|TOKEN_SCOPES|PORT|OAUTH_ETAT|OAUTH_EXPECTED_RESOURCE|ISSUER)="
    printf 'Environment=%s_ISSUER=https://mymcps.duckdns.org/oauth/%s-hub-staging\n' "$PREFIX" "$NAME"
    printf 'Environment=%s_PORT=%s\n' "$PREFIX" "$PORT"
    printf 'Environment=%s_TOKEN_FILE=%s\n' "$PREFIX" "$token_file"
    printf 'Environment="%s_TOKEN_SCOPES=%s"\n' "$PREFIX" "$SCOPE"
    printf 'ExecStart=%s\nRestart=on-failure\nRestartSec=5\nMemoryMax=128M\nCPUQuota=50%%\n' "$exec_start"
    printf 'NoNewPrivileges=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectSystem=strict\nProtectHome=yes\n'
    printf 'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n'
    printf 'RestrictSUIDSGID=yes\nLockPersonality=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n'
    printf 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n'
} > "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable "$NAME-gateway-hub-staging" >/dev/null 2>&1
systemctl restart "$NAME-gateway-hub-staging"
sleep 3
systemctl is-active "$NAME-gateway-hub-staging"
