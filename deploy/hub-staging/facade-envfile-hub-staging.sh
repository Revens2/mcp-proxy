#!/bin/sh
# Like facade-hub-staging.sh, for gateways configured through an
# EnvironmentFile (browser, excalidraw). Copies the production environment
# minus listener, token, scopes, issuer, OAuth store, and JWT settings into a
# staging env file owned by the service user, then starts a loopback-only
# instance whose single static token carries only the given scope(s).
#
#   sudo sh facade-envfile-hub-staging.sh <name> <prod-unit> <env-prefix> <port> "<scopes>" [token-var-is-file]
#   sudo sh facade-envfile-hub-staging.sh excalidraw excalidraw-gateway EXCALIDRAW_MCP 18975 excalidraw:lecture
#
# Idempotent; never prints a secret.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
NAME=$1 PROD=$2 PREFIX=$3 PORT=$4 SCOPES=$5
ETC=/etc/mcp-hub-staging
UNIT=/etc/systemd/system/$NAME-gateway-hub-staging.service
STAGE_ENV=$ETC/$NAME-gateway.env
VAR=MCP_HUB_$(echo "$NAME" | tr 'a-z-' 'A-Z_')_TOKEN
umask 077

user=$(systemctl show -p User --value "$PROD")
group=$(systemctl show -p Group --value "$PROD")
workdir=$(systemctl show -p WorkingDirectory --value "$PROD")
prod_env=$(systemctl show -p EnvironmentFiles --value "$PROD" | grep -oE '/[^ ]+' | head -1)
exec_start=$(systemctl cat "$PROD" | sed -n 's/^ExecStart=\(.\+\)/\1/p' | tail -1)
[ -n "$user" ] && [ -n "$exec_start" ] && [ -r "$prod_env" ] || { echo "cannot read $PROD" >&2; exit 1; }

token_file=$ETC/$NAME-facade.token
[ -s "$token_file" ] || head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > "$token_file"
grep -q "^$VAR=" "$ETC/hub.env" || printf '%s=%s\n' "$VAR" "$(cat "$token_file")" >> "$ETC/hub.env"

state=/var/lib/mcp-hub-staging/$NAME
install -d -o "$user" -g "${group:-$user}" -m 0700 "$state"
{
    grep -vE "^${PREFIX}_(PORT|TOKEN|TOKEN_FILE|TOKEN_SCOPES|ISSUER|RESOURCE_URL|OAUTH_ETAT|OAUTH_DIR|OAUTH_EXPECTED_RESOURCE|JWT_SECRET|JWT_ISSUER|JWT_AUDIENCE)=" "$prod_env"
    printf '%s_PORT=%s\n' "$PREFIX" "$PORT"
    printf '%s_ISSUER=https://mymcps.duckdns.org/oauth/%s-hub-staging\n' "$PREFIX" "$NAME"
    printf '%s_RESOURCE_URL=https://mymcps.duckdns.org/%s-hub-staging/mcp\n' "$PREFIX" "$NAME"
    printf '%s_OAUTH_DIR=%s\n' "$PREFIX" "$state"
    printf '%s_OAUTH_ETAT=%s/etat.json\n' "$PREFIX" "$state"
    printf '%s_TOKEN=%s\n' "$PREFIX" "$(cat "$token_file")"
    printf '%s_TOKEN_SCOPES="%s"\n' "$PREFIX" "$SCOPES"
} > "$STAGE_ENV"
chown "$user:${group:-$user}" "$STAGE_ENV" "$token_file"
chmod 0400 "$STAGE_ENV" "$token_file"
setfacl -m "u:$user:x" "$ETC" 2>/dev/null || chmod 0751 "$ETC"

{
    printf '[Unit]\nDescription=%s MCP gateway for the MCP hub staging (%s, loopback %s)\n' "$NAME" "$SCOPES" "$PORT"
    printf 'After=network-online.target %s.service\nWants=network-online.target\n\n[Service]\n' "$PROD"
    printf 'User=%s\nGroup=%s\n' "$user" "${group:-$user}"
    [ -n "$workdir" ] && printf 'WorkingDirectory=%s\n' "$workdir"
    systemctl cat "$PROD" | grep -E '^Environment=' || true
    printf 'EnvironmentFile=%s\nExecStart=%s\nRestart=on-failure\nRestartSec=5\n' "$STAGE_ENV" "$exec_start"
    printf 'MemoryMax=192M\nCPUQuota=50%%\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n'
    printf 'ReadWritePaths=%s\nProtectHome=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n' "$state"
    printf 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\n[Install]\nWantedBy=multi-user.target\n'
} > "$UNIT"
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable "$NAME-gateway-hub-staging" >/dev/null 2>&1
systemctl restart "$NAME-gateway-hub-staging"
sleep 4
systemctl is-active "$NAME-gateway-hub-staging"
