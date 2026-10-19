#!/bin/sh
# Install the MCP hub staging services on VPS Étude. Run as root from a checkout
# where `cargo build --release` has produced both binaries:
#
#   sudo sh deploy/hub-staging/install.sh services   # users, secrets, units, local start
#   sudo sh deploy/hub-staging/install.sh nginx      # publish the routes (reload only)
#
# Idempotent. Never prints a secret. Backups go to /root/backup-mcp-hub-staging-*.
# Rollback: docs/CHATGPT-HUB.md, section "Rollback".
set -eu

SRC=$(cd "$(dirname "$0")/../.." && pwd)
OPT=/opt/mcp-hub-staging
ETC=/etc/mcp-hub-staging
VAULT_TOKENS=/opt/vault-mcp/context-extra-tokens
VHOST=/etc/nginx/sites-enabled/mymcps.duckdns.org.conf
SNIPPET=/etc/nginx/snippets/hub-staging-mcp.conf
LABEL=mcp-hub-staging
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=/root/backup-mcp-hub-staging-$STAMP

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
umask 077

secret() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }

backup() {
    mkdir -p "$BACKUP"
    for f in "$@"; do [ -e "$f" ] && cp -a "$f" "$BACKUP/"; done
    echo "backup: $BACKUP"
}

services() {
    backup "$VAULT_TOKENS"
    id mcp-hub >/dev/null 2>&1 ||
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin mcp-hub

    install -d -o root -g mcp-hub -m 0750 "$OPT" "$ETC"
    install -o root -g root -m 0755 "$SRC/target/release/mcp-proxy" "$OPT/mcp-proxy"
    install -o root -g root -m 0755 "$SRC/contrib/hub-auth/target/release/hub-auth" "$OPT/hub-auth"
    install -o root -g mcp-hub -m 0640 "$SRC/deploy/hub-staging/mcp-hub-staging.toml" "$OPT/"

    # Secrets are generated once and kept across reinstalls.
    if [ ! -s "$ETC/hub.env" ]; then
        intro=$(secret); vault=$(secret); gh=$(secret)
        printf 'MCP_HUB_INTROSPECTION_SECRET=%s\nMCP_HUB_VAULT_TOKEN=%s\nMCP_HUB_GITHUB_TOKEN=%s\n' \
            "$intro" "$vault" "$gh" > "$ETC/hub.env"
        printf '%s\n' "$intro" > "$ETC/introspection.secret"
        printf '%s\n' "$gh" > "$ETC/github-facade.token"
        unset intro vault gh
    fi
    chown root:mcp-hub "$ETC/hub.env" "$ETC/introspection.secret"
    chmod 0640 "$ETC/hub.env" "$ETC/introspection.secret"
    chown github-app:github-app "$ETC/github-facade.token"
    chmod 0400 "$ETC/github-facade.token"
    # github-app must traverse the directory to read its own token file.
    setfacl -m u:github-app:x "$ETC" 2>/dev/null || chmod 0751 "$ETC"

    # Consent passphrase: plaintext readable by root only, for the operator.
    if [ ! -s "$ETC/consent.hash" ]; then
        phrase=$(for _ in 1 2 3 4 5 6; do head -c 64 /dev/urandom | tr -dc 'a-z' | head -c 5; printf -- '-'; done | sed 's/-$//')
        printf '%s\n' "$phrase" > /root/mcp-hub-staging-passphrase
        chmod 0600 /root/mcp-hub-staging-passphrase
        printf '%s' "$phrase" | "$OPT/hub-auth" hash-phrase > "$ETC/consent.hash"
        unset phrase
    fi
    chown root:mcp-hub "$ETC/consent.hash"
    chmod 0640 "$ETC/consent.hash"

    # vault-ro: register only the SHA-256 of the hub token (reread per request).
    if ! grep -q " $LABEL\$" "$VAULT_TOKENS"; then
        vault=$(sed -n 's/^MCP_HUB_VAULT_TOKEN=//p' "$ETC/hub.env")
        printf '%s %s\n' "$(printf '%s' "$vault" | sha256sum | cut -d' ' -f1)" "$LABEL" >> "$VAULT_TOKENS"
        unset vault
    fi

    install -o root -g root -m 0644 "$SRC"/deploy/hub-staging/*.service /etc/systemd/system/
    systemctl daemon-reload
    for unit in github-gateway-hub-staging hub-auth-staging mcp-hub-staging; do
        systemctl enable "$unit" >/dev/null 2>&1
        systemctl restart "$unit"
        sleep 3
        systemctl is-active --quiet "$unit" || { echo "$unit failed"; journalctl -u "$unit" -n 20 --no-pager; exit 1; }
        echo "$unit active"
    done
}

nginx_publish() {
    backup "$VHOST"
    install -o root -g root -m 0644 "$SRC/deploy/hub-staging/nginx-hub-staging.conf" "$SNIPPET"
    if ! grep -q "$SNIPPET" "$VHOST"; then
        sed -i "\|include /etc/nginx/snippets/sandbox-mcp.conf;|a\\    include $SNIPPET;" "$VHOST"
    fi
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
        echo "nginx reloaded"
    else
        cp -a "$BACKUP/$(basename "$VHOST")" "$VHOST"
        mv "$SNIPPET" "$BACKUP/"
        nginx -t && echo "nginx config invalid: restored backup, nothing reloaded" >&2
        exit 1
    fi
}

case "${1:-}" in
    services) services ;;
    nginx) nginx_publish ;;
    *) echo "usage: $0 services|nginx" >&2; exit 2 ;;
esac
