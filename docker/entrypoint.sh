#!/usr/bin/env bash
# Container entrypoint for the IDA image.
#
# 1. Trust any CA certificate mounted at $CERT_DIR (default /etc/unknowncyber/ssl):
#    as root it goes into the system store via update-ca-certificates; without
#    root a merged bundle is written to a temp file instead.  Either way
#    SSL_CERT_FILE is exported, which the Unknown Cyber plugin honours.
# 2. Drop to $APP_USER (if started as root) and exec ida64 with the given args.
set -euo pipefail

CERT_DIR="${CERT_DIR:-/etc/unknowncyber/ssl}"
APP_USER="${APP_USER:-unknowncyber}"
IDA_PREFIX="${IDA_PREFIX:-/opt/ida}"
SYSTEM_BUNDLE=/etc/ssl/certs/ca-certificates.crt

shopt -s nullglob
certs=("$CERT_DIR"/*.crt "$CERT_DIR"/*.pem)
shopt -u nullglob

if ((${#certs[@]})); then
    if [[ $(id -u) -eq 0 ]]; then
        for cert in "${certs[@]}"; do
            name=$(basename "${cert%.*}")
            cp "$cert" "/usr/local/share/ca-certificates/unknowncyber-${name}.crt"
        done
        update-ca-certificates >/dev/null
        export SSL_CERT_FILE="$SYSTEM_BUNDLE"
    else
        bundle="${TMPDIR:-/tmp}/unknowncyber-ca-bundle.crt"
        cat "$SYSTEM_BUNDLE" "${certs[@]}" >"$bundle"
        chmod 0644 "$bundle"
        export SSL_CERT_FILE="$bundle"
    fi
    echo "[entrypoint] trusting ${#certs[@]} CA certificate(s) from $CERT_DIR" >&2
else
    export SSL_CERT_FILE="${SSL_CERT_FILE:-$SYSTEM_BUNDLE}"
fi

if [[ $(id -u) -eq 0 ]]; then
    exec setpriv --reuid="$APP_USER" --regid="$(id -g "$APP_USER")" --init-groups \
        env HOME="/home/$APP_USER" USER="$APP_USER" "$IDA_PREFIX/ida64" "$@"
fi
exec "$IDA_PREFIX/ida64" "$@"
