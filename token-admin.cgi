#!/usr/bin/env bash
set -euo pipefail

# ── paths ──────────────────────────────────────────────────────────────────
# In a real CGI context (GATEWAY_INTERFACE is set by Apache), paths are
# hardcoded to prevent environment variable injection by a compromised web
# process. The env overrides remain active when GATEWAY_INTERFACE is absent
# (local testing, test suite).

if [ -n "${GATEWAY_INTERFACE:-}" ]; then
    SCRIPT_DIR="/opt/apache-token-auth"
    TOKEN_ROOT="/etc/apache-token-auth/tokens"
    MASTER_TOKEN_FILE="/etc/apache-token-auth/master.token"
    # Hardcode PATH so external commands cannot be hijacked via the CGI
    # environment (e.g. a malicious SetEnv PATH in .htaccess). Without this,
    # a substituted sha256sum returns empty strings and ct_equal always succeeds.
    PATH="/usr/local/bin:/usr/bin:/bin"
else
    SCRIPT_DIR="${SCRIPT_DIR:-/opt/apache-token-auth}"
    TOKEN_ROOT="${TOKEN_ROOT:-/etc/apache-token-auth/tokens}"
    MASTER_TOKEN_FILE="${MASTER_TOKEN_FILE:-/etc/apache-token-auth/master.token}"
fi

# Restrict file/directory creation permissions: token files 640 (owner+group
# read), token directories 750. Prevents local users from reading bearer tokens
# directly off the filesystem by listing token directory contents.
umask 027

# ── helpers ────────────────────────────────────────────────────────────────

# URL decode without passing attacker data through printf %b.
# Only the validated two hex digits ever touch printf -- never raw input.
# Bare '%' that don't precede a valid hex pair are stripped from the residual
# tail to prevent them being re-interpreted by downstream consumers.
urldecode() {
    local s="${1//+/ }"
    local result=''
    while [[ "$s" =~ ^([^%]*)%([0-9A-Fa-f][0-9A-Fa-f])(.*)$ ]]; do
        result="${result}${BASH_REMATCH[1]}$(printf "\\x${BASH_REMATCH[2]}")"
        s="${BASH_REMATCH[3]}"
    done
    # Strip any lone '%' in the residual tail (malformed percent-encoding).
    printf '%s' "${result}${s//%/}"
}

# Extract a parameter from a URL-encoded string by exact key match.
# Splits on & first, compares keys literally -- no regex, no substring collision.
param_get() {
    local key="$1" data="$2"
    local pair k v
    while IFS= read -r pair; do
        # Skip pairs with no '=' -- a bare key has no value and must not match.
        [[ "$pair" == *=* ]] || continue
        k="${pair%%=*}"
        v="${pair#*=}"
        if [ "$k" = "$key" ]; then
            urldecode "$v"
            return
        fi
    done < <(printf '%s\n' "$data" | tr '&' '\n')
}

# Extract a parameter without URL-decoding the value.
# Used for the action parameter, which is a fixed ASCII vocabulary.
# Decoding action would allow WAF/log evasion via cre%61te, dele%74e, etc.
param_get_raw() {
    local key="$1" data="$2"
    local pair k v
    while IFS= read -r pair; do
        [[ "$pair" == *=* ]] || continue
        k="${pair%%=*}"
        v="${pair#*=}"
        if [ "$k" = "$key" ]; then
            printf '%s' "$v"
            return
        fi
    done < <(printf '%s\n' "$data" | tr '&' '\n')
}

# Hostname: letters, digits, dots, hyphens; max 253 chars; no leading/trailing
# dot or hyphen; no consecutive dots (would allow path traversal via symlinks
# or confuse filesystem operations).
valid_host() {
    [ -n "$1" ] || return 1
    [ "${#1}" -le 253 ] || return 1
    case "$1" in
        -*|*-|.*|*.|*[!a-zA-Z0-9.-]*|*..*) return 1 ;;
        *)                                   return 0 ;;
    esac
}

# Token: exactly 32 lowercase hex characters (matches generation format).
valid_token() {
    [ "${#1}" -eq 32 ] || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
        *)            return 0 ;;
    esac
}

# JSON-escape a string: escape backslashes and double-quotes, strip control chars.
# Uses bash parameter expansion to avoid sed backslash-escaping ambiguity.
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"   # \ -> \\
    s="${s//\"/\\\"}"   # " -> \"
    # Strip control characters (0x00-0x1F) and DEL (0x7F).
    printf '%s' "$s" | tr -d '\001-\037\177' | tr -d '\000'
}

# Emit a JSON error with HTTP status, security headers, then exit.
# The message is json_escaped so this function is safe with variable input.
json_error() {
    printf 'Status: %s\n' "$1"
    printf 'Content-Type: application/json\n'
    printf 'X-Content-Type-Options: nosniff\n'
    printf 'X-Frame-Options: DENY\n'
    printf 'Cache-Control: no-store\n'
    printf 'Strict-Transport-Security: max-age=63072000; includeSubDomains\n'
    printf '\n'
    printf '{"error":"%s"}\n' "$(json_escape "$2")"
    exit 1
}

# Emit success JSON response headers.
# IMPORTANT: call this only AFTER all validation is complete AND the body has
# been buffered. Calling json_error() after json_headers() has run produces a
# garbled HTTP 200 response with the Status: line appearing in the body.
json_headers() {
    printf 'Content-Type: application/json\n'
    printf 'X-Content-Type-Options: nosniff\n'
    printf 'X-Frame-Options: DENY\n'
    printf 'Cache-Control: no-store\n'
    printf 'Strict-Transport-Security: max-age=63072000; includeSubDomains\n'
    printf '\n'
}

# Constant-time-safe token comparison using a random per-request salt.
# The random salt ensures sha256sum output is unpredictable, so comparing
# the hashes does not leak prefix information about the master token.
# Guards against empty-string false-positive: if any pipeline stage fails
# (e.g. sha256sum missing from PATH), a and b would both be empty and
# [ "" = "" ] would succeed -- bypassing auth. The length checks prevent this.
ct_equal() {
    local salt
    salt=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | sha256sum | cut -c1-32)
    # If /dev/urandom is unavailable, dd produces no bytes and sha256sum hashes
    # empty input (well-known constant e3b0c...). The salt would be predictable,
    # degrading timing-attack resistance. Fail closed if salt is not 32 chars.
    [ "${#salt}" -eq 32 ] || return 1
    local a b
    a=$(printf '%s%s' "$salt" "$1" | sha256sum)
    b=$(printf '%s%s' "$salt" "$2" | sha256sum)
    # sha256sum output is 64+ chars; anything shorter means a pipeline failure.
    [ "${#a}" -ge 64 ] || return 1
    [ "${#b}" -ge 64 ] || return 1
    [ "$a" = "$b" ]
}

# ── enforce HTTPS ──────────────────────────────────────────────────────────

[ "${HTTPS:-}" = "on" ] || json_error 403 "HTTPS required"

# ── routing: static assets and UI (no auth required) ──────────────────────

action=$(param_get_raw action "${QUERY_STRING:-}")

if [ -z "$action" ]; then
    printf 'Content-Type: text/html\n'
    printf 'X-Content-Type-Options: nosniff\n'
    printf 'X-Frame-Options: DENY\n'
    printf 'Cache-Control: no-store\n'
    printf 'Strict-Transport-Security: max-age=63072000; includeSubDomains\n'
    printf "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'none'; connect-src 'self'\n"
    printf '\n'
    cat "$SCRIPT_DIR/index.html"
    exit 0
fi

if [ "$action" = "css" ]; then
    printf 'Content-Type: text/css\n'
    printf 'X-Content-Type-Options: nosniff\n'
    printf 'X-Frame-Options: DENY\n'
    printf 'Cache-Control: no-store\n'
    printf 'Strict-Transport-Security: max-age=63072000; includeSubDomains\n'
    printf "Content-Security-Policy: default-src 'none'\n"
    printf '\n'
    cat "$SCRIPT_DIR/admin.css"
    exit 0
fi

if [ "$action" = "js" ]; then
    printf 'Content-Type: application/javascript\n'
    printf 'X-Content-Type-Options: nosniff\n'
    printf 'X-Frame-Options: DENY\n'
    printf 'Cache-Control: no-store\n'
    printf 'Strict-Transport-Security: max-age=63072000; includeSubDomains\n'
    printf "Content-Security-Policy: default-src 'none'\n"
    printf '\n'
    cat "$SCRIPT_DIR/admin.js"
    exit 0
fi

# ── auth ───────────────────────────────────────────────────────────────────

req_token=$(printf '%s' "${HTTP_AUTHORIZATION:-}" | sed -n 's/^Bearer //p')
# Reject empty token before ct_equal to avoid leaking timing info
[ -n "$req_token" ] || json_error 403 "forbidden"
master=$(cat "$MASTER_TOKEN_FILE" 2>/dev/null) || json_error 500 "configuration error"
ct_equal "$req_token" "$master" || json_error 403 "forbidden"

# ── read POST body, capped at 4 KB with a timeout ─────────────────────────

if [ "${REQUEST_METHOD:-}" = "POST" ]; then
    # timeout guards against slow-drip POST attacks exhausting CGI workers.
    # Apache enforces LimitRequestBody upstream; the cap here is defence in depth.
    POSTDATA=$(timeout 10 head -c 4096 2>/dev/null) || POSTDATA=""
    # Strip raw newlines and carriage returns. Standards-compliant URL-encoded
    # bodies encode these as %0A/%0D. Raw bytes would cause param_get to see
    # extra key=value pairs invisible to WAF/proxy URL-encoded parsers.
    POSTDATA="${POSTDATA//$'\n'/}"
    POSTDATA="${POSTDATA//$'\r'/}"
else
    POSTDATA=""
fi

# ── route ──────────────────────────────────────────────────────────────────
# ARCHITECTURE NOTE: each branch buffers its response body into $body BEFORE
# calling json_headers(). This ensures json_error() can still emit a correct
# Status: line if validation fails, and prevents truncated responses under
# set -e if a subcommand fails mid-output after headers have been sent.
# Never call json_headers() before the body is fully constructed.

case "$action" in

hosts)
    # Detect apachectl failure rather than silently returning an empty list.
    if ! hosts_out=$(apachectl -S 2>&1); then
        json_error 500 "host discovery failed"
    fi
    body='{"hosts":['
    sep=''
    while IFS= read -r h; do
        body="${body}${sep}\"$(json_escape "$h")\""
        sep=','
    done < <(printf '%s\n' "$hosts_out" | grep 'namevhost' | awk '{print $4}' | sort -u)
    body="${body}]}"
    json_headers
    printf '%s\n' "$body"
    ;;

list)
    body='{"hosts":['
    sep=''
    for d in "$TOKEN_ROOT"/*/; do
        [ -d "$d" ] || continue
        h=${d%/}; h=${h##*/}
        valid_host "$h" || continue    # skip directories with non-hostname names
        body="${body}${sep}\"$(json_escape "$h")\""
        sep=','
    done
    body="${body}]}"
    json_headers
    printf '%s\n' "$body"
    ;;

tokens)
    host=$(param_get host "${QUERY_STRING:-}")
    valid_host "$host" || json_error 400 "invalid host"
    [ -d "$TOKEN_ROOT/$host" ]  || json_error 404 "host not found"
    body="{\"host\":\"$(json_escape "$host")\",\"tokens\":["
    sep=''
    for f in "$TOKEN_ROOT/$host/"*; do
        [ -f "$f" ] || continue
        [ ! -L "$f" ] || continue        # skip symlinks -- could exfiltrate arbitrary files
        tok=${f##*/}
        valid_token "$tok" || continue    # skip any non-token files in the dir
        label=$(head -c 256 "$f" 2>/dev/null) || continue   # cap read; skip if file vanished
        body="${body}${sep}{\"token\":\"$(json_escape "$tok")\",\"label\":\"$(json_escape "$label")\"}"
        sep=','
    done
    body="${body}]}"
    json_headers
    printf '%s\n' "$body"
    ;;

create)
    [ "${REQUEST_METHOD:-}" = "POST" ] || json_error 405 "method not allowed"
    host=$(param_get host "$POSTDATA")
    label=$(param_get label "$POSTDATA")
    valid_host "$host" || json_error 400 "invalid host"
    [ "${#label}" -le 256 ] || json_error 400 "label too long"
    # Strip control characters (newlines, NUL, etc.) from label before storage.
    label=$(printf '%s' "$label" | tr -d '\000-\037\177')
    tok=$(head -c 32 /dev/urandom | sha256sum | cut -c1-32) \
                                      || json_error 500 "token generation failed"
    valid_token "$tok"                || json_error 500 "token generation failed"
    mkdir -p "$TOKEN_ROOT/$host"      || json_error 500 "cannot create host directory"
    # Write to a temp file then rename atomically. This prevents a partial write
    # from leaving a live (but label-less) bearer token on disk if the write fails.
    tmpfile=$(mktemp "$TOKEN_ROOT/$host/.tmp.XXXXXX") \
                                      || json_error 500 "cannot create temp file"
    printf '%s' "$label" > "$tmpfile" || { rm -f "$tmpfile"; json_error 500 "cannot write token"; }
    mv "$tmpfile" "$TOKEN_ROOT/$host/$tok" \
                                      || { rm -f "$tmpfile"; json_error 500 "cannot install token"; }
    # Buffer body before headers (consistent with other branches; see architecture note).
    body="{\"token\":\"$(json_escape "$tok")\",\"label\":\"$(json_escape "$label")\"}"
    json_headers
    printf '%s\n' "$body"
    ;;

delete)
    [ "${REQUEST_METHOD:-}" = "POST" ] || json_error 405 "method not allowed"
    host=$(param_get host "$POSTDATA")
    tok=$(param_get token "$POSTDATA")
    valid_host "$host"  || json_error 400 "invalid host"
    valid_token "$tok"  || json_error 400 "invalid token"
    rm -f "$TOKEN_ROOT/$host/$tok" || json_error 500 "cannot delete token"
    json_headers
    printf '{"status":"deleted"}\n'
    ;;

*)
    json_error 400 "unknown action"
    ;;

esac
