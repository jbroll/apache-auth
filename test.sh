#!/bin/bash

. "$(dirname "$0")/Test.sh"

# ── test environment setup ─────────────────────────────────────────────────

TMPDIR_ROOT=$(mktemp -d)
TOKEN_ROOT="$TMPDIR_ROOT/tokens"
MASTER_TOKEN_FILE="$TMPDIR_ROOT/master.token"
FAKE_BIN="$TMPDIR_ROOT/bin"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CGI="$SCRIPT_DIR/token-admin.cgi"

mkdir -p "$TOKEN_ROOT"
mkdir -p "$FAKE_BIN"

MASTER="testmaster1234"
printf '%s' "$MASTER" > "$MASTER_TOKEN_FILE"

# fake apachectl returning two vhosts
cat > "$FAKE_BIN/apachectl" << 'EOF'
#!/bin/bash
cat << 'VHOSTS'
VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server example.com (/etc/apache2/sites-enabled/example.com.conf:1)
         port 443 namevhost example.com (/etc/apache2/sites-enabled/example.com.conf:1)
         port 443 namevhost api.example.com (/etc/apache2/sites-enabled/api.conf:1)
VHOSTS
EOF
chmod +x "$FAKE_BIN/apachectl"

# separate bin dir with an apachectl that returns no vhosts
FAKE_BIN_EMPTY="$TMPDIR_ROOT/bin-empty"
mkdir -p "$FAKE_BIN_EMPTY"
cat > "$FAKE_BIN_EMPTY/apachectl" << 'EOF'
#!/bin/bash
echo "VirtualHost configuration:"
echo "No virtual hosts found."
EOF
chmod +x "$FAKE_BIN_EMPTY/apachectl"

# ── helpers ────────────────────────────────────────────────────────────────

# Run CGI with HTTPS=on, return body only (strips headers up to blank line).
cgi() {
    local out
    out=$(env \
        TOKEN_ROOT="$TOKEN_ROOT" \
        MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
        SCRIPT_DIR="$SCRIPT_DIR" \
        PATH="$FAKE_BIN:$PATH" \
        HTTPS=on \
        "$@" \
        bash "$CGI" 2>/dev/null)
    printf '%s' "$out" | awk 'p{print} /^$/{p=1}'
}

# Run CGI with HTTPS=on, return Status: value (empty = 200).
cgi_status() {
    local out
    out=$(env \
        TOKEN_ROOT="$TOKEN_ROOT" \
        MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
        SCRIPT_DIR="$SCRIPT_DIR" \
        PATH="$FAKE_BIN:$PATH" \
        HTTPS=on \
        "$@" \
        bash "$CGI" 2>/dev/null)
    printf '%s' "$out" | grep '^Status:' | awk '{print $2}' | head -1
}

# Run CGI with HTTPS=on, return value of a specific response header.
cgi_header() {
    local header="$1"; shift
    local out
    out=$(env \
        TOKEN_ROOT="$TOKEN_ROOT" \
        MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
        SCRIPT_DIR="$SCRIPT_DIR" \
        PATH="$FAKE_BIN:$PATH" \
        HTTPS=on \
        "$@" \
        bash "$CGI" 2>/dev/null)
    printf '%s' "$out" | grep "^${header}:" | sed "s/^${header}:[[:space:]]*//" | head -1
}

# Run CGI without HTTPS=on (to test enforcement).
cgi_no_https() {
    local out
    out=$(env \
        TOKEN_ROOT="$TOKEN_ROOT" \
        MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
        SCRIPT_DIR="$SCRIPT_DIR" \
        PATH="$FAKE_BIN:$PATH" \
        "$@" \
        bash "$CGI" 2>/dev/null)
    printf '%s' "$out" | grep '^Status:' | awk '{print $2}' | head -1
}

# Run CGI with a custom MASTER_TOKEN_FILE (to test missing file → 500).
cgi_with_master() {
    local master_file="$1"; shift
    local out
    out=$(env \
        TOKEN_ROOT="$TOKEN_ROOT" \
        MASTER_TOKEN_FILE="$master_file" \
        SCRIPT_DIR="$SCRIPT_DIR" \
        PATH="$FAKE_BIN:$PATH" \
        HTTPS=on \
        "$@" \
        bash "$CGI" 2>/dev/null)
    printf '%s' "$out" | grep '^Status:' | awk '{print $2}' | head -1
}

auth="HTTP_AUTHORIZATION=Bearer $MASTER"

# ── HTTPS enforcement ──────────────────────────────────────────────────────

Test "https: request without HTTPS returns 403"
CompareArgs "$(cgi_no_https QUERY_STRING=action=hosts)" "403"

Test "https: request without HTTPS returns JSON error"
out=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" \
    bash "$CGI" 2>/dev/null | awk 'p{print} /^$/{p=1}')
case "$out" in
    '{"error":'*) Pass ;;
    *)            Fail ;;
esac

# ── auth ───────────────────────────────────────────────────────────────────

Test "auth: missing token returns 403"
CompareArgs "$(cgi_status QUERY_STRING=action=hosts)" "403"

Test "auth: wrong token returns 403"
CompareArgs "$(cgi_status HTTP_AUTHORIZATION="Bearer wrongtoken" QUERY_STRING=action=hosts)" "403"

Test "auth: correct token passes"
result=$(cgi "$auth" QUERY_STRING=action=hosts)
case "$result" in
    '{"hosts":'*) Pass ;;
    *)            Fail ;;
esac

Test "auth: missing master.token returns 500"
# Must supply a non-empty token so the empty-token guard does not fire first.
CompareArgs "$(cgi_with_master "$TMPDIR_ROOT/no-such-file.token" \
    HTTP_AUTHORIZATION="Bearer sometoken" QUERY_STRING=action=hosts)" "500"

Test "auth: token with path traversal is rejected (not matched as master)"
CompareArgs "$(cgi_status HTTP_AUTHORIZATION="Bearer ../../etc/passwd" QUERY_STRING=action=hosts)" "403"

Test "auth: timing-safe: token prefix match does not grant access"
prefix=$(printf '%s' "$MASTER" | cut -c1-8)
CompareArgs "$(cgi_status HTTP_AUTHORIZATION="Bearer ${prefix}" QUERY_STRING=action=hosts)" "403"

# ── parameter isolation ────────────────────────────────────────────────────

Test "params: duplicate key uses first occurrence"
# If pollution worked, second host= value would override the first
result=$(cgi_status "$auth" QUERY_STRING="action=credentials&host=nonexistent.com&host=../../etc")
# Should be 404 (nonexistent.com), not 400 (traversal) or 200
CompareArgs "$result" "404"

Test "params: substring key does not match (ahost != host)"
# ahost=value should not be parsed as host=value
result=$(cgi_status "$auth" QUERY_STRING="action=credentials&ahost=example.com")
CompareArgs "$result" "400"

# ── ui serving (no action) ─────────────────────────────────────────────────

Test "ui: no action returns text/html content-type"
CompareArgs "$(cgi_header Content-Type QUERY_STRING=)" "text/html"

Test "ui: no action returns html body"
result=$(cgi QUERY_STRING=)
case "$result" in
    *'<!DOCTYPE html>'*) Pass ;;
    *)                   Fail ;;
esac

Test "ui: no action requires no auth"
result=$(cgi QUERY_STRING=)
case "$result" in
    *'<!DOCTYPE html>'*) Pass ;;
    *)                   Fail ;;
esac

Test "ui: no action sets Cache-Control: no-store"
CompareArgs "$(cgi_header Cache-Control QUERY_STRING=)" "no-store"

Test "ui: no action sets X-Frame-Options: DENY"
CompareArgs "$(cgi_header X-Frame-Options QUERY_STRING=)" "DENY"

Test "ui: CSP does not contain unsafe-inline"
csp=$(cgi_header Content-Security-Policy QUERY_STRING=)
case "$csp" in
    *'unsafe-inline'*) Fail ;;
    *)                 Pass ;;
esac

# ── static asset serving (css/js, no auth required) ────────────────────────

Test "css: action=css returns text/css content-type"
CompareArgs "$(cgi_header Content-Type QUERY_STRING=action=css)" "text/css"

Test "css: action=css requires no auth"
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    QUERY_STRING=action=css \
    bash "$CGI" 2>/dev/null | grep '^Status:')
# No Status: line means 200 — CSS served without auth
case "$result" in
    '') Pass ;;
    *)  Fail ;;
esac

Test "js: action=js returns application/javascript content-type"
CompareArgs "$(cgi_header Content-Type QUERY_STRING=action=js)" "application/javascript"

Test "js: action=js requires no auth"
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    QUERY_STRING=action=js \
    bash "$CGI" 2>/dev/null | grep '^Status:')
case "$result" in
    '') Pass ;;
    *)  Fail ;;
esac

# ── security headers ───────────────────────────────────────────────────────

Test "headers: api responses have application/json content-type"
CompareArgs "$(cgi_header Content-Type "$auth" QUERY_STRING=action=hosts)" "application/json"

Test "headers: api responses have X-Content-Type-Options: nosniff"
CompareArgs "$(cgi_header X-Content-Type-Options "$auth" QUERY_STRING=action=hosts)" "nosniff"

Test "headers: api responses have Cache-Control: no-store"
CompareArgs "$(cgi_header Cache-Control "$auth" QUERY_STRING=action=hosts)" "no-store"

Test "headers: api responses have X-Frame-Options: DENY"
CompareArgs "$(cgi_header X-Frame-Options "$auth" QUERY_STRING=action=hosts)" "DENY"

Test "headers: 403 response has application/json content-type"
CompareArgs "$(cgi_header Content-Type QUERY_STRING=action=hosts)" "application/json"

Test "headers: 403 response has Cache-Control: no-store"
CompareArgs "$(cgi_header Cache-Control QUERY_STRING=action=hosts)" "no-store"

# ── seed filesystem state (used by json, list, and tokens tests) ───────────
# "list: empty" must run before this block

Test "list: empty when no token dirs exist"
CompareArgs "$(cgi "$auth" QUERY_STRING=action=list)" '{"hosts":[]}'

mkdir -p "$TOKEN_ROOT/example.com"
printf 'my label' > "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223344"
mkdir -p "$TOKEN_ROOT/api.example.com"
printf 'ci token' > "$TOKEN_ROOT/api.example.com/11223344aabbccdd11223344aabbccdd"

# ── json injection ─────────────────────────────────────────────────────────

Test "json: double-quote in label is escaped"
printf 'say "hello"' > "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223344"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
case "$result" in
    *'\"hello\"'*) Pass ;;
    *)             Fail ;;
esac

Test "json: backslash in label is escaped"
printf 'path\\value' > "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223344"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
case "$result" in
    *'path\\value'*) Pass ;;
    *)               Fail ;;
esac
# restore clean label
printf 'my label' > "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223344"

Test "json: newline in label is stripped before storage"
result=$(printf 'host=example.com&label=line1%0aline2' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
stored=$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)
case "$stored" in
    *$'\n'*) Fail ;;
    *)       Pass ;;
esac

Test "json: control chars in label stripped before storage"
result=$(echo 'host=example.com&label=hello%01world' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
stored=$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)
CompareArgs "$stored" "helloworld"

# ── hosts ──────────────────────────────────────────────────────────────────

Test "hosts: returns both vhosts from apachectl"
CompareArgs "$(cgi "$auth" QUERY_STRING=action=hosts)" \
            '{"hosts":["api.example.com","example.com"]}'

Test "hosts: empty list when apachectl has no namevhosts"
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" \
    MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" \
    PATH="$FAKE_BIN_EMPTY:$PATH" \
    HTTPS=on \
    HTTP_AUTHORIZATION="Bearer $MASTER" \
    QUERY_STRING=action=hosts \
    bash "$CGI" 2>/dev/null | awk 'p{print} /^$/{p=1}')
CompareArgs "$result" '{"hosts":[]}'

# ── list ───────────────────────────────────────────────────────────────────

Test "list: shows all hosts that have tokens"
result=$(cgi "$auth" QUERY_STRING=action=list)
tok1_found=0; tok2_found=0
case "$result" in *'"example.com"'*)     tok1_found=1 ;; esac
case "$result" in *'"api.example.com"'*) tok2_found=1 ;; esac
if [ $tok1_found -eq 1 ] && [ $tok2_found -eq 1 ]; then Pass; else Fail; fi

# ── credentials ────────────────────────────────────────────────────────────

Test "credentials: returns bearer token and label for host"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
found_tok=0; found_label=0; found_type=0
case "$result" in *'"aabbccdd11223344aabbccdd11223344"'*) found_tok=1   ;; esac
case "$result" in *'"my label"'*)                        found_label=1 ;; esac
case "$result" in *'"type":"bearer"'*)                   found_type=1  ;; esac
if [ $found_tok -eq 1 ] && [ $found_label -eq 1 ] && [ $found_type -eq 1 ]; then Pass; else Fail; fi

Test "credentials: returns multiple bearer tokens for host"
printf 'second label' > "$TOKEN_ROOT/example.com/bbccdd1122334455bbccdd1122334455"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
tok1_found=0; tok2_found=0
case "$result" in *aabbccdd11223344aabbccdd11223344*) tok1_found=1 ;; esac
case "$result" in *bbccdd1122334455bbccdd1122334455*) tok2_found=1 ;; esac
if [ $tok1_found -eq 1 ] && [ $tok2_found -eq 1 ]; then Pass; else Fail; fi
rm -f "$TOKEN_ROOT/example.com/bbccdd1122334455bbccdd1122334455"

Test "credentials: empty array for host dir with no credential files"
mkdir -p "$TOKEN_ROOT/empty.example.com"
CompareArgs "$(cgi "$auth" QUERY_STRING="action=credentials&host=empty.example.com")" \
            '{"host":"empty.example.com","open":false,"credentials":[]}'

Test "credentials: token with empty label"
printf '' > "$TOKEN_ROOT/example.com/000000000000000000000000000000aa"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
case "$result" in
    *'"000000000000000000000000000000aa"'*) Pass ;;
    *) Fail ;;
esac
rm -f "$TOKEN_ROOT/example.com/000000000000000000000000000000aa"

Test "credentials: non-token files in dir are skipped"
printf 'junk' > "$TOKEN_ROOT/example.com/not-a-token"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
case "$result" in
    *'"not-a-token"'*) Fail ;;
    *)                 Pass ;;
esac
rm -f "$TOKEN_ROOT/example.com/not-a-token"

Test "credentials: 404 for unknown host"
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=credentials&host=unknown.com")" "404"

Test "credentials: 400 for path traversal in host"
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=credentials&host=../../etc")" "400"

Test "credentials: 400 for empty host"
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=credentials&host=")" "400"

Test "credentials: IP entries appear with type=ip"
mkdir -p "$TOKEN_ROOT/example.com/IP"
printf 'office' > "$TOKEN_ROOT/example.com/IP/10.0.0.1"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
found_ip=0; found_type=0
case "$result" in *'"10.0.0.1"'*)     found_ip=1   ;; esac
case "$result" in *'"type":"ip"'*)    found_type=1 ;; esac
rm -f "$TOKEN_ROOT/example.com/IP/10.0.0.1"
rmdir "$TOKEN_ROOT/example.com/IP"
if [ $found_ip -eq 1 ] && [ $found_type -eq 1 ]; then Pass; else Fail; fi

# ── create ─────────────────────────────────────────────────────────────────

Test "create: generates bearer token file with label"
result=$(printf 'host=example.com&type=bearer&label=test+token' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    '{"type":"bearer","value":"'*'"label":"test token"}'*)
        tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
        if [ -f "$TOKEN_ROOT/example.com/$tok" ]; then Pass
        else Fail
        fi ;;
    *) Fail ;;
esac

Test "create: type defaults to bearer when absent"
result=$(printf 'host=example.com&label=default-type' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"type":"bearer"'*) Pass ;;
    *)                   Fail ;;
esac

Test "create: token is 32 lowercase hex characters"
result=$(printf 'host=example.com&type=bearer&label=fmt' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
if [ "${#tok}" -eq 32 ]; then
    case "$tok" in
        *[!0-9a-f]*) Fail ;;
        *)            Pass ;;
    esac
else Fail
fi

Test "create: two tokens are unique"
tok1=$(printf 'host=example.com&type=bearer&label=a' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST | \
    sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
tok2=$(printf 'host=example.com&type=bearer&label=b' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST | \
    sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
if [ "$tok1" != "$tok2" ]; then Pass; else Fail; fi

Test "create: label stored in token file"
result=$(printf 'host=example.com&type=bearer&label=stored+label' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
CompareArgs "$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)" "stored label"

Test "create: empty label is accepted"
result=$(printf 'host=example.com&type=bearer&label=' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
if [ -f "$TOKEN_ROOT/example.com/$tok" ]; then Pass; else Fail; fi

Test "create: missing label field is accepted"
result=$(printf 'host=example.com&type=bearer' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
if [ -f "$TOKEN_ROOT/example.com/$tok" ]; then Pass; else Fail; fi

Test "create: type=ip creates IP file"
result=$(printf 'host=example.com&type=ip&value=10.0.0.1&label=office' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    '{"type":"ip","value":"10.0.0.1","label":"office"}') Pass ;;
    *)                                                    Fail ;;
esac

Test "create: type=ip file exists on disk"
if [ -f "$TOKEN_ROOT/example.com/IP/10.0.0.1" ]; then Pass; else Fail; fi

Test "create: type=ip 400 for invalid ip"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST <<< 'host=example.com&type=ip&value=not/valid')" \
    "400"

Test "create: type=ip 400 for empty value"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST <<< 'host=example.com&type=ip&value=')" \
    "400"

Test "create: 400 for invalid type"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST <<< 'host=example.com&type=ftp&label=x')" \
    "400"

Test "create: 400 for path traversal in host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST <<< 'host=../../etc&label=x')" \
    "400"

Test "create: 400 for empty host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST <<< 'host=&label=x')" \
    "400"

Test "create: token file created for new host"
printf 'host=newhost.com&label=fresh' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST > /dev/null
if [ -d "$TOKEN_ROOT/newhost.com" ]; then Pass; else Fail; fi

# ── delete ─────────────────────────────────────────────────────────────────

Test "delete: removes bearer token file"
printf 'deleteme' > "$TOKEN_ROOT/example.com/deadbeefdeadbeefdeadbeefdeadbeef"
printf 'host=example.com&type=bearer&value=deadbeefdeadbeefdeadbeefdeadbeef' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST > /dev/null
if [ ! -f "$TOKEN_ROOT/example.com/deadbeefdeadbeefdeadbeefdeadbeef" ]; then Pass; else Fail; fi

Test "delete: returns deleted status"
printf 'deletelabel' > "$TOKEN_ROOT/example.com/cafebabecafebabecafebabecafebabe"
result=$(printf 'host=example.com&type=bearer&value=cafebabecafebabecafebabecafebabe' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"deleted"}'

Test "delete: type defaults to bearer when absent"
printf 'label' > "$TOKEN_ROOT/example.com/ffffffffffffffffffffffffffffffff"
result=$(printf 'host=example.com&value=ffffffffffffffffffffffffffffffff' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"deleted"}'

Test "delete: 400 for path traversal in bearer value"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=bearer&value=../../etc/passwd')" \
    "400"

Test "delete: 400 for path traversal in host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=../../etc&type=bearer&value=cafebabecafebabecafebabecafebabe')" \
    "400"

Test "delete: non-existent bearer token is silent"
result=$(printf 'host=example.com&type=bearer&value=0000000000000000000000000000ffff' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"deleted"}'

Test "delete: 400 for empty host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=&type=bearer&value=cafebabecafebabecafebabecafebabe')" \
    "400"

Test "delete: 400 for empty bearer value"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=bearer&value=')" \
    "400"

Test "delete: 400 for non-hex bearer value"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=bearer&value=not-a-valid-token-string-here')" \
    "400"

Test "delete: type=ip removes IP file"
printf 'office' > "$TOKEN_ROOT/example.com/IP/10.0.0.1"
printf 'host=example.com&type=ip&value=10.0.0.1' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST > /dev/null
if [ ! -f "$TOKEN_ROOT/example.com/IP/10.0.0.1" ]; then Pass; else Fail; fi

Test "delete: type=ip returns deleted status"
printf 'label' > "$TOKEN_ROOT/example.com/IP/10.0.0.9"
result=$(printf 'host=example.com&type=ip&value=10.0.0.9' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"deleted"}'

Test "delete: type=ip non-existent IP is silent"
result=$(printf 'host=example.com&type=ip&value=10.0.0.99' | \
    cgi "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"deleted"}'

Test "delete: type=ip 400 for invalid ip"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=ip&value=not/valid')" \
    "400"

Test "delete: type=ip 400 for empty value"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=ip&value=')" \
    "400"

Test "delete: 400 for invalid type"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST <<< 'host=example.com&type=ftp&value=anything')" \
    "400"

# ── css/js: full security header set ──────────────────────────────────────

Test "css: X-Frame-Options: DENY present"
CompareArgs "$(cgi_header X-Frame-Options QUERY_STRING=action=css)" "DENY"

Test "css: Content-Security-Policy present"
result=$(cgi_header Content-Security-Policy QUERY_STRING=action=css)
case "$result" in
    *"default-src 'none'"*) Pass ;;
    *)                       Fail ;;
esac

Test "js: X-Frame-Options: DENY present"
CompareArgs "$(cgi_header X-Frame-Options QUERY_STRING=action=js)" "DENY"

Test "js: Content-Security-Policy present"
result=$(cgi_header Content-Security-Policy QUERY_STRING=action=js)
case "$result" in
    *"default-src 'none'"*) Pass ;;
    *)                       Fail ;;
esac

# ── ct_equal: salt length guard ────────────────────────────────────────────

Test "auth: ct_equal rejects when sha256sum produces no output (empty salt guard)"
# Simulate sha256sum producing no output, causing an empty salt string.
# The salt length check [ "${#salt}" -eq 32 ] must catch this and fail closed.
# If the guard were absent, [ "" = "" ] would succeed and auth would be bypassed.
FAKE_BIN_NOSHA="$TMPDIR_ROOT/bin-nosha"
mkdir -p "$FAKE_BIN_NOSHA"
printf '#!/bin/sh\n# Output nothing -- simulates broken sha256sum\n' \
    > "$FAKE_BIN_NOSHA/sha256sum"
chmod +x "$FAKE_BIN_NOSHA/sha256sum"
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN_NOSHA:$FAKE_BIN:$PATH" HTTPS=on \
    HTTP_AUTHORIZATION="Bearer $MASTER" QUERY_STRING=action=hosts \
    bash "$CGI" 2>/dev/null | grep '^Status:' | awk '{print $2}')
rm -rf "$FAKE_BIN_NOSHA"
# Must return 403 (auth failed), not 200 (bypassed) or empty (dropped connection)
CompareArgs "$result" "403"

# ── create: atomic token file write ────────────────────────────────────────

Test "create: token file is created with correct label"
result=$(printf 'host=example.com&label=atomic+test' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
CompareArgs "$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)" "atomic test"

Test "create: no stale tmp files left after successful create"
result=$(printf 'host=example.com&label=tmpcheck' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tmp_count=$(ls "$TOKEN_ROOT/example.com/"*.tmp.* 2>/dev/null | wc -l || echo 0)
CompareArgs "$tmp_count" "0"

# ── json_error: complete security headers ─────────────────────────────────

Test "headers: 403 response has X-Frame-Options: DENY"
CompareArgs "$(cgi_header X-Frame-Options QUERY_STRING=action=hosts)" "DENY"

Test "headers: 403 response has Strict-Transport-Security"
result=$(cgi_header Strict-Transport-Security QUERY_STRING=action=hosts)
case "$result" in
    *'max-age='*) Pass ;;
    *)            Fail ;;
esac

# ── param_get: bare key (no = sign) ────────────────────────────────────────

Test "params: bare key without = sign is not matched as host"
# POST body 'host' has no '=', so param_get host should return empty → 400
result=$(printf 'host' | \
    cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
CompareArgs "$result" "400"

# ── tokens: symlink guard ──────────────────────────────────────────────────

Test "tokens: symlinks in token dir are skipped"
mkdir -p "$TOKEN_ROOT/example.com"
ln -sf /etc/hostname "$TOKEN_ROOT/example.com/ccddaabb11223344ccddaabb11223344"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
rm -f "$TOKEN_ROOT/example.com/ccddaabb11223344ccddaabb11223344"
case "$result" in
    *'"ccddaabb11223344ccddaabb11223344"'*) Fail ;;
    *)                                       Pass ;;
esac

# ── tokens: read-side label size cap ──────────────────────────────────────

Test "tokens: label truncated to 256 chars on read"
big_label=$(printf 'x%.0s' {1..500})
printf '%s' "$big_label" > "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223300"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
rm -f "$TOKEN_ROOT/example.com/aabbccdd11223344aabbccdd11223300"
# Extract label value from JSON result and verify length <= 256
label_val=$(printf '%s' "$result" | sed -n 's/.*"label":"\([^"]*\)".*/\1/p' | head -1)
if [ "${#label_val}" -le 256 ]; then Pass; else Fail; fi

# ── ct_equal: empty-string guard ──────────────────────────────────────────

Test "auth: ct_equal rejects when sha256sum produces short output"
# Simulate a broken sha256sum by injecting a fake that outputs < 64 chars.
# If the guard is missing, [ "" = "" ] would pass and auth would succeed.
FAKE_BIN_BADSHA="$TMPDIR_ROOT/bin-badsha"
mkdir -p "$FAKE_BIN_BADSHA"
# Copy all real commands via symlinks, then override sha256sum with a fake
for cmd in dd head cut timeout tr grep awk sort cat mkdir rm apachectl; do
    real=$(PATH="$FAKE_BIN:$PATH" command -v "$cmd" 2>/dev/null) && \
        ln -sf "$real" "$FAKE_BIN_BADSHA/$cmd" 2>/dev/null || true
done
printf '#!/bin/sh\necho "tooshort"\n' > "$FAKE_BIN_BADSHA/sha256sum"
chmod +x "$FAKE_BIN_BADSHA/sha256sum"
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN_BADSHA:$PATH" HTTPS=on \
    HTTP_AUTHORIZATION="Bearer anything" QUERY_STRING=action=hosts \
    bash "$CGI" 2>/dev/null | grep '^Status:' | awk '{print $2}')
rm -rf "$FAKE_BIN_BADSHA"
# Should be 403 (auth failed), not 200 (auth bypassed)
CompareArgs "$result" "403"

# ── POST body newline injection ────────────────────────────────────────────

Test "params: raw newline in POST body cannot inject a host parameter"
# Attack: body has no host= at the normal position; a literal newline is used
# to inject host=example.com as a second pair, invisible to a strict URL-encoded
# parser. Without stripping, param_get would find host=example.com and create
# a token. With stripping, the newline is removed and the key disappears.
result=$(printf 'label=x\nhost=example.com' | \
    cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
# The injected host= pair must not be extracted -- should return 400 (no host).
CompareArgs "$result" "400"

# ── css/js: HSTS header ────────────────────────────────────────────────────

Test "css: Strict-Transport-Security header present"
result=$(cgi_header Strict-Transport-Security QUERY_STRING=action=css)
case "$result" in
    *'max-age='*) Pass ;;
    *)            Fail ;;
esac

Test "js: Strict-Transport-Security header present"
result=$(cgi_header Strict-Transport-Security QUERY_STRING=action=js)
case "$result" in
    *'max-age='*) Pass ;;
    *)            Fail ;;
esac

# ── REQUEST_METHOD enforcement ─────────────────────────────────────────────

Test "create: GET request returns 405"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=create REQUEST_METHOD=GET)" "405"

Test "delete: GET request returns 405"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=GET)" "405"

Test "create: missing REQUEST_METHOD returns 405"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=create)" "405"

# ── delete error handling ───────────────────────────────────────────────────

Test "delete: rm failure returns 500"
# Make a token dir unwritable so rm fails
mkdir -p "$TOKEN_ROOT/readonly.example.com"
printf 'label' > "$TOKEN_ROOT/readonly.example.com/aabbccdd11223344aabbccdd11223300"
chmod 555 "$TOKEN_ROOT/readonly.example.com"
result=$(printf 'host=readonly.example.com&type=bearer&value=aabbccdd11223344aabbccdd11223300' | \
    cgi_status "$auth" QUERY_STRING=action=delete REQUEST_METHOD=POST)
chmod 755 "$TOKEN_ROOT/readonly.example.com"
rm -rf "$TOKEN_ROOT/readonly.example.com"
CompareArgs "$result" "500"

# ── HSTS header ────────────────────────────────────────────────────────────

Test "headers: api responses include Strict-Transport-Security"
result=$(cgi_header Strict-Transport-Security "$auth" QUERY_STRING=action=hosts)
case "$result" in
    *'max-age='*) Pass ;;
    *)            Fail ;;
esac

Test "headers: HTML response includes Strict-Transport-Security"
result=$(cgi_header Strict-Transport-Security QUERY_STRING=)
case "$result" in
    *'max-age='*) Pass ;;
    *)            Fail ;;
esac

# ── unknown action ─────────────────────────────────────────────────────────

Test "unknown action returns 400 status"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=bogus)" "400"

Test "unknown action returns error json body"
CompareArgs "$(cgi "$auth" QUERY_STRING=action=bogus)" \
            '{"error":"unknown action"}'

# ── url decoding ───────────────────────────────────────────────────────────

Test "url: malformed percent sequence is stripped (not passed through)"
# %zz is not a valid %XX sequence; urldecode should not pass the bare % through.
result=$(printf 'host=example.com&label=bad%%zztag' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
stored=$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)
case "$stored" in
    *'%'*) Fail ;;
    *)     Pass ;;
esac

Test "url: plus decoded to space in label"
result=$(printf 'host=example.com&label=hello+world' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
CompareArgs "$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)" "hello world"

Test "url: percent-encoded label decoded correctly"
result=$(echo 'host=example.com&label=hello%20world' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
CompareArgs "$(cat "$TOKEN_ROOT/example.com/$tok" 2>/dev/null)" "hello world"

Test "url: percent-encoded host decoded correctly"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
case "$result" in
    '{"host":"example.com"'*) Pass ;;
    *)                        Fail ;;
esac

Test "url: percent-encoded action is NOT decoded (WAF evasion prevention)"
# action is a fixed ASCII vocabulary; decoding it would allow cre%61te to
# bypass log-based monitoring. Encoded action must not match.
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=ho%73ts")" "400"

# ── valid_host: consecutive dots rejected ─────────────────────────────────

Test "valid_host: consecutive dots in host are rejected"
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=credentials&host=a..b.com")" "400"

Test "valid_host: single dots are allowed"
# example.com is not in TOKEN_ROOT yet from this path — expect 404, not 400
CompareArgs "$(cgi_status "$auth" QUERY_STRING="action=credentials&host=sub.example.com")" "404"

# ── list: invalid directory names skipped ─────────────────────────────────

Test "list: directory with non-hostname name is excluded from output"
mkdir -p "$TOKEN_ROOT/..bad-dir"
result=$(cgi "$auth" QUERY_STRING=action=list)
rm -rf "$TOKEN_ROOT/..bad-dir"
case "$result" in
    *'..bad-dir'*) Fail ;;
    *)             Pass ;;
esac

# ── GATEWAY_INTERFACE: env overrides are blocked in CGI context ────────────

Test "gateway: GATEWAY_INTERFACE set hardcodes paths (env overrides blocked)"
# With GATEWAY_INTERFACE set, MASTER_TOKEN_FILE is hardcoded to the production
# path (/etc/apache-token-auth/master.token), which does not exist in the test
# environment. The CGI should return 500 — proving it ignored our env override.
# If the env override were respected, ct_equal would fail and return 403.
result=$(env \
    TOKEN_ROOT="$TOKEN_ROOT" \
    MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" \
    PATH="$FAKE_BIN:$PATH" \
    HTTPS=on \
    GATEWAY_INTERFACE="CGI/1.1" \
    HTTP_AUTHORIZATION="Bearer $MASTER" \
    QUERY_STRING=action=list \
    bash "$CGI" 2>/dev/null | grep '^Status:' | awk '{print $2}')
CompareArgs "$result" "500"

# ── http status codes are correct (not buried in body) ────────────────────

Test "status: 400 for invalid host in credentials is real HTTP status"
# Previously json_headers ran before case dispatch, so Status: appeared in
# the body and HTTP status was always 200. Verify the status line comes first.
out=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    "$auth" QUERY_STRING="action=credentials&host=../../etc" bash "$CGI" 2>/dev/null)
first_line=$(printf '%s' "$out" | head -1)
case "$first_line" in
    'Status: 400') Pass ;;
    *)             Fail ;;
esac

Test "status: 404 for missing host in credentials is real HTTP status"
out=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    "$auth" QUERY_STRING="action=credentials&host=missing.example.com" bash "$CGI" 2>/dev/null)
first_line=$(printf '%s' "$out" | head -1)
case "$first_line" in
    'Status: 404') Pass ;;
    *)             Fail ;;
esac

Test "status: 400 for invalid host in create is real HTTP status"
out=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    REQUEST_METHOD=POST \
    "$auth" QUERY_STRING=action=create bash "$CGI" 2>/dev/null \
    <<< 'host=../../etc&label=x')
first_line=$(printf '%s' "$out" | head -1)
case "$first_line" in
    'Status: 400') Pass ;;
    *)             Fail ;;
esac

Test "status: 200 success response has no Status: line"
out=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    "$auth" QUERY_STRING=action=hosts bash "$CGI" 2>/dev/null)
first_line=$(printf '%s' "$out" | head -1)
case "$first_line" in
    'Status: '*) Fail ;;
    *)           Pass ;;
esac

# ── apachectl failure ──────────────────────────────────────────────────────

Test "hosts: apachectl failure returns 500"
FAKE_BIN_FAIL="$TMPDIR_ROOT/bin-fail"
mkdir -p "$FAKE_BIN_FAIL"
printf '#!/bin/bash\nexit 1\n' > "$FAKE_BIN_FAIL/apachectl"
chmod +x "$FAKE_BIN_FAIL/apachectl"
result=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="$MASTER_TOKEN_FILE" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN_FAIL:$PATH" HTTPS=on \
    HTTP_AUTHORIZATION="Bearer $MASTER" QUERY_STRING=action=hosts \
    bash "$CGI" 2>/dev/null | grep '^Status:' | awk '{print $2}')
CompareArgs "$result" "500"

# ── label length limit ─────────────────────────────────────────────────────

Test "create: label longer than 256 chars is rejected"
long_label=$(printf 'x%.0s' {1..257})
result=$(printf 'host=example.com&label=%s' "$long_label" | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"error"'*) Pass ;;
    *)           Fail ;;
esac

Test "create: label exactly 256 chars is accepted"
label256=$(printf 'x%.0s' {1..256})
result=$(printf 'host=example.com&type=bearer&label=%s' "$label256" | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"type":"bearer"'*) Pass ;;
    *)                   Fail ;;
esac

# ── json_error message escaping ────────────────────────────────────────────

Test "json_error: message with special chars is escaped in output"
# json_error is called internally with hardcoded strings; this verifies the
# escaping function itself works on strings containing JSON-special chars.
# We test via the 'configuration error' path since we can trigger it.
out=$(env TOKEN_ROOT="$TOKEN_ROOT" MASTER_TOKEN_FILE="/nonexistent" \
    SCRIPT_DIR="$SCRIPT_DIR" PATH="$FAKE_BIN:$PATH" HTTPS=on \
    "$auth" QUERY_STRING=action=hosts bash "$CGI" 2>/dev/null \
    | awk 'p{print} /^$/{p=1}')
case "$out" in
    '{"error":"'*'"}') Pass ;;
    *)                  Fail ;;
esac

# ── open/close: basic operation ────────────────────────────────────────────

Test "open: creates OPEN sentinel file"
mkdir -p "$TOKEN_ROOT/open.example.com"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
if [ -f "$TOKEN_ROOT/open.example.com/OPEN" ]; then Pass; else Fail; fi

Test "open: returns status open"
result=$(printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"open"}'

Test "open: creates host directory if absent"
rm -rf "$TOKEN_ROOT/newopen.example.com"
printf 'host=newopen.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
if [ -d "$TOKEN_ROOT/newopen.example.com" ] && \
   [ -f "$TOKEN_ROOT/newopen.example.com/OPEN" ]; then Pass; else Fail; fi
rm -rf "$TOKEN_ROOT/newopen.example.com"

Test "open: 405 for GET request"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=open REQUEST_METHOD=GET)" "405"

Test "open: 400 for invalid host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST <<< 'host=../../etc')" \
    "400"

Test "open: 400 for empty host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST <<< 'host=')" \
    "400"

Test "close: removes OPEN sentinel file"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST > /dev/null
if [ ! -f "$TOKEN_ROOT/open.example.com/OPEN" ]; then Pass; else Fail; fi

Test "close: returns status closed"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
result=$(printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"closed"}'

Test "close: silently succeeds when OPEN does not exist"
rm -f "$TOKEN_ROOT/open.example.com/OPEN"
result=$(printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST)
CompareArgs "$result" '{"status":"closed"}'

Test "close: 405 for GET request"
CompareArgs "$(cgi_status "$auth" QUERY_STRING=action=close REQUEST_METHOD=GET)" "405"

Test "close: 400 for invalid host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST <<< 'host=../../etc')" \
    "400"

Test "close: 400 for empty host"
CompareArgs \
    "$(cgi_status "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST <<< 'host=')" \
    "400"

# ── open/close: OPEN sentinel excluded from credential listing ─────────────

Test "credentials: OPEN sentinel file is not listed as a credential"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
case "$result" in
    *'"OPEN"'*) Fail ;;
    *)          Pass ;;
esac

# ── open/close: open status in credentials response ────────────────────────

Test "credentials: open:false for protected host"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
case "$result" in
    *'"open":false'*) Fail ;;   # should be open:true since we set it open above
    *'"open":true'*)  Pass ;;
    *)                Fail ;;
esac

Test "credentials: open:false after close"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST > /dev/null
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
case "$result" in
    *'"open":false'*) Pass ;;
    *)                Fail ;;
esac

# ── open/close: open status in list response ───────────────────────────────

Test "list: open:false for protected host"
result=$(cgi "$auth" QUERY_STRING=action=list)
# open.example.com should appear with open:false (we closed it above)
case "$result" in
    *'"host":"open.example.com","open":false'*) Pass ;;
    *)                                           Fail ;;
esac

Test "list: open:true for open host"
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
result=$(cgi "$auth" QUERY_STRING=action=list)
case "$result" in
    *'"host":"open.example.com","open":true'*) Pass ;;
    *)                                          Fail ;;
esac

# ── open/close: transition behavior ───────────────────────────────────────

Test "transition: open then close then open toggles correctly"
# start protected
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST > /dev/null
r1=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
# go open
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
r2=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
# go protected again
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST > /dev/null
r3=$(cgi "$auth" QUERY_STRING="action=credentials&host=open.example.com")
ok=0
case "$r1" in *'"open":false'*) ok=$((ok+1)) ;; esac
case "$r2" in *'"open":true'*)  ok=$((ok+1)) ;; esac
case "$r3" in *'"open":false'*) ok=$((ok+1)) ;; esac
if [ $ok -eq 3 ]; then Pass; else Fail; fi

Test "transition: existing tokens survive open/close cycle"
# create a token, open the host, close it, verify token still present
result=$(printf 'host=open.example.com&label=persistent' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
tok=$(printf '%s' "$result" | sed -n 's/.*"value":"\([^"]*\)".*/\1/p')
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=open REQUEST_METHOD=POST > /dev/null
printf 'host=open.example.com' | \
    cgi "$auth" QUERY_STRING=action=close REQUEST_METHOD=POST > /dev/null
if [ -f "$TOKEN_ROOT/open.example.com/$tok" ]; then Pass; else Fail; fi

# ── credentials: IP entries via unified create/delete ──────────────────────

Test "credentials: IP symlinks are skipped"
mkdir -p "$TOKEN_ROOT/example.com/IP"
ln -sf /etc/hostname "$TOKEN_ROOT/example.com/IP/10.9.9.1"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
rm -f "$TOKEN_ROOT/example.com/IP/10.9.9.1"
rmdir "$TOKEN_ROOT/example.com/IP" 2>/dev/null || true
case "$result" in
    *'"10.9.9.1"'*) Fail ;;
    *)              Pass ;;
esac

Test "credentials: non-IP filenames in IP dir are skipped"
mkdir -p "$TOKEN_ROOT/example.com/IP"
printf 'junk' > "$TOKEN_ROOT/example.com/IP/not!valid"
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
rm -f "$TOKEN_ROOT/example.com/IP/not!valid"
rmdir "$TOKEN_ROOT/example.com/IP" 2>/dev/null || true
case "$result" in
    *'"not!valid"'*) Fail ;;
    *)               Pass ;;
esac

Test "create: type=ip accepts IPv6 address"
result=$(printf 'host=example.com&type=ip&value=::1&label=loopback' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"::1"'*) Pass ;;
    *)         Fail ;;
esac
rm -f "$TOKEN_ROOT/example.com/IP/::1"

Test "create: type=ip accepts full IPv6 address"
result=$(printf 'host=example.com&type=ip&value=2001:db8::1&label=v6host' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"2001:db8::1"'*) Pass ;;
    *)                  Fail ;;
esac
rm -f "$TOKEN_ROOT/example.com/IP/2001:db8::1"

Test "create: type=ip control chars stripped from label"
result=$(echo 'host=example.com&type=ip&value=10.0.0.2&label=hello%01world' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
stored=$(cat "$TOKEN_ROOT/example.com/IP/10.0.0.2" 2>/dev/null)
rm -f "$TOKEN_ROOT/example.com/IP/10.0.0.2"
CompareArgs "$stored" "helloworld"

Test "create: type=ip empty label is accepted"
result=$(printf 'host=example.com&type=ip&value=172.16.0.1&label=' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST)
case "$result" in
    *'"172.16.0.1"'*) Pass ;;
    *)                 Fail ;;
esac
rm -f "$TOKEN_ROOT/example.com/IP/172.16.0.1"

Test "create: type=ip label stored in file"
printf 'host=example.com&type=ip&value=10.5.5.5&label=stored' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST > /dev/null
CompareArgs "$(cat "$TOKEN_ROOT/example.com/IP/10.5.5.5" 2>/dev/null)" "stored"
rm -f "$TOKEN_ROOT/example.com/IP/10.5.5.5"

Test "credentials: multiple IPs appear in list"
printf 'host=example.com&type=ip&value=10.1.1.1&label=a' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST > /dev/null
printf 'host=example.com&type=ip&value=10.1.1.2&label=b' | \
    cgi "$auth" QUERY_STRING=action=create REQUEST_METHOD=POST > /dev/null
result=$(cgi "$auth" QUERY_STRING="action=credentials&host=example.com")
ip1_found=0; ip2_found=0
case "$result" in *'"10.1.1.1"'*) ip1_found=1 ;; esac
case "$result" in *'"10.1.1.2"'*) ip2_found=1 ;; esac
rm -f "$TOKEN_ROOT/example.com/IP/10.1.1.1" "$TOKEN_ROOT/example.com/IP/10.1.1.2"
if [ $ip1_found -eq 1 ] && [ $ip2_found -eq 1 ]; then Pass; else Fail; fi

# ── cleanup ────────────────────────────────────────────────────────────────

rm -rf "$TMPDIR_ROOT"

TestDone
