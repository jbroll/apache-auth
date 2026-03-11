# Apache Token Auth — Implementation Plan

## Goals

Minimalist bearer token authentication for Apache virtual and reverse proxy hosts.
Pure shell. No daemons. No external dependencies beyond bash, apache2, and coreutils.

---

## Design Principles

- Apache does all heavy lifting: HTTP, TLS, routing, concurrency
- Token state lives entirely on the filesystem
- Auth check is a single live filesystem stat — no config reload on token changes
- One static Apache fragment, one CGI script, token files — nothing else
- No code duplication across helper scripts; everything lives in the CGI

---

## Directory Layout

```
/opt/apache-token-auth/
    token-admin.cgi         # the only script

/etc/apache-token-auth/
    master.token            # master bearer token for admin API access
    tokens/                 # token store
        example.com/
            <token>         # filename is the token, content is the label
        api.example.com/
            <token>

/etc/apache-token-auth/apache/
    token-auth.conf         # single static fragment, included by all vhosts
```

The `tokens/<host>/` directories are created on first token creation for that host.
No pre-provisioning of host directories is required.

---

## Apache Integration

### Single Static Fragment

One file, never regenerated:

```
/etc/apache-token-auth/apache/token-auth.conf
```

```apache
RewriteEngine On

# Validate SERVER_NAME before use in filesystem path.
# With UseCanonicalName Off (Apache default), SERVER_NAME is derived from
# the Host: header and could contain path traversal sequences.
# Two conditions are required:
#   1. Allowlist: only letters, digits, dots, hyphens; must start and end
#      with an alphanumeric character (rejects leading/trailing dot or hyphen).
#   2. Denylist: reject consecutive dots which Apache's PCRE cannot exclude
#      with a pure positive regex without lookaheads.
RewriteCond %{SERVER_NAME} ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$
RewriteCond %{SERVER_NAME} !\.\.
RewriteCond %{HTTP:Authorization} ^Bearer\s+([a-f0-9]{32})$
RewriteCond /etc/apache-token-auth/tokens/%{SERVER_NAME}/%1 -f
RewriteRule ^ - [L]

RewriteRule ^ - [F]
```

`%{SERVER_NAME}` is resolved by Apache at request time, scoping token lookup
to the vhost being accessed. No per-host configuration files are needed.

### Vhost Include

Each protected vhost adds one line:

```apache
<VirtualHost *:443>
    ServerName api.example.com
    Include /etc/apache-token-auth/apache/token-auth.conf
</VirtualHost>
```

No Apache reload is ever needed for token create/delete operations. The `-f`
check is evaluated live. A reload is only needed when adding the `Include`
directive to a new vhost.

---

## Token Model

Each token is a file:

```
/etc/apache-token-auth/tokens/<hostname>/<token>
```

The file **content** is a human-readable label (e.g. `"mobile app prod"`).
This allows the admin API to return label information without a separate index.

Token generation:

```bash
head -c 32 /dev/urandom | sha256sum | cut -c1-32
```

Revocation is instant: delete the file.

---

## Host Discovery

The `hosts` endpoint returns all vhosts Apache is currently serving, parsed
from `apachectl -S`. This shows the full universe of hosts eligible for token
auth — not just hosts that already have tokens.

Parsing strategy:

```bash
apachectl -S 2>/dev/null \
    | grep 'namevhost' \
    | awk '{print $4}' \
    | sort -u
```

This is intentionally kept (vs. listing token directories) because the token
directory only contains hosts that already have tokens. The `hosts` endpoint
is meant to answer "what can I protect?" not "what is already protected?".

---

## Admin API

All requests must carry the master token:

```
Authorization: Bearer <master-token>
```

The master token is stored in `/etc/apache-token-auth/master.token` and is
never exposed through the API.

### Endpoints

| Method | Query              | Body                          | Description                        |
|--------|--------------------|-------------------------------|------------------------------------|
| GET    | `action=hosts`     | —                             | List all Apache vhosts             |
| GET    | `action=list`      | —                             | List hosts that have tokens        |
| GET    | `action=tokens`    | `host=<host>`                 | List tokens and labels for a host  |
| POST   | `action=create`    | `host=<host>&label=<label>`   | Create a new token for a host      |
| POST   | `action=delete`    | `host=<host>&token=<token>`   | Delete a specific token            |

All responses are JSON. HTTP status codes are used correctly (200, 400, 403, 500).

### Response Examples

**`action=hosts`**
```json
{ "hosts": ["example.com", "api.example.com"] }
```

**`action=list`**
```json
{ "hosts": ["api.example.com"] }
```

**`action=tokens`** (with `host=api.example.com`)
```json
{
  "host": "api.example.com",
  "tokens": [
    { "token": "7f9e3c2a...", "label": "mobile app prod" },
    { "token": "a1b2c3d4...", "label": "ci pipeline" }
  ]
}
```

**`action=create`** (POST `host=api.example.com&label=mobile+app+prod`)
```json
{ "token": "7f9e3c2a...", "label": "mobile app prod" }
```

**`action=delete`** (POST `host=api.example.com&token=7f9e3c2a...`)
```json
{ "status": "deleted" }
```

---

## Security

### Input Validation

All user-supplied `host`, `token`, and `label` values must be validated before
use in filesystem paths. A `valid_name()` guard rejects any value that:

- is empty
- contains `/`
- contains `..`

This prevents path traversal attacks.

Labels are free-form text but must not contain newlines (one line per token file).

### URL Decoding

POST bodies arrive URL-encoded. A pure-shell URL decoder handles `%XX` sequences
and `+` → space so that host names and labels with special characters are handled
correctly. This is done with a `urldecode()` function using only `printf` and `sed`.

### Permissions

The CGI runs as the Apache process user (`www-data` on Debian/Ubuntu).
That user requires read access to the master token and write access to the
token store. Separate these from general `www-data` processes using suexec
or a dedicated CGI user for stronger isolation.

**Minimum required permissions:**
```bash
# /etc/apache-token-auth itself: only root and the CGI user enter
chmod 750 /etc/apache-token-auth
chown root:www-data /etc/apache-token-auth

# master.token: readable by CGI user, not world-readable
chmod 640 /etc/apache-token-auth/master.token
chown root:www-data /etc/apache-token-auth/master.token

# token store: CGI user needs read+write+execute; Apache read+execute for -f check
# (both are www-data in the minimal deployment)
chmod 750 /etc/apache-token-auth/tokens
chown www-data:www-data /etc/apache-token-auth/tokens
```

**Recommended: suexec isolation**

Run the CGI under a dedicated user (e.g. `token-admin`) to prevent any other
`www-data` process (e.g. a compromised PHP app) from reading the master token
or manipulating the token store:

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin token-admin

# Assign ownership
chown root:token-admin /etc/apache-token-auth/master.token
chmod 640 /etc/apache-token-auth/master.token
chown token-admin:www-data /etc/apache-token-auth/tokens
chmod 750 /etc/apache-token-auth/tokens

# Apache suexec config in the admin vhost:
SuexecUserGroup token-admin token-admin
```

Token files are readable by the Apache process (`www-data`) for the `-f`
RewriteCond check. With the suexec model, `token-admin` owns the token files
and `www-data` gets group read access via the `750` directory permission.

### Master Token Generation

On first install:

```bash
head -c 32 /dev/urandom | sha256sum | cut -c1-32 > /etc/apache-token-auth/master.token
chmod 600 /etc/apache-token-auth/master.token
```

---

## Implementation: `token-admin.cgi`

Single script. No sourced libraries. No exec to helper scripts.

### Structure

```
1. Constants
2. urldecode()
3. valid_name()
4. json_error() — emit error JSON and exit
5. Master token auth check
6. Parse action from QUERY_STRING
7. Emit Content-Type header
8. case $action in
       hosts)   — apachectl -S parse
       list)    — list directories under TOKEN_ROOT
       tokens)  — list files under TOKEN_ROOT/$host with labels
       create)  — validate, mkdir -p, generate token, write label, echo token
       delete)  — validate, rm -f
       *)       — unknown action error
   esac
```

### Serving the UI

When `action` is absent from `QUERY_STRING`, the CGI emits `Content-Type: text/html`
and streams `index.html` from `SCRIPT_DIR`. The browser loads the page; all subsequent
calls go back to the same CGI URL with `?action=...`.

```bash
if [ -z "$action" ]; then
    printf 'Content-Type: text/html\n\n'
    cat "$SCRIPT_DIR/index.html"
    exit 0
fi
```

`index.html` sets `const API = window.location.pathname` so it automatically calls
back to the correct CGI path regardless of where it is deployed.

### Script

```bash
#!/usr/bin/env bash
set -euo pipefail

TOKEN_ROOT="/etc/apache-token-auth/tokens"
MASTER_TOKEN_FILE="/etc/apache-token-auth/master.token"

# --- helpers ---

urldecode() {
    printf '%b' "$(printf '%s' "$1" | sed 's/+/ /g; s/%\([0-9A-Fa-f][0-9A-Fa-f]\)/\\x\1/g')"
}

valid_name() {
    case "$1" in
        ''|*/*|*..*)  return 1;;
        *)            return 0;;
    esac
}

json_error() {
    printf 'Status: %s\nContent-Type: application/json\n\n{"error":"%s"}\n' "$1" "$2"
    exit 1
}

# --- auth ---

req_token=$(printf '%s' "${HTTP_AUTHORIZATION:-}" | sed -n 's/^Bearer //p')
master=$(cat "$MASTER_TOKEN_FILE")
[ "$req_token" = "$master" ] || json_error 403 "forbidden"

# --- routing ---

action=$(printf '%s' "${QUERY_STRING:-}" | sed -n 's/.*action=\([^&]*\).*/\1/p')

printf 'Content-Type: application/json\n\n'

case "$action" in

hosts)
    printf '{"hosts":['
    sep=''
    while IFS= read -r h; do
        printf '%s"%s"' "$sep" "$h"
        sep=','
    done < <(apachectl -S 2>/dev/null | grep 'namevhost' | awk '{print $4}' | sort -u)
    printf ']}\n'
    ;;

list)
    printf '{"hosts":['
    sep=''
    for d in "$TOKEN_ROOT"/*/; do
        [ -d "$d" ] || continue
        h=${d%/}; h=${h##*/}
        printf '%s"%s"' "$sep" "$h"
        sep=','
    done
    printf ']}\n'
    ;;

tokens)
    host=$(urldecode "$(printf '%s' "${QUERY_STRING:-}" | sed -n 's/.*host=\([^&]*\).*/\1/p')")
    valid_name "$host" || json_error 400 "invalid host"
    [ -d "$TOKEN_ROOT/$host" ] || json_error 404 "host not found"
    printf '{"host":"%s","tokens":[' "$host"
    sep=''
    for f in "$TOKEN_ROOT/$host/"*; do
        [ -f "$f" ] || continue
        tok=${f##*/}
        label=$(cat "$f")
        printf '%s{"token":"%s","label":"%s"}' "$sep" "$tok" "$label"
        sep=','
    done
    printf ']}\n'
    ;;

create)
    read -r POSTDATA
    host=$(urldecode "$(printf '%s' "$POSTDATA" | sed -n 's/.*host=\([^&]*\).*/\1/p')")
    label=$(urldecode "$(printf '%s' "$POSTDATA" | sed -n 's/.*label=\([^&]*\).*/\1/p')")
    valid_name "$host" || json_error 400 "invalid host"
    tok=$(head -c 32 /dev/urandom | sha256sum | cut -c1-32)
    mkdir -p "$TOKEN_ROOT/$host"
    printf '%s' "$label" > "$TOKEN_ROOT/$host/$tok"
    printf '{"token":"%s","label":"%s"}\n' "$tok" "$label"
    ;;

delete)
    read -r POSTDATA
    host=$(urldecode "$(printf '%s' "$POSTDATA" | sed -n 's/.*host=\([^&]*\).*/\1/p')")
    tok=$(urldecode "$(printf '%s' "$POSTDATA" | sed -n 's/.*token=\([^&]*\).*/\1/p')")
    valid_name "$host" || json_error 400 "invalid host"
    valid_name "$tok"  || json_error 400 "invalid token"
    rm -f "$TOKEN_ROOT/$host/$tok"
    printf '{"status":"deleted"}\n'
    ;;

*)
    printf '{"error":"unknown action"}\n'
    ;;

esac
```

---

## Installation Steps

1. Create directories and set permissions:
```bash
mkdir -p /opt/apache-token-auth
mkdir -p /etc/apache-token-auth/tokens
mkdir -p /etc/apache-token-auth/apache
chmod 700 /etc/apache-token-auth
chmod 750 /etc/apache-token-auth/tokens
chown root:www-data /etc/apache-token-auth/tokens
```

2. Generate master token:
```bash
head -c 32 /dev/urandom | sha256sum | cut -c1-32 > /etc/apache-token-auth/master.token
chmod 600 /etc/apache-token-auth/master.token
```

3. Write the static Apache fragment to `/etc/apache-token-auth/apache/token-auth.conf`.

4. Deploy `token-admin.cgi` to `/usr/lib/cgi-bin/token-admin.cgi`, set executable.

5. Configure an Apache vhost for the admin CGI, protected by the same token-auth fragment:
```apache
<VirtualHost *:443>
    ServerName auth-admin.internal
    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
    Include /etc/apache-token-auth/apache/token-auth.conf
</VirtualHost>
```

6. For each vhost to protect, add the include:
```apache
Include /etc/apache-token-auth/apache/token-auth.conf
```

7. Reload Apache once:
```bash
apachectl configtest && systemctl reload apache2
```

---

## What Was Removed vs. Original Design

| Original               | Reason Removed                                                      |
|------------------------|---------------------------------------------------------------------|
| `lib.sh`               | Inlined into single CGI; no benefit to a shared library at this size |
| `create_token.sh`      | 3 lines; inlined                                                    |
| `delete_token.sh`      | 2 lines; inlined                                                    |
| `rebuild_config.sh`    | Not needed; `-f` check is live; Apache fragment is static          |
| `scan_vhosts.sh`       | Duplicate of `list_hosts()` in lib.sh; inlined into CGI            |
| Per-host `.conf` files | Replaced by single fragment using `%{SERVER_NAME}`                  |
| Apache reload on token ops | Not needed; token files are live auth state                    |

---

## What Was Added vs. Original Design

| Addition               | Reason                                                              |
|------------------------|---------------------------------------------------------------------|
| `%{SERVER_NAME}` in fragment | Eliminates all per-host config generation                   |
| `action=list`          | Shows which hosts actually have tokens (distinct from `hosts`)      |
| `action=tokens`        | Lists tokens and labels for a specific host                         |
| Token labels           | Stored as file content; identifies what each token is for           |
| `urldecode()`          | Correctly handles POST body encoding                                |
| `valid_name()` guard   | Prevents path traversal on user-supplied host/token values          |
| Proper HTTP status codes | 400/403/404 instead of always 200                                |

---

## Possible Future Enhancements

- **Token expiration**: store expiry timestamp in token file alongside label;
  add a cron job or check-on-access to clean up expired tokens
- **Per-token IP restriction**: store allowed CIDR in token file; validate
  `%{REMOTE_ADDR}` with an additional RewriteCond
- **Audit log**: append to a log file on each admin action from the CGI
- **Rate limiting**: Apache `mod_ratelimit` or `mod_evasive` at the vhost level
- **Wildcard host tokens**: a `_default_` directory checked as fallback
- **mod_lua version**: eliminates CGI and shell entirely; validates tokens
  directly in a Lua handler with no Apache reload ever needed
