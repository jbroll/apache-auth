# apache-auth

Bearer token authentication for Apache virtual hosts. No daemons, no databases, no external dependencies — just Apache mod_rewrite and the filesystem.

## How it works

Each request is checked by a static Apache fragment (`token-auth.conf`) included in the vhost config:

1. If `tokens/<host>/.open` exists → allow (open access mode)
2. If `Authorization: Bearer <token>` matches a file at `tokens/<host>/<token>` → allow
3. Otherwise → 403

Token validation is a filesystem `stat` — no process is spawned, no reload needed for token changes.

## Files

| File | Purpose |
|------|---------|
| `token-auth.conf` | Apache `Include` fragment — drop into any vhost |
| `token-admin.cgi` | CGI admin API (bash, runs under Apache) |
| `index.html` / `admin.js` / `admin.css` | Web UI served by the CGI |

## Filesystem layout

```
/etc/apache-token-auth/
    master.token              # Admin API credential (640, root:www-data)
    tokens/
        api.example.com/
            a3f9...           # Token file — filename is the token, content is the label
            OPEN              # Sentinel: present = open access, absent = token required
        app.example.com/
            7c2b...
    apache/
        token-auth.conf       # Deployed copy of the auth fragment
/opt/apache-token-auth/
    token-admin.cgi           # CGI script
    index.html / admin.js / admin.css
/usr/lib/cgi-bin/
    token-admin.cgi           # Symlink or copy — Apache CGI location
```

## Apache vhost integration

Add one line to each vhost you want to protect:

```apache
<VirtualHost *:443>
    ServerName api.example.com
    ...
    Include /etc/apache-token-auth/apache/token-auth.conf
</VirtualHost>
```

No per-host config files. The single fragment uses `%{SERVER_NAME}` to resolve the token directory at request time.

## Admin API

All requests require `Authorization: Bearer <master-token>`.

| Method | Action | Body | Response |
|--------|--------|------|----------|
| `GET` | `hosts` | — | `{"hosts":["api.example.com",...]}` |
| `GET` | `list` | — | `{"hosts":[{"host":"...","open":bool},...]}` |
| `GET` | `tokens` | `host=...` | `{"host":"...","open":bool,"tokens":[{"token":"...","label":"..."},...]}` |
| `POST` | `create` | `host=...&label=...` | `{"token":"...","label":"..."}` |
| `POST` | `delete` | `host=...&token=...` | `{"status":"deleted"}` |
| `POST` | `open` | `host=...` | `{"status":"open"}` |
| `POST` | `close` | `host=...` | `{"status":"closed"}` |

Example:

```sh
MASTER=$(sudo cat /etc/apache-token-auth/master.token)
BASE="https://auth-admin.example.com/admin"

# Create a token
curl -s -X POST -H "Authorization: Bearer $MASTER" \
     -d "host=api.example.com&label=ci-deploy" "$BASE?action=create"

# Revoke it
curl -s -X POST -H "Authorization: Bearer $MASTER" \
     -d "host=api.example.com&token=a3f9..." "$BASE?action=delete"

# Open access temporarily (no token required)
curl -s -X POST -H "Authorization: Bearer $MASTER" \
     -d "host=api.example.com" "$BASE?action=open"
```

## Open vs protected

A host is in one of two states:

- **Open** — `tokens/<host>/.open` exists. Requests pass without a token. Useful during initial setup or maintenance.
- **Protected** — `OPEN` absent, at least one token exists. Requests must supply a valid bearer token.

Switching states is instant (filesystem operation, no Apache reload).

## Security notes

- **Constant-time comparison** for master token authentication (prevents timing attacks).
- **Path traversal protection** — `SERVER_NAME` is validated against an allowlist regex before use in filesystem paths.
- **Hardcoded `PATH`** in CGI context — prevents environment variable injection by a compromised Apache worker.
- **`umask 027`** — token files are `640` (root:www-data), not world-readable.
- **Atomic token writes** — `mktemp` + `mv` prevents partial token files being live.
- Tokens are 32 hex characters (128-bit entropy from `/dev/urandom`).

## Deployment

Use the `token_auth` module from [deploy.sh](https://github.com/johnbma/deploy.sh):

```sh
# deploy.conf
export DEPLOY_TYPES="token_auth"
export TOKEN_AUTH_ADMIN_DOMAIN="auth-admin.example.com"
```

Or install manually:

```sh
# Directories
sudo mkdir -p /opt/apache-token-auth /etc/apache-token-auth/tokens /etc/apache-token-auth/apache
sudo chown root:www-data /opt/apache-token-auth /etc/apache-token-auth /etc/apache-token-auth/apache
sudo chmod 750 /opt/apache-token-auth /etc/apache-token-auth /etc/apache-token-auth/apache

# Master token
sudo sh -c 'head -c32 /dev/urandom | sha256sum | cut -c1-32 > /etc/apache-token-auth/master.token'
sudo chmod 640 /etc/apache-token-auth/master.token
sudo chown root:www-data /etc/apache-token-auth/master.token

# Files
sudo cp token-auth.conf /etc/apache-token-auth/apache/
sudo cp token-admin.cgi /usr/lib/cgi-bin/
sudo chmod 750 /usr/lib/cgi-bin/token-admin.cgi
sudo chown root:www-data /usr/lib/cgi-bin/token-admin.cgi

# Apache modules
sudo a2enmod rewrite cgid

# Retrieve master token
sudo cat /etc/apache-token-auth/master.token
```

## Testing

```sh
bash test.sh
```

119 tests covering token lifecycle, open/close transitions, path traversal rejection, timing-safe auth, and CGI input validation.

## Dependencies

- bash
- Apache 2.4 with `mod_rewrite` and `mod_cgid`
- coreutils (`sha256sum`, `mktemp`)
