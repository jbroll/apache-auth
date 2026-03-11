Below is a minimalist architecture specifically designed for:

Apache virtual hosts

Apache reverse proxy hosts

Bearer token authentication

filesystem token store

shell scripting only

no external dependencies

no daemon processes

The design intentionally leverages Apache for everything heavy: HTTP, TLS, routing, concurrency.

Architecture Overview

The system has four major components.

Apache virtual host discovery

Filesystem token database

Apache authentication include files

Bash CGI admin interface

All logic is implemented with POSIX shell scripts.

High Level Flow

System startup or admin action performs the following workflow.

Discover Apache virtual hosts.

Generate authentication configuration fragments.

Store tokens in filesystem directories.

Reload Apache configuration.

Admin users interact through a small web interface protected by a master bearer token.

Directory Layout

Example installation layout.

/opt/apache-token-auth
    admin.cgi
    lib.sh
    scan_vhosts.sh
    create_token.sh
    delete_token.sh
    rebuild_config.sh

/etc/apache-token-auth
    master.token
    tokens/

        example.com/
        api.example.com/

/etc/apache-token-auth/tokens/example.com
    token1
    token2

/etc/apache-token-auth/tokens/api.example.com
    tokenA

Apache configuration fragments live in:

/etc/apache-token-auth/apache/
Apache Integration

Each virtual host includes an authentication fragment.

Example virtual host:

<VirtualHost *:443>
    ServerName api.example.com

    Include /etc/apache-token-auth/apache/api.example.com.conf
</VirtualHost>
Generated Apache Authentication Fragment

For each host a file is generated.

Example:

/etc/apache-token-auth/apache/api.example.com.conf

Contents:

RewriteEngine On

RewriteCond %{HTTP:Authorization} ^Bearer\s+(.+)$
RewriteCond /etc/apache-token-auth/tokens/api.example.com/%1 -f
RewriteRule ^ - [L]

RewriteRule ^ - [F]

Logic:

Extract bearer token.

Check if a file exists matching the token.

Allow request if file exists.

Otherwise return HTTP 403.

This provides:

constant time lookup

instant revocation

no database

no memory state

Token Model

Each token is simply a file.

Example:

/etc/apache-token-auth/tokens/api.example.com/7f9e3c2a

Deleting the file revokes the token immediately.

Admin API

The CGI admin interface exposes minimal operations.

Endpoints:

GET  /cgi-bin/admin.cgi?action=hosts
POST /cgi-bin/admin.cgi?action=create
POST /cgi-bin/admin.cgi?action=delete

All requests must include:

Authorization: Bearer MASTER_TOKEN

The master token is stored in:

/etc/apache-token-auth/master.token
Virtual Host Discovery

Discovery is performed via:

apachectl -S

This command outputs all configured virtual hosts.

The script parses:

port 443 namevhost example.com
port 443 namevhost api.example.com
Apache Reload Strategy

After token creation or deletion:

apachectl configtest && systemctl reload apache2

Reload is sufficient since only configuration fragments change.

Security Properties

Advantages:

tokens never appear in Apache config

revocation is instant

minimal attack surface

filesystem permissions protect tokens

master token controls admin API

Recommended permissions:

root:root
chmod 700 /etc/apache-token-auth
Core Library Script

File:

/opt/apache-token-auth/lib.sh
#!/usr/bin/env bash

TOKEN_ROOT="/etc/apache-token-auth/tokens"
MASTER_TOKEN_FILE="/etc/apache-token-auth/master.token"
APACHE_FRAGMENT_DIR="/etc/apache-token-auth/apache"

json_header() {
    echo "Content-Type: application/json"
    echo
}

read_master_token() {
    cat "$MASTER_TOKEN_FILE"
}

auth_admin() {
    header="$HTTP_AUTHORIZATION"

    token=$(echo "$header" | sed -n 's/^Bearer //p')
    master=$(read_master_token)

    if [ "$token" != "$master" ]; then
        echo "Status: 403"
        echo
        echo "forbidden"
        exit 1
    fi
}

generate_token() {
    head -c 32 /dev/urandom | sha256sum | cut -c1-32
}

list_hosts() {
    apachectl -S 2>/dev/null \
        | grep namevhost \
        | awk '{print $4}' \
        | sort -u
}
Create Token Script

File:

/opt/apache-token-auth/create_token.sh
#!/usr/bin/env bash

. ./lib.sh

host="$1"

token=$(generate_token)

mkdir -p "$TOKEN_ROOT/$host"

touch "$TOKEN_ROOT/$host/$token"

echo "$token"
Delete Token Script

File:

/opt/apache-token-auth/delete_token.sh
#!/usr/bin/env bash

. ./lib.sh

host="$1"
token="$2"

rm -f "$TOKEN_ROOT/$host/$token"
Apache Config Builder

File:

/opt/apache-token-auth/rebuild_config.sh
#!/usr/bin/env bash

. ./lib.sh

mkdir -p "$APACHE_FRAGMENT_DIR"

for host in $(list_hosts)
do
cat > "$APACHE_FRAGMENT_DIR/$host.conf" <<EOF
RewriteEngine On

RewriteCond %{HTTP:Authorization} ^Bearer\\s+(.+)\$
RewriteCond $TOKEN_ROOT/$host/%1 -f
RewriteRule ^ - [L]

RewriteRule ^ - [F]
EOF

done

apachectl configtest && systemctl reload apache2
Admin CGI Script

File:

/usr/lib/cgi-bin/token-admin.cgi
#!/usr/bin/env bash

SCRIPT_DIR="/opt/apache-token-auth"
. "$SCRIPT_DIR/lib.sh"

auth_admin

action=$(echo "$QUERY_STRING" | sed -n 's/.*action=\([^&]*\).*/\1/p')

json_header

case "$action" in

hosts)

    echo "{ \"hosts\": ["

    first=1
    for h in $(list_hosts)
    do
        if [ $first -eq 0 ]; then echo ","; fi
        printf "\"%s\"" "$h"
        first=0
    done

    echo "] }"
;;

create)

    read POSTDATA
    host=$(echo "$POSTDATA" | sed -n 's/.*host=\([^&]*\).*/\1/p')

    token=$("$SCRIPT_DIR/create_token.sh" "$host")

    "$SCRIPT_DIR/rebuild_config.sh"

    echo "{ \"token\":\"$token\" }"
;;

delete)

    read POSTDATA
    host=$(echo "$POSTDATA" | sed -n 's/.*host=\([^&]*\).*/\1/p')
    token=$(echo "$POSTDATA" | sed -n 's/.*token=\([^&]*\).*/\1/p')

    "$SCRIPT_DIR/delete_token.sh" "$host" "$token"

    "$SCRIPT_DIR/rebuild_config.sh"

    echo "{ \"status\":\"deleted\" }"
;;

*)

    echo "{ \"error\":\"unknown action\" }"

;;

esac
Complexity

Total code size is roughly:

~200 lines of shell

Dependencies:

bash
apache
coreutils

Nothing else.

Possible Future Enhancements

Optional improvements if needed later:

token expiration

per-token IP restriction

audit logs

rate limiting

host wildcard tokens

If you'd like, I can also show a much cleaner second-generation architecture that uses Apache mod_lua to validate tokens directly.

That version removes:

config regeneration

Apache reloads

most of the shell scripts

and ends up being even simpler operationally.