#!/usr/bin/env bash
#
# Purpose: Run application (with ssl) using hypercorn
#

set -e


ROOTDIR=$( dirname "${BASH_SOURCE[0]}" )

cd "$ROOTDIR"

cat << "EOF"
+------------------------------------------------+
| Contest Data Server Media Authentication Proxy |
| Version 1.0.0                                  |
| Licensed under the MIT License                 |
+------------------------------------------------+

EOF

# Generate self-signed certificate
if [ -f "key.pem" ]; then
    echo "key.pem already exists, skipping..."
    echo ""
else
    echo "Generating self-signed certificate..."
    echo "For production use, please use a valid certificate."
    echo ""
    openssl req -x509 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
fi

hypercorn app:app --config file:config/hypercorn_config.py "$@"
