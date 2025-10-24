#!/usr/bin/env bash
# rotate_tokens.sh
# rotates tokens for node1,node2,node3 and client and writes into ./tokens/tokens.json
set -e
mkdir -p ./tokens
python3 token_manager.py --path ./tokens/tokens.json --rotate node1.local:8443 node2.local:8443 node3.local:8443 client.local --ttl 24
echo "Rotated tokens and stored in ./tokens/tokens.json"