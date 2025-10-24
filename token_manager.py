#!/usr/bin/env python3
"""
token_manager.py
- Generates cryptographically-secure ephemeral tokens for nodes/clients.
- Persists to JSON (tokens.json) and rotates on demand.
- Provides a tiny HTTP endpoint to fetch token metadata (protected by admin token).
"""

import os, sys, json, time, argparse, secrets, hmac, hashlib
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

TOKENS_PATH = os.environ.get("TOKENS_PATH", "./tokens.json")
ADMIN_TOKEN = os.environ.get("TOKEN_MGR_ADMIN", None) or secrets.token_hex(24)

def load_tokens():
    if not os.path.exists(TOKENS_PATH):
        return {}
    with open(TOKENS_PATH, "r") as f:
        return json.load(f)

def persist_tokens(obj):
    with open(TOKENS_PATH + ".tmp", "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(TOKENS_PATH + ".tmp", TOKENS_PATH)

def generate_token_record(entity_id: str, ttl_hours: int = 24):
    tok = secrets.token_urlsafe(32)
    now = int(time.time())
    return {
        "id": entity_id,
        "token": tok,
        "created": now,
        "expires": now + ttl_hours * 3600,
        "ttl_hours": ttl_hours
    }

def rotate_tokens_for(list_of_ids, ttl_hours=24):
    tokens = load_tokens()
    changed = False
    for eid in list_of_ids:
        rec = generate_token_record(eid, ttl_hours)
        tokens[eid] = rec
        changed = True
    if changed:
        persist_tokens(tokens)
    return tokens

# tiny admin HTTP server to fetch tokens (requires admin token header)
class TokenHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization","")
        if auth != f"Bearer {ADMIN_TOKEN}":
            self.send_response(401); self.end_headers(); self.wfile.write(b"unauthorized"); return
        tokens = load_tokens()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.end_headers()
        self.wfile.write(json.dumps(tokens, indent=2).encode("utf-8"))

def run_server(port=9200):
    server = HTTPServer(("0.0.0.0", port), TokenHandler)
    print(f"Token manager admin API running on http://0.0.0.0:{port}  (ADMIN_TOKEN in env)")
    server.serve_forever()

def cli():
    p = argparse.ArgumentParser()
    p.add_argument("--rotate", nargs="+", help="list of entity ids to rotate tokens for")
    p.add_argument("--ttl", type=int, default=24, help="TTL hours")
    p.add_argument("--serve", action="store_true", help="run HTTP admin server (requires ADMIN_TOKEN env)")
    p.add_argument("--path", default=TOKENS_PATH, help="tokens.json path")
    args = p.parse_args()
    global TOKENS_PATH
    TOKENS_PATH = args.path
    if args.rotate:
        t = rotate_tokens_for(args.rotate, args.ttl)
        print(json.dumps(t, indent=2))
    if args.serve:
        if "TOKEN_MGR_ADMIN" not in os.environ:
            print("Please set TOKEN_MGR_ADMIN env for admin access (printed on start).")
        run_server()

if __name__ == "__main__":
    print("Token manager starting. ADMIN_TOKEN:", ADMIN_TOKEN)
    cli()