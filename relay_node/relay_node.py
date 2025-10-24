#!/usr/bin/env python3
"""
relay_node.py
Relay node service:
- HTTPS server (mTLS optional)
- Accepts JSON envelope { payload_b64, client_id }
- Validates Authorization: Bearer <token> against tokens.json (mounted)
- Decrypts envelope with per-node shared key (here: AES-GCM using node-local key file)
- Forwards request to target using httpx (http2 enabled)
- Re-encrypts response and returns { payload_b64 }
- Persists audit logs to node-local SQLite "node.db"
"""

import os, sys, json, base64, time, asyncio, pathlib, hashlib
from aiohttp import web
import aiosqlite
import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# CONFIG via env
DB_PATH = os.environ.get("NODE_DB", "/data/node.db")
TOKENS_FILE = os.environ.get("TOKENS_FILE", "/data/tokens.json")  # tokens provided by token_manager
SHARED_KEY_FILE = os.environ.get("SHARED_KEY_FILE", "/data/shared_key.bin")
LISTEN_HOST = os.environ.get("NODE_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("NODE_PORT", "8443"))
CERTFILE = os.environ.get("TLS_CERT","/certs/node.crt.pem")
KEYFILE = os.environ.get("TLS_KEY","/certs/node.key.pem")
CAFILE = os.environ.get("TLS_CA", "/certs/ca.crt.pem")  # for client cert validation if used

# utility crypto
def load_or_create_shared_key(path):
    if os.path.exists(path):
        return open(path,"rb").read()
    k = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path,"wb").write(k)
    return k

def aesgcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, b"")
    return nonce + ct

def aesgcm_decrypt(key: bytes, blob: bytes) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, b"")

# DB helpers
async def ensure_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = await aiosqlite.connect(path)
    await c.execute("""
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL, client_id TEXT, target TEXT, method TEXT, status INTEGER, latency REAL, reason TEXT, payload_digest TEXT
    )
    """)
    await c.commit()
    return c

# load token set
def load_tokens(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path,"r") as f:
            return json.load(f)
    except Exception:
        return {}

# minimal policy: disallow RFC1918 hosts
def is_private_host(host):
    if not host:
        return False
    try:
        if host.startswith("10.") or host.startswith("192.168.") or host.startswith("127."):
            return True
    except Exception:
        pass
    return False

async def handle_relay(request):
    # Authorization header required
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "):
        return web.json_response({"error":"unauthorized"},status=401)
    token = auth.split(" ",1)[1].strip()
    tokens = load_tokens(TOKENS_FILE)
    # token list maps entity->record; check presence
    found = False
    for eid, rec in tokens.items():
        if rec.get("token") == token:
            found = True
            client_entity = eid
            break
    if not found:
        return web.json_response({"error":"invalid token"}, status=403)

    db = request.app["db"]
    shared_key = request.app["shared_key"]
    try:
        env = await request.json()
        payload_b64 = env.get("payload_b64")
        client_id = env.get("client_id","unknown")
        if not payload_b64:
            await db.execute("INSERT INTO audit(ts,client_id,target,method,status,latency,reason,payload_digest) VALUES (?,?,?,?,?,?,?,?)",
                             (time.time(), client_id, None, None, 400, 0.0, "missing_payload", None))
            await db.commit()
            return web.json_response({"error":"missing payload"}, status=400)
        blob = base64.b64decode(payload_b64)
        plain = aesgcm_decrypt(shared_key, blob)
        reqobj = json.loads(plain.decode("utf-8"))
        # validate target
        target = reqobj.get("url")
        if not target or len(target) > 4096:
            await db.execute("INSERT INTO audit(ts,client_id,target,method,status,latency,reason,payload_digest) VALUES (?,?,?,?,?,?,?,?)",
                             (time.time(), client_id, target, reqobj.get("method"), 400, 0.0, "invalid_target", None))
            await db.commit()
            return web.json_response({"error":"invalid target"}, status=400)
        # policy block private hosts
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if is_private_host(parsed.hostname):
            await db.execute("INSERT INTO audit(ts,client_id,target,method,status,latency,reason,payload_digest) VALUES (?,?,?,?,?,?,?,?)",
                             (time.time(), client_id, target, reqobj.get("method"), 403, 0.0, "policy_block_private", None))
            await db.commit()
            return web.json_response({"error":"destination not allowed"}, status=403)
        method = reqobj.get("method","GET").upper()
        headers = reqobj.get("headers",{})
        body = base64.b64decode(reqobj.get("body_b64","")) if reqobj.get("body_b64") else b""
        # forward using httpx (http2 enabled)
        async with httpx.AsyncClient(http2=True, timeout=30.0) as client:
            start = time.time()
            resp = await client.request(method, target, headers=headers, content=body, follow_redirects=True)
            latency = time.time() - start
            resp_body = resp.content
            resp_obj = {"status": resp.status_code, "headers": dict(resp.headers), "body_b64": base64.b64encode(resp_body).decode("utf-8")}
            resp_plain = json.dumps(resp_obj).encode("utf-8")
            resp_blob = aesgcm_encrypt(shared_key, resp_plain)
            await db.execute("INSERT INTO audit(ts,client_id,target,method,status,latency,reason,payload_digest) VALUES (?,?,?,?,?,?,?,?)",
                             (time.time(), client_id, target, method, resp.status_code, latency, "ok", hashlib.sha256(resp_body).hexdigest()))
            await db.commit()
            return web.json_response({"payload_b64": base64.b64encode(resp_blob).decode("utf-8")})
    except Exception as e:
        try:
            await db.execute("INSERT INTO audit(ts,client_id,target,method,status,latency,reason,payload_digest) VALUES (?,?,?,?,?,?,?,?)",
                             (time.time(), env.get("client_id","unknown") if 'env' in locals() else "unknown", None, None, 500, 0.0, str(e), None))
            await db.commit()
        except Exception:
            pass
        return web.json_response({"error":"internal"}, status=500)

async def init_app():
    app = web.Application()
    app.add_routes([web.post("/relay", handle_relay), web.get("/admin/health", lambda r: web.json_response({"ok":True}))])
    app["db"] = await ensure_db(DB_PATH)
    app["shared_key"] = load_or_create_shared_key(SHARED_KEY_FILE)
    return app

if __name__ == "__main__":
    import ssl, argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=LISTEN_HOST)
    parser.add_argument("--port", type=int, default=LISTEN_PORT)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--tokens", default=TOKENS_FILE)
    parser.add_argument("--shared", default=SHARED_KEY_FILE)
    parser.add_argument("--cert", default=CERTFILE)
    parser.add_argument("--key", default=KEYFILE)
    args = parser.parse_args()
    DB_PATH = args.db; TOKENS_FILE = args.tokens; SHARED_KEY_FILE = args.shared
    loop = asyncio.get_event_loop()
    app = loop.run_until_complete(init_app())
    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    # optional mTLS: require client certs signed by CA in /certs/ca.crt.pem if present
    ca = os.environ.get("TLS_CA", "/certs/ca.crt.pem")
    if os.path.exists(ca):
        sslctx.load_verify_locations(cafile=ca)
        sslctx.verify_mode = ssl.CERT_OPTIONAL  # require client cert if provided; can be changed to CERT_REQUIRED
    web.run_app(app, host=args.host, port=args.port, ssl_context=sslctx)