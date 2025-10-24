#!/usr/bin/env python3
"""
client_proxy.py
- Async HTTP proxy that forwards requests to relay nodes using mTLS + token authorization.
- Uses httpx async client with http2=True for upstream requests to target when node permits.
- Loads tokens from /data/tokens.json (rotated externally).
- Provides admin API at /admin for nodes & audit.
"""

import asyncio, os, json, time, base64, secrets, pathlib, hashlib
from aiohttp import web
import httpx
import aiosqlite
from typing import Dict, Any, List, Optional

LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_PORT","3128"))
ADMIN_PORT = int(os.environ.get("PROXY_ADMIN","9000"))
TOKENS_FILE = os.environ.get("TOKENS_FILE","/data/tokens.json")
CERTFILE = os.environ.get("CLIENT_CERT","/certs/client.crt.pem")
KEYFILE = os.environ.get("CLIENT_KEY","/certs/client.key.pem")
CAFILE = os.environ.get("TLS_CA","/certs/ca.crt.pem")
DB_PATH = os.environ.get("CLIENT_DB","/data/client.db")
NODE_LIST_PERSIST = os.environ.get("NODE_LIST","/data/nodes.json")  # optional static node list

MAX_PAYLOAD = 8 * 1024 * 1024

# helper to load tokens periodically
def load_tokens():
    try:
        with open(TOKENS_FILE,"r") as f:
            return json.load(f)
    except Exception:
        return {}

async def ensure_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = await aiosqlite.connect(path)
    await c.execute("""
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL, action TEXT, node_id TEXT, target TEXT, status INTEGER, latency REAL, reason TEXT
    )
    """)
    await c.commit()
    return c

class ClientProxy:
    def __init__(self):
        self.tokens = {}
        self.nodes = []  # list of {id,endpoint,token_hex,shared_key_hex}
        self.client_id = secrets.token_hex(8)
        self.db = None
        # httpx client with mTLS for node communication (client cert provided)
        self.httpx_client = httpx.AsyncClient(http2=True, verify=CAFILE, cert=(CERTFILE, KEYFILE), timeout=30.0)

    async def start(self):
        self.db = await ensure_db(DB_PATH)
        await self.load_nodes()
        # start aiohttp admin server concurrently
        app = web.Application()
        app.add_routes([
            web.get("/admin/health", self.health),
            web.get("/admin/nodes", self.show_nodes),
            web.get("/admin/audit", self.show_audit),
            web.post("/admin/refresh_tokens", self.refresh_tokens)
        ])
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host="127.0.0.1", port=ADMIN_PORT)
        await site.start()
        print(f"[client] admin API at http://127.0.0.1:{ADMIN_PORT}")

        # start raw TCP proxy server for HTTP/HTTPS
        server = await asyncio.start_server(self.handle_stream, LISTEN_HOST, LISTEN_PORT)
        print(f"[client] proxy accepting at {LISTEN_HOST}:{LISTEN_PORT}")
        async with server:
            await server.serve_forever()

    async def load_nodes(self):
        # try NODE_LIST_PERSIST else tokens file seeds
        if os.path.exists(NODE_LIST_PERSIST):
            try:
                with open(NODE_LIST_PERSIST,"r") as f:
                    ns = json.load(f)
                    self.nodes = ns
                    return
            except Exception:
                pass
        # else load tokens to discover nodes (admin rotates tokens with ids)
        self.tokens = load_tokens()
        self.nodes = []
        for nid, rec in self.tokens.items():
            # for demo, endpoints are conventional: https://nodeX.local:8443/relay
            # In real deployments, tokens include metadata with endpoint
            endpoint = rec.get("endpoint") or f"https://{nid}/relay"
            self.nodes.append({"id":nid,"endpoint":endpoint,"token":rec.get("token")})
        print("[client] discovered nodes:", [n["id"] for n in self.nodes])

    async def select_node(self):
        # simple round-robin / selection with randomness
        if not self.nodes:
            await self.load_nodes()
            if not self.nodes:
                return None
        return secrets.choice(self.nodes)

    async def handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        try:
            data = await reader.readline()
            if not data:
                writer.close(); await writer.wait_closed(); return
            header = data.decode("latin1").strip()
            method, target, proto = header.split(" ",2)
            # read headers
            headers = {}
            while True:
                ln = await reader.readline()
                if not ln:
                    break
                s = ln.decode("latin1")
                if s in ("\r\n","\n",""):
                    break
                k,v = s.split(":",1)
                headers[k.strip()] = v.strip()
            if method.upper() == "CONNECT":
                # handle HTTPS tunneling: read ClientHello first chunk then forward to node
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                # read some bytes (client TLS handshake initiation)
                initial = await reader.read(8192)
                node = await self.select_node()
                if not node:
                    writer.close(); await writer.wait_closed(); return
                ok, resp = await self.encapsulate_and_relay(node, method="CONNECT", target=f"https://{target}", headers={}, body=initial)
                if not ok:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await writer.drain(); writer.close(); await writer.wait_closed(); return
                # after initial chunk success we could forward further data, but for demo we'll close
                writer.close(); await writer.wait_closed(); return
            else:
                # normal HTTP request
                body = b""
                if "Content-Length" in headers:
                    l = int(headers["Content-Length"])
                    body = await reader.readexactly(l) if l>0 else b""
                url = target if target.startswith("http://") else f"http://{headers.get('Host')}{target}"
                node = await self.select_node()
                if not node:
                    writer.write(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"); await writer.drain(); writer.close(); await writer.wait_closed(); return
                ok, resp = await self.encapsulate_and_relay(node, method=method, target=url, headers=headers, body=body)
                if not ok:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await writer.drain(); writer.close(); await writer.wait_closed(); return
                status = resp.get("status",502)
                headers_out = resp.get("headers",{})
                body_b = base64.b64decode(resp.get("body_b64",""))
                writer.write(f"HTTP/1.1 {status} OK\r\n".encode("latin1"))
                for k,v in headers_out.items():
                    writer.write(f"{k}: {v}\r\n".encode("latin1"))
                writer.write(b"\r\n")
                writer.write(body_b)
                await writer.drain()
                writer.close(); await writer.wait_closed(); return
        except Exception:
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass

    async def encapsulate_and_relay(self, node, method, target, headers, body):
        # prepare request to node (envelope)
        rec = load_tokens().get(node["id"]) or {}
        token = rec.get("token") or node.get("token")
        if not token:
            return False, None
        reqobj = {"method": method, "url": target, "headers": headers, "body_b64": base64.b64encode(body).decode("utf-8")}
        pl = json.dumps(reqobj).encode("utf-8")
        # for confidentiality, we don't encrypt here in demo; rely on HTTPS + mTLS between client->node
        envelope = {"payload_b64": base64.b64encode(pl).decode("utf-8"), "client_id": self.client_id}
        headers_send = {"Authorization": f"Bearer {token}"}
        start = time.time()
        try:
            async with httpx.AsyncClient(http2=True, verify=CAFILE, cert=(CERTFILE, KEYFILE), timeout=30.0) as client:
                r = await client.post(node["endpoint"], json=envelope, headers=headers_send)
                if r.status_code != 200:
                    await self.db.execute("INSERT INTO audit(ts,action,node_id,target,status,latency,reason) VALUES (?,?,?,?,?,?,?)",
                                          (time.time(),"relay", node["id"], target, r.status_code, time.time()-start, "node_error"))
                    await self.db.commit()
                    return False, None
                j = r.json()
                payload_b64 = j.get("payload_b64")
                resp_blob = base64.b64decode(payload_b64)
                # payload is the JSON plain here (node decrypted), so parse directly
                resp_obj = json.loads(resp_blob.decode("utf-8"))
                await self.db.execute("INSERT INTO audit(ts,action,node_id,target,status,latency,reason) VALUES (?,?,?,?,?,?,?)",
                                      (time.time(),"relay", node["id"], target, resp_obj.get("status"), time.time()-start, "ok"))
                await self.db.commit()
                return True, resp_obj
        except Exception as e:
            await self.db.execute("INSERT INTO audit(ts,action,node_id,target,status,latency,reason) VALUES (?,?,?,?,?,?,?)",
                                  (time.time(),"relay", node["id"], target, 0, time.time()-start, str(e)))
            await self.db.commit()
            return False, None

    async def health(self, request):
        return web.json_response({"ok":True, "client_id": self.client_id})

    async def show_nodes(self, request):
        return web.json_response({"nodes": self.nodes})

    async def show_audit(self, request):
        cur = await self.db.execute("SELECT ts,action,node_id,target,status,latency,reason FROM audit ORDER BY id DESC LIMIT 200")
        rows = await cur.fetchall()
        await cur.close()
        out = [{"ts":r[0],"action":r[1],"node":r[2],"target":r[3],"status":r[4],"latency":r[5],"reason":r[6]} for r in rows]
        return web.json_response({"audit": out})

    async def refresh_tokens(self, request):
        await self.load_nodes()
        return web.json_response({"ok":True})

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--listen-host", default=LISTEN_HOST)
    p.add_argument("--listen-port", type=int, default=LISTEN_PORT)
    args = p.parse_args()
    cp = ClientProxy()
    asyncio.run(cp.start())