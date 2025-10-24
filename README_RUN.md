Here’s a **clean, professional, and publication-ready rewrite** of your `README_RUN.md` — consistent with enterprise open-source documentation standards (GitHub/Docs-style clarity, correct markdown hierarchy, and formatting polish):

---

# Privacy Relay System — Quick Run Guide

A minimal deployment guide for quickly running the **Privacy Relay System** in a local or development environment.

---

## 🚀 Quick Start (Demo Environment)

### 1. Generate Certificates

```bash
chmod +x init_certs.sh
./init_certs.sh
```

Generates all required certificates under `./certs/`, including:

* Root CA certificate
* Node certificates and keys

---

### 2. Build and Start Containers

```bash
docker-compose up --build -d
```

Starts all containers in detached mode and builds any missing images.

---

### 3. Generate Authentication Tokens

```bash
chmod +x rotate_tokens.sh
./rotate_tokens.sh
```

Creates authentication tokens and stores them in:

```
./tokens/tokens.json
```

---

### 4. Verify Service Availability

| Service           | Endpoint                              | Notes                          |
| ----------------- | ------------------------------------- | ------------------------------ |
| **Node 1**        | `https://localhost:8443/admin/health` | Accept self-signed certificate |
| **Node 2**        | `https://localhost:8444/admin/health` |                                |
| **Node 3**        | `https://localhost:8445/admin/health` |                                |
| **Client Admin**  | `http://localhost:9000/admin/health`  |                                |
| **Token Manager** | `http://localhost:9200`               | Requires `ADMIN_TOKEN` header  |

---

### 5. Test the Proxy

#### HTTP Request

```bash
curl -x http://localhost:3128 http://httpbin.org/ip
```

#### HTTPS Request

```bash
curl -x http://localhost:3128 https://httpbin.org/ip --insecure
```

---

### 6. Monitor Activity

#### View Client Audit Logs

```bash
curl http://localhost:9000/admin/audit
```

#### View Node Logs

```bash
docker logs node1
docker logs node2
docker logs node3
```

---

## 🔧 Configuration

### Environment Variables

| Component         | Variable              | Description                            |
| ----------------- | --------------------- | -------------------------------------- |
| **Token Manager** | `TOKEN_MGR_ADMIN`     | Admin token for API access             |
| **Nodes**         | `TLS_CERT`, `TLS_KEY` | Certificate and private key paths      |
|                   | `TLS_CA`              | CA certificate for client verification |
|                   | `TOKENS_FILE`         | Path to token JSON file                |
| **Client**        | `PROXY_PORT`          | Proxy listening port (default: `3128`) |
|                   | `PROXY_ADMIN`         | Admin API port (default: `9000`)       |

---

### Certificate Management (Production)

For production deployments:

1. Replace self-signed CA with a trusted Certificate Authority.
2. Use domain-specific subjects for each certificate.
3. Enable strict mTLS verification (`ssl.CERT_REQUIRED`).

---

## 🛠 Troubleshooting

### Common Issues

**Certificate Errors**

* Ensure `init_certs.sh` ran successfully.
* Verify file permissions in `./certs/`.

**Connection Refused**

* Confirm all containers are running:

  ```bash
  docker ps
  ```
* Check for conflicting local ports.

**Token Authentication Failed**

* Regenerate tokens:

  ```bash
  ./rotate_tokens.sh
  ```
* Verify the existence of `tokens/tokens.json`.

---

### Logs and Debugging

**View All Logs**

```bash
docker-compose logs -f
```

**Check Node Health**

```bash
curl -k https://localhost:8443/admin/health
```

**Verify Token Manager**

```bash
curl -H "Authorization: Bearer changeme_admin_token" http://localhost:9200
```

---

## 🔒 Security Notes

* Default configuration uses self-signed certificates for local testing.
* In production:

  * Replace with CA-issued certificates.
  * Rotate tokens regularly via `rotate_tokens.sh`.
  * Monitor audit logs for anomalies.
  * Implement IP allow-listing for admin APIs.

---

## 📁 File Structure

```
privacy-relay-system/
├── certs/          # Generated certificates
├── tokens/         # Generated token files
├── node1_data/     # Node 1 persistent data
├── node2_data/     # Node 2 persistent data
├── node3_data/     # Node 3 persistent data
├── client_data/    # Client persistent data
├── *.py, *.sh, *.yml  # Source files and scripts
└── README_RUN.md   # This guide
```

---

✅ **System Ready**

Your local Privacy Relay System is now operational and ready for development or testing