#!/usr/bin/env bash
set -e
OUTDIR="./certs"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

# 1) Create CA key + cert
if [ ! -f ca.key.pem ]; then
  openssl genrsa -out ca.key.pem 4096
  openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 3650 -subj "/CN=privacy-relay-test-CA" -out ca.crt.pem
  echo "Created CA cert: $OUTDIR/ca.crt.pem"
fi

# helper to generate server cert signed by CA
generate_cert() {
  name=$1
  key="${name}.key.pem"
  csr="${name}.csr.pem"
  crt="${name}.crt.pem"
  conf="${name}.csr.cnf"
  cat > "$conf" <<EOF
[req]
prompt = no
distinguished_name = dn
[dn]
CN = $name
EOF
  if [ ! -f "$key" ]; then
    openssl genrsa -out "$key" 2048
  fi
  openssl req -new -key "$key" -out "$csr" -config "$conf"
  openssl x509 -req -in "$csr" -CA ca.crt.pem -CAkey ca.key.pem -CAcreateserial -out "$crt" -days 3650 -sha256
  rm -f "$csr" "$conf"
  echo "Created cert: $crt"
}

# nodes
generate_cert node1.local
generate_cert node2.local
generate_cert node3.local

# client certificate (used for mTLS client auth if desired)
generate_cert client.local

echo "All certs generated in $OUTDIR"