# Sourced by the tier and remote-backend tests: a throwaway PKI and zkfsm endpoints that
# demand a client certificate. Needs WORK, BIN and freeport() from the caller.
# tls_pki: $PKI/{ca,rogue}.pem, server.{pem,key} (SAN localhost + 127.0.0.1), client.{pem,key}
tls_pki() {
  PKI="$WORK/pki"
  mkdir -p "$PKI"
  cat >"$PKI/ext.cnf" <<'EOF'
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[srv]
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
[cli]
basicConstraints=CA:FALSE
extendedKeyUsage=clientAuth
EOF
  local n
  for n in ca rogue; do
    openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$n.key"
    openssl req -x509 -new -key "$PKI/$n.key" -subj "/CN=$n" -days 2 -out "$PKI/$n.pem" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
  done
  _tls_cert() { # name cn ca ext
    openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkcs8 -topk8 -nocrypt -out "$PKI/$1.key"
    openssl req -new -key "$PKI/$1.key" -subj "/CN=$2" -out "$PKI/$1.csr" 2>/dev/null
    openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/$3.pem" -CAkey "$PKI/$3.key" -CAcreateserial -days 2 -extfile "$PKI/ext.cnf" -extensions "$4" -out "$PKI/$1.pem" 2>/dev/null
  }
  _tls_cert server localhost ca srv
  _tls_cert client tier-client ca cli
  _tls_cert rogue-client rogue rogue cli
  chmod 644 "$PKI"/*
}

# tls_zkfsm NAME PORT AK SK [flags...]: zkfsm over HTTPS that requires a client cert
# from $PKI/ca.pem; sets TLS_PIDS+=pid. Extra flags e.g. --tls-max-version 1.2.
TLS_PIDS=()
tls_zkfsm() {
  local name="$1" port="$2" ak="$3" sk="$4"; shift 4
  mkdir -p "$WORK/$name"
  ZKFSM_ACCESS_KEY="$ak" ZKFSM_SECRET_KEY="$sk" "$BIN" --data "$WORK/$name" --listen "127.0.0.1:$port" \
    --tls-cert "$PKI/server.pem" --tls-key "$PKI/server.key" --tls-client-ca "$PKI/ca.pem" --tls-client-auth require \
    "$@" 2>>"$WORK/$name.log" &
  TLS_PIDS+=($!)
  for _ in $(seq 100); do
    curl -s -o /dev/null --cacert "$PKI/ca.pem" --cert "$PKI/client.pem" --key "$PKI/client.key" "https://127.0.0.1:$port/" && return 0
    sleep 0.1
  done
  echo "tls zkfsm $name did not start"; return 1
}

# tls_s3 PORT AK SK METHOD PATH [curl args]: signed request with the client certificate.
tls_s3() {
  local port="$1" ak="$2" sk="$3" m="$4" p="$5"; shift 5
  curl -s --cacert "$PKI/ca.pem" --cert "$PKI/client.pem" --key "$PKI/client.key" \
    --aws-sigv4 aws:amz:us-east-1:s3 --user "$ak:$sk" -X "$m" "$@" "https://127.0.0.1:$port$p"
}

# tls_count PORT AK SK BUCKET PREFIX: objects under PREFIX.
tls_count() {
  tls_s3 "$1" "$2" "$3" GET "/$4?list-type=2&prefix=$5" | grep -o '<Key>' | wc -l | tr -d ' '
}
