#!/bin/sh
# Regenerates the chain-of-trust test fixtures used by test_chain.c: a small
# root -> intermediate -> leaf hierarchy (deliberately mixing RSA and EC
# keys/signatures so both hand-rolled signature paths get exercised), plus
# tampered variants for the negative test cases. Committed under
# tests/chain_fixtures/ so the test suite doesn't need OpenSSL to run.
set -e
cd "$(dirname "$0")/chain_fixtures"

cat > /tmp/nanocurl_test_openssl.cnf << 'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
[dn]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[v3_intermediate]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectAltName = DNS:test-leaf.example
EOF

# Root CA: RSA key, self-signed with RSA (sha256WithRSAEncryption)
openssl genrsa -out root.key 2048 2>/dev/null
openssl req -x509 -new -key root.key -subj "/CN=nanocurl Test Root CA" -days 3650 \
    -config /tmp/nanocurl_test_openssl.cnf -extensions v3_ca -sha256 -outform der -out root.der 2>/dev/null
openssl x509 -inform der -in root.der -outform pem -out root.pem

# Intermediate CA: EC P-256 key, signed by the RSA root (exercises RSA-verifying-EC-issued-cert)
openssl ecparam -genkey -name prime256v1 -noout -out inter.key 2>/dev/null
openssl req -new -key inter.key -subj "/CN=nanocurl Test Intermediate CA" -out inter.csr 2>/dev/null
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3650 \
    -extfile /tmp/nanocurl_test_openssl.cnf -extensions v3_intermediate -sha256 -outform der -out inter.der 2>/dev/null
openssl x509 -inform der -in inter.der -outform pem -out inter.pem

# Leaf: RSA key, signed by the EC intermediate (exercises ECDSA-verifying-RSA-issued-cert)
openssl genrsa -out leaf.key 2048 2>/dev/null
openssl req -new -key leaf.key -subj "/CN=test-leaf.example" -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -CA inter.pem -CAkey inter.key -CAcreateserial -days 3650 \
    -extfile /tmp/nanocurl_test_openssl.cnf -extensions v3_leaf -sha256 -outform der -out leaf.der 2>/dev/null

# A leaf with a corrupted signature (flips a byte inside the signature value).
python3 -c "
data = bytearray(open('leaf.der','rb').read())
data[-10] ^= 0xFF
open('leaf_badsig.der','wb').write(bytes(data))
"

# The same leaf but with notAfter patched into the past (fixed forever).
python3 -c "
data = bytearray(open('leaf.der','rb').read())
times = []
i = 0
while True:
    i = data.find(b'\x17\x0d', i)
    if i < 0: break
    times.append(i)
    i += 2
off = times[1]  # second UTCTime in the cert is notAfter
data[off+2:off+2+13] = b'200601000000Z'
open('leaf_expired.der','wb').write(bytes(data))
"

# A fake trust-store bundle containing only our test root (so tests don't
# touch the real system trust store).
cp root.pem trust_store.pem

# A second variant of the hierarchy where a P-384 intermediate signs the
# leaf using ecdsa-with-SHA384 -- this is the exact shape (a P-256 leaf
# under a P-384/SHA-384-signing intermediate) that a real Cloudflare/SSL.com
# chain surfaced as a gap in the original P-256-only implementation. The
# intermediate itself is signed by the RSA root with plain SHA-256 (RSA
# signing an EC-keyed cert is already covered by inter.der above); the new
# thing here is an EC key doing the SHA-384 signing, which only happens on
# the intermediate-signs-leaf link.
openssl ecparam -genkey -name secp384r1 -noout -out inter384.key 2>/dev/null
openssl req -new -key inter384.key -subj "/CN=nanocurl Test Intermediate CA (P-384)" -out inter384.csr 2>/dev/null
openssl x509 -req -in inter384.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3650 \
    -extfile /tmp/nanocurl_test_openssl.cnf -extensions v3_intermediate -sha256 -outform der -out inter384.der 2>/dev/null
openssl x509 -inform der -in inter384.der -outform pem -out inter384.pem

openssl ecparam -genkey -name prime256v1 -noout -out leaf384.key 2>/dev/null
openssl req -new -key leaf384.key -subj "/CN=test-leaf.example" -out leaf384.csr 2>/dev/null
openssl x509 -req -in leaf384.csr -CA inter384.pem -CAkey inter384.key -CAcreateserial -days 3650 \
    -extfile /tmp/nanocurl_test_openssl.cnf -extensions v3_leaf -sha384 -outform der -out leaf384.der 2>/dev/null

rm -f root.key inter.key inter384.key leaf.key leaf384.key inter.csr inter384.csr leaf.csr leaf384.csr *.srl root.pem inter.pem inter384.pem
echo "generated chain fixtures in chain_fixtures/"
