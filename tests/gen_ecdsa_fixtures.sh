#!/bin/sh
# Regenerates the ECDSA P-256 test fixtures used by test_ecdsa.c: a keypair,
# a message, and a real OpenSSL ECDSA-SHA256 signature over it. Committed
# under tests/ecdsa_fixtures/ so the test suite doesn't need OpenSSL or
# network access to run.
set -e
cd "$(dirname "$0")"
mkdir -p ecdsa_fixtures
openssl ecparam -genkey -name prime256v1 -noout -out ecdsa_fixtures/key.pem 2>/dev/null
openssl ec -in ecdsa_fixtures/key.pem -pubout -outform der -out ecdsa_fixtures/pub.der 2>/dev/null
printf 'ecdsa test message, deterministic fixture for nanocurl-verify' > ecdsa_fixtures/message.txt
openssl dgst -sha256 -sign ecdsa_fixtures/key.pem -out ecdsa_fixtures/sig.der ecdsa_fixtures/message.txt
rm -f ecdsa_fixtures/key.pem
echo "generated ECDSA fixtures in ecdsa_fixtures/"

# P-384 + SHA-384 variant (real-world CA hierarchies commonly pair these)
openssl ecparam -genkey -name secp384r1 -noout -out ecdsa_fixtures/key384.pem 2>/dev/null
openssl ec -in ecdsa_fixtures/key384.pem -pubout -outform der -out ecdsa_fixtures/pub384.der 2>/dev/null
printf 'ecdsa p384 test message, deterministic fixture for nanocurl-verify' > ecdsa_fixtures/message384.txt
openssl dgst -sha384 -sign ecdsa_fixtures/key384.pem -out ecdsa_fixtures/sig384.der ecdsa_fixtures/message384.txt
rm -f ecdsa_fixtures/key384.pem
echo "generated P-384 fixtures too"
