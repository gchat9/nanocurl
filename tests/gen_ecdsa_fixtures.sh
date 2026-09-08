#!/bin/sh
# Regenerates the ECDSA test fixtures used by test_ecdsa.c: P-256 and P-384
# keypairs, a message for each, and real OpenSSL ECDSA-SHA256/SHA384
# signatures over them. Written to build/ecdsa_fixtures/, which `make test`
# (re)generates automatically and which is never committed. Requires
# OpenSSL.
set -e
cd "$(dirname "$0")/../build"
mkdir -p ecdsa_fixtures

openssl ecparam -genkey -name prime256v1 -noout -out ecdsa_fixtures/key.pem 2>/dev/null
openssl ec -in ecdsa_fixtures/key.pem -pubout -outform der -out ecdsa_fixtures/pub.der 2>/dev/null
printf 'ecdsa test message, deterministic fixture for nanocurl-verify' > ecdsa_fixtures/message.txt
openssl dgst -sha256 -sign ecdsa_fixtures/key.pem -out ecdsa_fixtures/sig.der ecdsa_fixtures/message.txt
rm -f ecdsa_fixtures/key.pem

openssl ecparam -genkey -name secp384r1 -noout -out ecdsa_fixtures/key384.pem 2>/dev/null
openssl ec -in ecdsa_fixtures/key384.pem -pubout -outform der -out ecdsa_fixtures/pub384.der 2>/dev/null
printf 'ecdsa p384 test message, deterministic fixture for nanocurl-verify' > ecdsa_fixtures/message384.txt
openssl dgst -sha384 -sign ecdsa_fixtures/key384.pem -out ecdsa_fixtures/sig384.der ecdsa_fixtures/message384.txt
rm -f ecdsa_fixtures/key384.pem

echo "generated ECDSA fixtures in ecdsa_fixtures/"
