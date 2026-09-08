#!/bin/sh
# Builds and runs the nanocurl-verify unit tests. Exits nonzero on any
# failure. Fixtures under certs/ and rsa/ are pre-generated and committed --
# only re-run gen_certs.sh / gen_rsa_fixtures.sh yourself if you're adding or
# changing a fixture.
set -e
cd "$(dirname "$0")"
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_verify test_verify.c -lssl -lcrypto
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_rsa test_rsa.c -lssl -lcrypto
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_ecdsa test_ecdsa.c -lssl -lcrypto
echo "== test_verify (hostname/SAN/CN/validity) =="
./test_verify
echo
echo "== test_rsa (bignum + RSA signature verification) =="
./test_rsa
echo
echo "== test_ecdsa (P-256 group arithmetic + ECDSA signature verification) =="
./test_ecdsa
