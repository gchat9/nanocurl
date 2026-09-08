#!/bin/sh
# Builds and runs the nanocurl-verify unit tests. Exits nonzero on any
# failure. Fixtures are generated fresh into build/ (nothing under build/ is
# committed) -- see gen_certs.sh / gen_rsa_fixtures.sh / gen_ecdsa_fixtures.sh
# for what each one produces. Requires OpenSSL and python3.
set -e
cd "$(dirname "$0")"
./gen_certs.sh
./gen_rsa_fixtures.sh
./gen_ecdsa_fixtures.sh
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
