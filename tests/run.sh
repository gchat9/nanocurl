#!/bin/sh
# Builds and runs the nanocurl-verify unit tests. Exits nonzero on any
# failure. Fixtures under certs/, rsa/, ecdsa_fixtures/, and chain_fixtures/
# are pre-generated and committed -- only re-run the matching gen_*.sh
# yourself if you're adding or changing a fixture.
#
# These four suites test pure hand-rolled code (ASN.1, bignum, RSA, ECDSA,
# chain building) and link no crypto library at all -- same as the release
# build of nanocurl-verify itself. See run_audit_build.sh for a build that
# additionally exercises the NANOCURL_VERIFY_WITH_OPENSSL comparison path.
set -e
cd "$(dirname "$0")"
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_verify test_verify.c
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_rsa test_rsa.c
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_ecdsa test_ecdsa.c
gcc -O0 -g -Wall -Wextra -Wno-unused-function -o test_chain test_chain.c
echo "== test_verify (hostname/SAN/CN/validity) =="
./test_verify
echo
echo "== test_rsa (bignum + RSA signature verification) =="
./test_rsa
echo
echo "== test_ecdsa (P-256/P-384 group arithmetic + ECDSA signature verification) =="
./test_ecdsa
echo
echo "== test_chain (trust store loading + chain-of-trust verification) =="
./test_chain
