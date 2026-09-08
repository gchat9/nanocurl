#!/bin/sh
# Regenerates the RSA test fixtures used by test_rsa.c: a keypair, a message,
# and real OpenSSL-produced PKCS#1 v1.5 and PSS signatures over it. Written
# to build/rsa/, which `make test` (re)generates automatically and which is
# never committed. Requires OpenSSL.
set -e
cd "$(dirname "$0")/../build"
mkdir -p rsa
openssl genrsa -out rsa/key.pem 2048 2>/dev/null
openssl rsa -in rsa/key.pem -pubout -outform der -out rsa/pub.der 2>/dev/null
printf 'the quick brown fox jumps over the lazy dog, 17 times, deterministically' > rsa/message.txt
openssl dgst -sha256 -sign rsa/key.pem -out rsa/sig_pkcs1.bin rsa/message.txt
openssl dgst -sha256 -sign rsa/key.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -out rsa/sig_pss.bin rsa/message.txt
rm -f rsa/key.pem   # only the public key and signatures are needed by the tests
echo "generated RSA fixtures in rsa/"
