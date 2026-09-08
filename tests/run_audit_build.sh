#!/bin/sh
# Builds nanocurl-verify both ways -- the default release build (no crypto
# library at all) and the audit build (-DNANOCURL_VERIFY_WITH_OPENSSL,
# linking libssl/libcrypto as a reference implementation) -- and checks the
# one property that actually matters about the flag: it must never change
# what gets trusted. Both builds are fed the same wire-protocol request and
# must produce the same exit code and the same failure reason, and the
# audit build's extra [selfcheck] lines must show agreement with OpenSSL,
# not silently override the hand-rolled verdict.
set -e
cd "$(dirname "$0")/.."

gcc -O2 -Wall -Wextra -o /tmp/nanocurl-verify-release nanocurl-verify.c
gcc -O2 -Wall -Wextra -DNANOCURL_VERIFY_WITH_OPENSSL -o /tmp/nanocurl-verify-audit nanocurl-verify.c -lssl -lcrypto

echo "checking release build has no crypto-library dependency..."
if ldd /tmp/nanocurl-verify-release | grep -qi crypto; then
    echo "FAIL: release build links a crypto library -- it shouldn't"
    exit 1
fi
echo "  ok, libc only"

REQ=build/wire_fixtures_untrusted_root.bin
if [ ! -f "$REQ" ]; then
    tests/gen_chain_fixtures.sh
    tests/gen_wire_fixtures.sh
fi
echo "running both builds against the same request (real signed chain, untrusted root)..."
rc_release=0; /tmp/nanocurl-verify-release < "$REQ" > /tmp/out_release.txt 2>&1 || rc_release=$?
rc_audit=0; /tmp/nanocurl-verify-audit < "$REQ" > /tmp/out_audit.txt 2>&1 || rc_audit=$?

fail=0
if [ "$rc_release" != "$rc_audit" ]; then
    echo "FAIL: exit codes differ (release=$rc_release audit=$rc_audit)"
    fail=1
else
    echo "  ok, both exit $rc_release"
fi

release_reason=$(grep "certificate verification failed" /tmp/out_release.txt || true)
audit_reason=$(grep "certificate verification failed" /tmp/out_audit.txt || true)
if [ "$release_reason" != "$audit_reason" ]; then
    echo "FAIL: rejection reason differs between builds"
    echo "  release: $release_reason"
    echo "  audit:   $audit_reason"
    fail=1
else
    echo "  ok, identical rejection reason: $release_reason"
fi

if ! grep -q '\[selfcheck' /tmp/out_audit.txt; then
    echo "FAIL: audit build produced no [selfcheck] comparison output"
    fail=1
else
    echo "  ok, audit build printed comparison lines:"
    grep '\[selfcheck' /tmp/out_audit.txt | sed 's/^/    /'
fi

if ! grep -qi mismatch /tmp/out_audit.txt; then
    echo "  ok, no MISMATCH between hand-rolled and OpenSSL on this input"
else
    echo "FAIL: audit build reported a MISMATCH -- investigate before trusting either build"
    fail=1
fi

if [ "$fail" = 0 ]; then echo; echo "all checks passed"; else echo; echo "SOME CHECKS FAILED"; fi
exit $fail
