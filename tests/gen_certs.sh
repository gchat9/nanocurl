#!/bin/sh
# Regenerates the deterministic certificate fixtures used by test_verify.c.
# Not run automatically by the test suite -- the resulting DER files are
# committed under tests/certs/ so tests don't need OpenSSL or network access
# to run. Re-run this manually if you need to add/change a fixture.
#
# Dates are patched directly into the DER's fixed-width UTCTime fields after
# generation (this OpenSSL build has no -not_before/-not_after in `req`).
# This invalidates each cert's self-signature, which is fine: these fixtures
# are only ever fed to handrolled_check_leaf(), which never touches the
# signature -- only structure, SAN/CN, and validity dates.
set -e
cd "$(dirname "$0")"
mkdir -p certs

patch_dates() {
    # patch_dates <der-file> <notBefore YYMMDDHHMMSSZ> <notAfter YYMMDDHHMMSSZ>
    python3 - "$1" "$2" "$3" << 'EOF'
import sys
path, nb, na = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
data = bytearray(open(path, 'rb').read())
times = []
i = 0
while True:
    i = data.find(b'\x17\x0d', i)
    if i < 0: break
    times.append(i)
    i += 2
assert len(times) == 2, f"expected exactly 2 UTCTime fields, found {len(times)}"
for off, val in zip(times, (nb, na)):
    assert len(val) == 13
    data[off+2:off+2+13] = val
open(path, 'wb').write(bytes(data))
EOF
}

gen() {
    name=$1; subj=$2; san=$3; nb=$4; na=$5
    key=$(mktemp)
    openssl genrsa -out "$key" 2048 2>/dev/null
    if [ -n "$san" ]; then
        openssl req -x509 -new -key "$key" -subj "$subj" -addext "subjectAltName=$san" \
            -days 1 -sha256 -outform der -out "certs/$name.der" 2>/dev/null
    else
        openssl req -x509 -new -key "$key" -subj "$subj" \
            -days 1 -sha256 -outform der -out "certs/$name.der" 2>/dev/null
    fi
    rm -f "$key"
    patch_dates "certs/$name.der" "$nb" "$na"
}

# a) exact SAN dNSName match, no wildcard involved
gen exact_san      "/CN=irrelevant"     "DNS:test-a.example"      "200101000000Z" "491231235959Z"
# b) wildcard SAN -- must match subdomains, must NOT match the bare apex
gen wildcard_san   "/CN=irrelevant"     "DNS:*.test-b.example"    "200101000000Z" "491231235959Z"
# c) SAN present but doesn't match -- CN must NOT be used as a fallback here
gen san_no_match   "/CN=test-c.example" "DNS:unrelated.example"   "200101000000Z" "491231235959Z"
# d) no SAN extension at all -- CN fallback path
gen cn_only        "/CN=test-d.example" ""                        "200101000000Z" "491231235959Z"
# e) expired (notAfter in the past, fixed forever)
gen expired        "/CN=test-e.example" "DNS:test-e.example"      "200101000000Z" "200601000000Z"
# f) not yet valid (notBefore far in the future; UTCTime tops out at 2049)
gen not_yet_valid  "/CN=test-f.example" "DNS:test-f.example"      "490101000000Z" "491231235959Z"

echo "generated $(ls certs/*.der | wc -l) fixtures in certs/"
