#!/bin/sh
# Regenerates the wire-protocol fixture(s) used by run_audit_build.sh: a
# synthetic nanocurl-verify request built from the real signed chain in
# chain_fixtures/ (leaf+intermediate, real DER, real signatures) whose root
# is deliberately not in the *system* trust store -- both the release and
# audit builds must reject it, and for the same chain-of-trust reason, even
# though every signature inside the chain is genuinely valid.
set -e
cd "$(dirname "$0")"
python3 - << 'EOF'
import struct
def build(host, sigalg, sig, th, certs):
    out = b'\x01'
    out += struct.pack('>H', len(host)) + host.encode()
    out += struct.pack('>H', sigalg)
    out += struct.pack('>H', len(sig)) + sig
    out += th
    out += struct.pack('>H', len(certs))
    for c in certs:
        out += struct.pack('>I', len(c))[1:]
        out += c
    return out
leaf = open('chain_fixtures/leaf.der','rb').read()
inter = open('chain_fixtures/inter.der','rb').read()
open('wire_fixtures_untrusted_root.bin','wb').write(
    build('test-leaf.example', 0x0403, b'\x00'*70, b'\x00'*32, [leaf, inter]))
EOF
echo "generated wire_fixtures_untrusted_root.bin"
