/*
 * pki_crypto.h -- the signature-verification crypto nanocurl-verify.c
 * needs: bignum, SHA-384, RSA (PKCS#1 v1.5 and PSS), and ECDSA (P-256 and
 * P-384). Header-only, used only by nanocurl-verify.c (nanocurl.c has no
 * use for any of this -- it never verifies a certificate, only does a key
 * exchange and symmetric encryption, which is what handshake_crypto.h is
 * for).
 *
 * What's deliberately NOT in here: ASN.1 walking beyond the bare TLV reader
 * (der.h) needed to parse a SubjectPublicKeyInfo or an ECDSA-Sig-Value --
 * everything X.509-shaped (TBSCertificate structure, extensions, hostname
 * matching, chain building, trust store loading) is certificate semantics,
 * not a crypto primitive, and stays in nanocurl-verify.c.
 *
 * Requires sha256.h and der.h to already be included.
 */
#ifndef NANOCURL_PKI_CRYPTO_H
#define NANOCURL_PKI_CRYPTO_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#ifndef NANOCURL_BASIC_TYPES_DEFINED
#define NANOCURL_BASIC_TYPES_DEFINED
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

/* ======================================================================
 * Hand-rolled bignum.
 *
 * Deliberately avoids implementing general multiplication and division.
 * RSA/ECDSA *verification* only ever exponentiates by a small public
 * exponent or a curve-order-sized scalar, so classic "double-and-add"
 * modular multiplication -- add a running total, double the multiplicand
 * mod n, repeat once per bit -- is plenty fast (tens of milliseconds for a
 * 4096-bit RSA modulus) while needing only add/subtract/compare on numbers
 * that never exceed n. That sidesteps ever needing a generic big-integer
 * divide, by far the fiddliest thing to get right in a from-scratch bignum.
 * ==================================================================== */

#define BN_MAX_LIMBS 130 /* supports moduli up to 4160 bits (32-bit limbs); real-world RSA tops out at 4096 */
typedef struct { u32 limb[BN_MAX_LIMBS]; int n; /* limb[n-1] != 0, or n==0 for the value zero */ } bn_t;

static void bn_from_be(bn_t *r, const u8 *be, size_t len) {
    memset(r->limb, 0, sizeof r->limb);
    r->n = 0;
    for (size_t i = 0; i < len; i++) {
        size_t byte_idx = len - 1 - i; /* distance from the least-significant byte */
        size_t limb_idx = byte_idx / 4;
        int shift = (int)(byte_idx % 4) * 8;
        if (limb_idx >= BN_MAX_LIMBS) continue; /* silently drop bits beyond our max -- caller bounds-checks len first */
        r->limb[limb_idx] |= ((u32)be[i]) << shift;
        if ((int)limb_idx + 1 > r->n) r->n = (int)limb_idx + 1;
    }
    while (r->n > 0 && r->limb[r->n - 1] == 0) r->n--;
}

/* Serializes to exactly `outlen` big-endian bytes, zero-padded on the left.
   Caller must ensure `a` actually fits (true by construction here: results
   are always < n, and n's byte length is what callers pass as outlen). */
static void bn_to_be(const bn_t *a, u8 *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        size_t byte_idx = outlen - 1 - i;
        size_t limb_idx = byte_idx / 4;
        int shift = (int)(byte_idx % 4) * 8;
        u32 v = (limb_idx < (size_t)a->n) ? a->limb[limb_idx] : 0;
        out[i] = (u8)(v >> shift);
    }
}

static int bn_cmp(const bn_t *a, const bn_t *b) {
    int n = a->n > b->n ? a->n : b->n;
    for (int i = n - 1; i >= 0; i--) {
        u32 av = i < a->n ? a->limb[i] : 0;
        u32 bv = i < b->n ? b->limb[i] : 0;
        if (av != bv) return av > bv ? 1 : -1;
    }
    return 0;
}

static int bn_bitlen(const bn_t *a) {
    if (a->n == 0) return 0;
    u32 top = a->limb[a->n - 1];
    int bits = (a->n - 1) * 32;
    while (top) { bits++; top >>= 1; }
    return bits;
}

/* r = a + b (unsigned, no assumptions about relative size). May produce one
   more significant limb than max(a->n, b->n); callers here always follow
   this with a conditional subtract, so that's fine. */
static void bn_add(bn_t *r, const bn_t *a, const bn_t *b) {
    int n = a->n > b->n ? a->n : b->n;
    u64 carry = 0;
    int i;
    for (i = 0; i < n && i < BN_MAX_LIMBS; i++) {
        u64 s = (u64)(i < a->n ? a->limb[i] : 0) + (i < b->n ? b->limb[i] : 0) + carry;
        r->limb[i] = (u32)s;
        carry = s >> 32;
    }
    if (carry && i < BN_MAX_LIMBS) { r->limb[i] = (u32)carry; i++; }
    r->n = i;
    while (r->n > 0 && r->limb[r->n - 1] == 0) r->n--;
}

/* r = a - b, assumes a >= b (true for every call site here). */
static void bn_sub(bn_t *r, const bn_t *a, const bn_t *b) {
    int64_t borrow = 0;
    int i;
    for (i = 0; i < a->n; i++) {
        int64_t d = (int64_t)a->limb[i] - (i < b->n ? (int64_t)b->limb[i] : 0) - borrow;
        if (d < 0) { d += ((int64_t)1 << 32); borrow = 1; } else borrow = 0;
        r->limb[i] = (u32)d;
    }
    r->n = a->n;
    while (r->n > 0 && r->limb[r->n - 1] == 0) r->n--;
}

/* r = (a + b) mod n, given a < n and b < n (so a+b < 2n -- one conditional
   subtract always suffices, no full reduction loop needed). */
static void bn_addmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *n) {
    bn_t sum; bn_add(&sum, a, b);
    if (bn_cmp(&sum, n) >= 0) bn_sub(r, &sum, n); else *r = sum;
}

/* r = (a - b) mod n, for any a, b < n (bn_sub alone only handles a >= b). */
static void bn_submod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *n) {
    if (bn_cmp(a, b) >= 0) { bn_sub(r, a, b); return; }
    bn_t t; bn_sub(&t, b, a); bn_sub(r, n, &t);
}

/* r = (a * k) mod n for a small integer constant k, via the same
   double-and-add technique bn_mulmod uses for two bignums. */
static void bn_mulsmall_mod(bn_t *r, const bn_t *a, unsigned k, const bn_t *n) {
    bn_t acc = {0};
    bn_t addend = *a;
    while (k) {
        if (k & 1) bn_addmod(&acc, &acc, &addend, n);
        bn_addmod(&addend, &addend, &addend, n);
        k >>= 1;
    }
    *r = acc;
}

/* r = (a * b) mod n via double-and-add, given a < n and b < n. */
static void bn_mulmod(bn_t *r, const bn_t *a_in, const bn_t *b, const bn_t *n) {
    bn_t result = {0}; /* zero */
    bn_t a = *a_in;
    int bitlen = bn_bitlen(b);
    for (int i = 0; i < bitlen; i++) {
        int limb_idx = i / 32, bit_idx = i % 32;
        if (limb_idx < b->n && ((b->limb[limb_idx] >> bit_idx) & 1)) bn_addmod(&result, &result, &a, n);
        bn_addmod(&a, &a, &a, n); /* a = 2a mod n */
    }
    *r = result;
}

/* r = base^exp mod n, base < n required (true for an RSA signature s, which
   is only valid if 0 <= s < n in the first place -- see the s>=n check at
   each call site, which rejects rather than trying to cope). */
static void bn_modexp(bn_t *r, const bn_t *base, const bn_t *exp, const bn_t *n) {
    bn_t result = {0}; result.limb[0] = 1; result.n = 1; /* result = 1 */
    int bitlen = bn_bitlen(exp);
    for (int i = bitlen - 1; i >= 0; i--) {
        bn_mulmod(&result, &result, &result, n); /* square */
        int limb_idx = i / 32, bit_idx = i % 32;
        if ((exp->limb[limb_idx] >> bit_idx) & 1) bn_mulmod(&result, &result, base, n); /* multiply */
    }
    *r = result;
}

static void bn_from_hex(bn_t *r, const char *hex) {
    u8 bytes[64]; size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) sscanf(hex + 2*i, "%2hhx", &bytes[i]);
    bn_from_be(r, bytes, n);
}

/* ======================================================================
 * Hand-rolled SHA-384 (FIPS 180-4), needed for chain-signature
 * verification: real-world CA hierarchies commonly use P-384 keys signed
 * with ecdsa-with-SHA384 at the intermediate/root level even when leaf
 * certificates stay on P-256/SHA-256.
 *
 * The round constants and the initial hash value were not typed from
 * memory -- they were derived from their FIPS 180-4 definition (fractional
 * bits of cube/square roots of the first N primes) using exact arbitrary-
 * precision integer arithmetic, then verified byte-for-byte against
 * `openssl dgst -sha384`/`-sha512` on several inputs including a
 * multi-block message, before this code was ever wired into anything.
 * ==================================================================== */
typedef struct { u64 s[8]; u8 buf[128]; u64 len; } sha512_ctx;

static const u64 SHA512_K[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

static const u64 SHA384_IV[8] = {
0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};

#define SHA512_ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

static void sha512_block(sha512_ctx *c, const u8 *p) {
    u64 w[80], a,b,cc,d,e,f,g,h,t1,t2; int i;
    for (i=0;i<16;i++) { w[i]=0; for (int j=0;j<8;j++) w[i]=(w[i]<<8)|p[8*i+j]; }
    for (;i<80;i++) {
        u64 s0 = SHA512_ROTR(w[i-15],1)^SHA512_ROTR(w[i-15],8)^(w[i-15]>>7);
        u64 s1 = SHA512_ROTR(w[i-2],19)^SHA512_ROTR(w[i-2],61)^(w[i-2]>>6);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i=0;i<80;i++) {
        u64 S1 = SHA512_ROTR(e,14)^SHA512_ROTR(e,18)^SHA512_ROTR(e,41);
        u64 ch = (e&f)^((~e)&g);
        t1 = h+S1+ch+SHA512_K[i]+w[i];
        u64 S0 = SHA512_ROTR(a,28)^SHA512_ROTR(a,34)^SHA512_ROTR(a,39);
        u64 maj = (a&b)^(a&cc)^(b&cc);
        t2 = S0+maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}

static void sha512_init_iv(sha512_ctx *c, const u64 iv[8]) { memcpy(c->s, iv, sizeof(u64)*8); c->len = 0; }

static void sha512_update(sha512_ctx *c, const u8 *data, size_t n) {
    size_t off = c->len % 128;
    c->len += n;
    while (n) {
        size_t take = 128-off < n ? 128-off : n;
        memcpy(c->buf+off, data, take);
        off += take; data += take; n -= take;
        if (off == 128) { sha512_block(c, c->buf); off = 0; }
    }
}

/* finalizes a copy, writing the first `outlen` bytes of the 64-byte state
   (48 for SHA-384). Message lengths beyond 2^61 bytes would overflow the
   64-bit bit-length field this uses (the true field is 128 bits; the top
   64 are always zero for anything this program will ever hash --
   certificates and TLS transcripts, not petabyte files). */
static void sha512_final_copy(sha512_ctx c, u8 *out, size_t outlen) {
    u64 bitlen = c.len * 8;
    u8 pad = 0x80;
    sha512_update(&c, &pad, 1);
    u8 z = 0;
    while (c.len % 128 != 112) sha512_update(&c, &z, 1);
    u8 lenbytes[16] = {0};
    for (int i = 0; i < 8; i++) lenbytes[8+i] = (u8)(bitlen >> (56-8*i));
    sha512_update(&c, lenbytes, 16);
    u8 full[64];
    for (int i = 0; i < 8; i++) for (int j = 0; j < 8; j++) full[8*i+j] = (u8)(c.s[i] >> (56-8*j));
    memcpy(out, full, outlen);
}

static void sha384_oneshot(const u8 *data, size_t n, u8 out[48]) {
    sha512_ctx c; sha512_init_iv(&c, SHA384_IV); sha512_update(&c, data, n); sha512_final_copy(c, out, 48);
}

/* ======================================================================
 * RSA: SubjectPublicKeyInfo parsing + PKCS#1 v1.5 / PSS verification,
 * SHA-256 only (all nanocurl offers).
 * ==================================================================== */

static const u8 OID_RSA_ENCRYPTION[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01}; /* 1.2.840.113549.1.1.1 */

/* RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER } */
static int parse_rsa_public_key(const u8 *p, size_t len, bn_t *n, bn_t *e) {
    der_reader_t r = { p, p + len };
    der_tlv_t rsapk;
    if (!der_read_tlv(&r, &rsapk) || rsapk.tag != 0x30) return 0;
    der_reader_t sr = { rsapk.value, rsapk.value + rsapk.len };
    der_tlv_t mod, exp;
    if (!der_read_tlv(&sr, &mod) || mod.tag != 0x02) return 0;
    if (!der_read_tlv(&sr, &exp) || exp.tag != 0x02) return 0;
    const u8 *mp = mod.value; size_t ml = mod.len;
    if (ml > 1 && mp[0] == 0x00) { mp++; ml--; } /* strip the sign-guard leading zero DER INTEGER encoding adds */
    const u8 *ep = exp.value; size_t el = exp.len;
    if (el > 1 && ep[0] == 0x00) { ep++; el--; }
    if (ml == 0 || ml > BN_MAX_LIMBS * 4 || el == 0 || el > BN_MAX_LIMBS * 4) return 0; /* zero or absurdly large -- reject */
    bn_from_be(n, mp, ml);
    bn_from_be(e, ep, el);
    return 1;
}

/* Given an already-parsed SubjectPublicKeyInfo SEQUENCE's value/len, checks
   the algorithm is rsaEncryption and parses the key out of the BIT STRING. */
static int parse_rsa_spki_fields(const u8 *spki_value, size_t spki_len, bn_t *n, bn_t *e) {
    der_reader_t sr = { spki_value, spki_value + spki_len };
    der_tlv_t alg, bits;
    if (!der_read_tlv(&sr, &alg) || alg.tag != 0x30) return 0;
    der_reader_t ar = { alg.value, alg.value + alg.len };
    der_tlv_t oid;
    if (!der_read_tlv(&ar, &oid) || oid.tag != 0x06) return 0;
    if (oid.len != sizeof(OID_RSA_ENCRYPTION) || memcmp(oid.value, OID_RSA_ENCRYPTION, oid.len) != 0) return 0;
    if (!der_read_tlv(&sr, &bits) || bits.tag != 0x03) return 0;
    if (bits.len < 1 || bits.value[0] != 0x00) return 0; /* unused-bits count must be 0 for a DER key */
    return parse_rsa_public_key(bits.value + 1, bits.len - 1, n, e);
}

/* SHA-256 DigestInfo prefix (RFC 8017, fixed DER encoding of the
   AlgorithmIdentifier for id-sha256 + the OCTET STRING header) -- this
   fixed 19-byte constant, followed by the 32-byte hash, is exactly what
   PKCS#1 v1.5 signs. */
static const u8 SHA256_DIGESTINFO_PREFIX[] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};

/* RSASSA-PKCS1-v1_5 verify (RFC 8017 8.2.2). */
static int rsa_pkcs1_verify(const bn_t *n, const bn_t *e, const u8 *sig, size_t siglen, const u8 hash[32]) {
    size_t k = ((size_t)bn_bitlen(n) + 7) / 8;
    if (k == 0 || k > BN_MAX_LIMBS * 4 || siglen != k) return 0;
    bn_t s; bn_from_be(&s, sig, siglen);
    if (bn_cmp(&s, n) >= 0) return 0; /* signature must be < modulus */
    bn_t m; bn_modexp(&m, &s, e, n);
    u8 em[BN_MAX_LIMBS * 4];
    bn_to_be(&m, em, k);
    size_t tlen = sizeof(SHA256_DIGESTINFO_PREFIX) + 32;
    if (k < 11 + tlen) return 0; /* RFC 8017 requires >=8 bytes of 0xFF padding, plus the 00 01 ... 00 wrapper */
    if (em[0] != 0x00 || em[1] != 0x01) return 0;
    size_t pslen = k - 3 - tlen;
    for (size_t i = 0; i < pslen; i++) if (em[2+i] != 0xFF) return 0;
    if (em[2+pslen] != 0x00) return 0;
    const u8 *t = em + 3 + pslen;
    if (memcmp(t, SHA256_DIGESTINFO_PREFIX, sizeof SHA256_DIGESTINFO_PREFIX) != 0) return 0;
    return memcmp(t + sizeof SHA256_DIGESTINFO_PREFIX, hash, 32) == 0;
}

/* MGF1 mask generation function (RFC 8017 B.2.1), SHA-256 only. */
static void mgf1_sha256(const u8 *seed, size_t seedlen, u8 *mask, size_t masklen) {
    u32 counter = 0;
    size_t off = 0;
    while (off < masklen) {
        u8 c[4] = { (u8)(counter>>24), (u8)(counter>>16), (u8)(counter>>8), (u8)counter };
        sha256_ctx ctx; sha256_init(&ctx);
        sha256_update(&ctx, seed, seedlen);
        sha256_update(&ctx, c, 4);
        u8 digest[32]; sha256_final_copy(ctx, digest);
        size_t take = masklen - off < 32 ? masklen - off : 32;
        memcpy(mask+off, digest, take);
        off += take;
        counter++;
    }
}

/* RSASSA-PSS verify (RFC 8017 9.1.2), SHA-256 only, salt length == hash
   length (32 bytes) -- the length TLS 1.3 (RFC 8446 4.2.3) mandates for
   rsa_pss_rsae_sha256, so it's not a guess, it's what a compliant peer
   is required to use. */
static int rsa_pss_verify(const bn_t *n, const bn_t *e, const u8 *sig, size_t siglen, const u8 mhash[32]) {
    int modBits = bn_bitlen(n);
    size_t k = ((size_t)modBits + 7) / 8;
    if (k == 0 || k > BN_MAX_LIMBS * 4 || siglen != k) return 0;
    bn_t s; bn_from_be(&s, sig, siglen);
    if (bn_cmp(&s, n) >= 0) return 0;
    bn_t m; bn_modexp(&m, &s, e, n);
    size_t emLen = ((size_t)modBits - 1 + 7) / 8;
    u8 em[BN_MAX_LIMBS * 4];
    bn_to_be(&m, em, emLen);
    const size_t hLen = 32, sLen = 32;
    if (emLen < hLen + sLen + 2) return 0;
    if (em[emLen-1] != 0xbc) return 0;
    size_t dbLen = emLen - hLen - 1;
    u8 *maskedDB = em;
    u8 *H = em + dbLen;
    u8 dbMask[BN_MAX_LIMBS * 4];
    mgf1_sha256(H, hLen, dbMask, dbLen);
    u8 DB[BN_MAX_LIMBS * 4];
    for (size_t i = 0; i < dbLen; i++) DB[i] = maskedDB[i] ^ dbMask[i];
    int unusedBits = (int)(8*emLen) - (modBits - 1);
    if (unusedBits > 0 && unusedBits < 8) DB[0] &= (u8)(0xFF >> unusedBits); /* clear padding bits per spec */
    size_t pslen = dbLen - sLen - 1;
    for (size_t i = 0; i < pslen; i++) if (DB[i] != 0x00) return 0;
    if (DB[pslen] != 0x01) return 0;
    const u8 *salt = DB + pslen + 1;
    u8 mprime[8 + 32 + 32]; /* 8 zero bytes || mHash || salt */
    memset(mprime, 0, 8);
    memcpy(mprime+8, mhash, hLen);
    memcpy(mprime+8+hLen, salt, sLen);
    u8 hprime[32];
    sha256_oneshot(mprime, 8+hLen+sLen, hprime);
    return memcmp(hprime, H, hLen) == 0;
}

/* ======================================================================
 * ECDSA (P-256 and P-384).
 *
 * Curve constants were not typed from memory -- they were extracted with
 * `openssl ecparam -name <curve> -param_enc explicit -text` and
 * cross-checked against the OID bytes in real openssl-generated public
 * keys, since a transcription error in a 256/384-bit constant is exactly
 * the kind of bug that's invisible until it silently breaks (or worse,
 * doesn't break) verification.
 *
 * Points are carried in Jacobian coordinates (X, Y, Z) representing affine
 * (X/Z^2, Y/Z^3), Z==0 meaning the point at infinity. That avoids a modular
 * inversion (an expensive full modexp) on every single point addition and
 * doubling during scalar multiplication -- only the final conversion back
 * to affine coordinates needs one inversion. bn_mulmod's double-and-add
 * multiplication (already built for RSA) doubles as the field multiplier
 * here too, since it works for any modulus, not just RSA moduli.
 * ==================================================================== */

typedef enum { EC_CURVE_P256, EC_CURVE_P384 } ec_curve_id_t;

typedef struct { bn_t p, b, n, gx, gy; int field_bytes; ec_curve_id_t id; } curve_params_t;

/* secp256r1 / NIST P-256. */
static void curve_params_p256(curve_params_t *c) {
    bn_from_hex(&c->p,  "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
    bn_from_hex(&c->b,  "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
    bn_from_hex(&c->n,  "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    bn_from_hex(&c->gx, "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    bn_from_hex(&c->gy, "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    c->field_bytes = 32; c->id = EC_CURVE_P256;
}

/* secp384r1 / NIST P-384. */
static void curve_params_p384(curve_params_t *c) {
    bn_from_hex(&c->p,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF");
    bn_from_hex(&c->b,  "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF");
    bn_from_hex(&c->n,  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973");
    bn_from_hex(&c->gx, "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7");
    bn_from_hex(&c->gy, "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F");
    c->field_bytes = 48; c->id = EC_CURVE_P384;
}
/* a = -3 mod p is baked into the doubling formula below (the "3*(...)"
   step), not carried as a separate constant -- both P-256 and P-384 use it,
   and every other NIST prime curve does too. */

typedef struct { bn_t X, Y, Z; } jpoint_t; /* Z.n==0 means the point at infinity */

static int jpoint_is_infinity(const jpoint_t *p) { return p->Z.n == 0; }
static void jpoint_set_infinity(jpoint_t *p) { memset(p, 0, sizeof *p); }

static void jpoint_from_affine(jpoint_t *p, const bn_t *x, const bn_t *y) {
    p->X = *x; p->Y = *y;
    memset(&p->Z, 0, sizeof p->Z); p->Z.limb[0] = 1; p->Z.n = 1;
}

/* Jacobian doubling, a=-3 optimized form (EFD "dbl-2001-b"). */
static void jpoint_double(jpoint_t *r, const jpoint_t *p, const bn_t *prime) {
    if (jpoint_is_infinity(p) || p->Y.n == 0) { jpoint_set_infinity(r); return; }
    bn_t delta, gamma, beta, alpha, t1, t2, t3, x3, y3, z3;
    bn_mulmod(&delta, &p->Z, &p->Z, prime);
    bn_mulmod(&gamma, &p->Y, &p->Y, prime);
    bn_mulmod(&beta, &p->X, &gamma, prime);
    bn_submod(&t1, &p->X, &delta, prime);
    bn_addmod(&t2, &p->X, &delta, prime);
    bn_mulmod(&t3, &t1, &t2, prime);
    bn_mulsmall_mod(&alpha, &t3, 3, prime);
    bn_mulmod(&t1, &alpha, &alpha, prime);
    bn_mulsmall_mod(&t2, &beta, 8, prime);
    bn_submod(&x3, &t1, &t2, prime);
    bn_addmod(&t1, &p->Y, &p->Z, prime);
    bn_mulmod(&t2, &t1, &t1, prime);
    bn_submod(&t1, &t2, &gamma, prime);
    bn_submod(&z3, &t1, &delta, prime);
    bn_mulsmall_mod(&t1, &beta, 4, prime);
    bn_submod(&t2, &t1, &x3, prime);
    bn_mulmod(&t1, &alpha, &t2, prime);
    bn_mulmod(&t2, &gamma, &gamma, prime);
    bn_mulsmall_mod(&t3, &t2, 8, prime);
    bn_submod(&y3, &t1, &t3, prime);
    r->X = x3; r->Y = y3; r->Z = z3;
}

/* General Jacobian addition (EFD "add-2007-bl"), with the standard
   same-point (-> double) and P+(-P) (-> infinity) special cases. */
static void jpoint_add(jpoint_t *r, const jpoint_t *p1, const jpoint_t *p2, const bn_t *prime) {
    if (jpoint_is_infinity(p1)) { *r = *p2; return; }
    if (jpoint_is_infinity(p2)) { *r = *p1; return; }
    bn_t Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, rr, V, t1, t2, t3, t4, X3, Y3, Z3;
    bn_mulmod(&Z1Z1, &p1->Z, &p1->Z, prime);
    bn_mulmod(&Z2Z2, &p2->Z, &p2->Z, prime);
    bn_mulmod(&U1, &p1->X, &Z2Z2, prime);
    bn_mulmod(&U2, &p2->X, &Z1Z1, prime);
    bn_mulmod(&t1, &p1->Y, &p2->Z, prime);
    bn_mulmod(&S1, &t1, &Z2Z2, prime);
    bn_mulmod(&t1, &p2->Y, &p1->Z, prime);
    bn_mulmod(&S2, &t1, &Z1Z1, prime);
    bn_submod(&H, &U2, &U1, prime);
    if (H.n == 0) {
        bn_t sdiff; bn_submod(&sdiff, &S2, &S1, prime);
        if (sdiff.n == 0) jpoint_double(r, p1, prime); else jpoint_set_infinity(r);
        return;
    }
    bn_mulsmall_mod(&t1, &H, 2, prime);
    bn_mulmod(&I, &t1, &t1, prime);
    bn_mulmod(&J, &H, &I, prime);
    bn_submod(&t2, &S2, &S1, prime);
    bn_mulsmall_mod(&rr, &t2, 2, prime);
    bn_mulmod(&V, &U1, &I, prime);
    bn_mulmod(&t1, &rr, &rr, prime);
    bn_submod(&t2, &t1, &J, prime);
    bn_mulsmall_mod(&t3, &V, 2, prime);
    bn_submod(&X3, &t2, &t3, prime);
    bn_submod(&t1, &V, &X3, prime);
    bn_mulmod(&t2, &rr, &t1, prime);
    bn_mulmod(&t1, &S1, &J, prime);
    bn_mulsmall_mod(&t3, &t1, 2, prime);
    bn_submod(&Y3, &t2, &t3, prime);
    bn_addmod(&t1, &p1->Z, &p2->Z, prime);
    bn_mulmod(&t2, &t1, &t1, prime);
    bn_submod(&t3, &t2, &Z1Z1, prime);
    bn_submod(&t4, &t3, &Z2Z2, prime);
    bn_mulmod(&Z3, &t4, &H, prime);
    r->X = X3; r->Y = Y3; r->Z = Z3;
}

static void jpoint_scalar_mult(jpoint_t *r, const jpoint_t *p, const bn_t *k, const bn_t *prime) {
    jpoint_t result; jpoint_set_infinity(&result);
    int bitlen = bn_bitlen(k);
    for (int i = bitlen - 1; i >= 0; i--) {
        jpoint_double(&result, &result, prime);
        int limb_idx = i / 32, bit_idx = i % 32;
        if ((k->limb[limb_idx] >> bit_idx) & 1) jpoint_add(&result, &result, p, prime);
    }
    *r = result;
}

/* Converts back to affine via a single Fermat inversion (Z^(p-2) mod p --
   valid since p is prime and Z != 0 here). Returns 0 for the point at
   infinity (no affine representation). */
static int jpoint_to_affine(bn_t *x, bn_t *y, const jpoint_t *p, const bn_t *prime) {
    if (jpoint_is_infinity(p)) return 0;
    bn_t two = {0}; two.limb[0] = 2; two.n = 1;
    bn_t pm2; bn_sub(&pm2, prime, &two);
    bn_t zinv; bn_modexp(&zinv, &p->Z, &pm2, prime);
    bn_t zinv2; bn_mulmod(&zinv2, &zinv, &zinv, prime);
    bn_t zinv3; bn_mulmod(&zinv3, &zinv2, &zinv, prime);
    bn_mulmod(x, &p->X, &zinv2, prime);
    bn_mulmod(y, &p->Y, &zinv3, prime);
    return 1;
}

static const u8 OID_EC_PUBLIC_KEY[] = {0x2a,0x86,0x48,0xce,0x3d,0x02,0x01}; /* 1.2.840.10045.2.1 */
static const u8 OID_PRIME256V1[]    = {0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07}; /* 1.2.840.10045.3.1.7 */
static const u8 OID_SECP384R1[]     = {0x2b,0x81,0x04,0x00,0x22}; /* 1.3.132.0.34 */

/* Given an already-parsed SubjectPublicKeyInfo SEQUENCE's value/len, checks
   the algorithm is id-ecPublicKey and its curve is explicitly one of the
   two supported here (P-256, P-384) -- any other curve is refused rather
   than guessed at. `curve` is filled in with the matched curve's
   parameters, since the caller needs them for the point arithmetic. */
static int parse_ec_pubkey_from_spki_fields(const u8 *spki_value, size_t spki_len,
                                             curve_params_t *curve, bn_t *qx, bn_t *qy) {
    der_reader_t sr = { spki_value, spki_value + spki_len };
    der_tlv_t alg, bits;
    if (!der_read_tlv(&sr, &alg) || alg.tag != 0x30) return 0;
    der_reader_t ar = { alg.value, alg.value + alg.len };
    der_tlv_t oid, curveoid;
    if (!der_read_tlv(&ar, &oid) || oid.tag != 0x06) return 0;
    if (oid.len != sizeof(OID_EC_PUBLIC_KEY) || memcmp(oid.value, OID_EC_PUBLIC_KEY, oid.len) != 0) return 0;
    if (!der_read_tlv(&ar, &curveoid) || curveoid.tag != 0x06) return 0; /* namedCurve OID, not an explicit-params SEQUENCE */
    if (curveoid.len == sizeof(OID_PRIME256V1) && memcmp(curveoid.value, OID_PRIME256V1, curveoid.len) == 0) {
        curve_params_p256(curve);
    } else if (curveoid.len == sizeof(OID_SECP384R1) && memcmp(curveoid.value, OID_SECP384R1, curveoid.len) == 0) {
        curve_params_p384(curve);
    } else {
        return 0; /* unsupported curve -- fail closed, don't guess */
    }
    if (!der_read_tlv(&sr, &bits) || bits.tag != 0x03) return 0;
    /* uncompressed point: unused-bits byte (0x00), then 0x04 || X || Y */
    size_t expected_len = 2 + 2 * (size_t)curve->field_bytes;
    if (bits.len != expected_len || bits.value[0] != 0x00 || bits.value[1] != 0x04) return 0;
    bn_from_be(qx, bits.value + 2, (size_t)curve->field_bytes);
    bn_from_be(qy, bits.value + 2 + curve->field_bytes, (size_t)curve->field_bytes);
    return 1;
}

/* ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } -- exactly the DER
   TLS puts on the wire for ECDSA signatures, and how X.509 certificates
   encode their own ECDSA signatures too. */
static int parse_ecdsa_sig(const u8 *der, size_t len, bn_t *r, bn_t *s) {
    der_reader_t rd = { der, der + len };
    der_tlv_t seq;
    if (!der_read_tlv(&rd, &seq) || seq.tag != 0x30) return 0;
    der_reader_t sr = { seq.value, seq.value + seq.len };
    der_tlv_t ri, si;
    if (!der_read_tlv(&sr, &ri) || ri.tag != 0x02) return 0;
    if (!der_read_tlv(&sr, &si) || si.tag != 0x02) return 0;
    const u8 *rp = ri.value; size_t rl = ri.len;
    if (rl > 1 && rp[0] == 0x00) { rp++; rl--; }
    const u8 *sp = si.value; size_t sl = si.len;
    if (sl > 1 && sp[0] == 0x00) { sp++; sl--; }
    if (rl == 0 || rl > 48 || sl == 0 || sl > 48) return 0; /* larger than P-384's order -- malformed for any curve we support */
    bn_from_be(r, rp, rl);
    bn_from_be(s, sp, sl);
    return 1;
}

/* SEC1's bits2int: interprets a hash as an integer no wider than the curve
   order's bit length, taking the leftmost order_bits bits if the hash is
   longer (dropping the excess least-significant bits), zero-extending if
   shorter. Only the byte-aligned case is implemented -- every hash length
   this program produces (32/48 bytes for SHA-256/384) and every curve
   order it supports (32/48 bytes for P-256/P-384) is a whole number of
   bytes, and their pairwise differences always land on a byte boundary
   too, so the bit-level shifting SEC1 describes in general never actually
   arises here. bn_from_be with fewer bytes than the order already produces
   the correct zero-extended value, so the shorter case needs no special
   handling at all. */
static void ecdsa_bits2int(bn_t *e, const u8 *hash, size_t hashlen, int order_bytes) {
    size_t take = hashlen < (size_t)order_bytes ? hashlen : (size_t)order_bytes;
    bn_from_be(e, hash, take);
}

/* ECDSA verify (SEC1 4.1.4 / FIPS 186-4). */
static int ecdsa_verify(const curve_params_t *curve, const bn_t *qx, const bn_t *qy,
                         const bn_t *rr, const bn_t *ss, const u8 *hash, size_t hashlen) {
    const bn_t *p = &curve->p, *b = &curve->b, *n = &curve->n, *gx = &curve->gx, *gy = &curve->gy;

    bn_t one = {0}; one.limb[0] = 1; one.n = 1;
    bn_t nm1; bn_sub(&nm1, n, &one);
    if (bn_cmp(rr, &one) < 0 || bn_cmp(rr, &nm1) > 0) return 0; /* r not in [1, n-1] */
    if (bn_cmp(ss, &one) < 0 || bn_cmp(ss, &nm1) > 0) return 0; /* s not in [1, n-1] */

    /* reject a public key that isn't actually on the curve -- accepting one
       that isn't would let an attacker smuggle a point in a weaker group */
    { bn_t x2, x3, ax, y2, rhs;
      bn_mulmod(&x2, qx, qx, p);
      bn_mulmod(&x3, &x2, qx, p);
      bn_mulsmall_mod(&ax, qx, 3, p);          /* a = -3, so a*x = -3x */
      bn_submod(&rhs, &x3, &ax, p);
      bn_addmod(&rhs, &rhs, b, p);
      bn_mulmod(&y2, qy, qy, p);
      if (bn_cmp(&y2, &rhs) != 0) return 0;
    }

    bn_t e; ecdsa_bits2int(&e, hash, hashlen, bn_bitlen(n) / 8);
    if (bn_cmp(&e, n) >= 0) bn_submod(&e, &e, n, n); /* reduce mod n in the (rare) case e>=n; e<2n always so one subtract suffices */

    bn_t nm2; bn_t two = {0}; two.limb[0]=2; two.n=1; bn_sub(&nm2, n, &two);
    bn_t w; bn_modexp(&w, ss, &nm2, n); /* w = s^-1 mod n, via Fermat (n is prime) */
    bn_t u1; bn_mulmod(&u1, &e, &w, n);
    bn_t u2; bn_mulmod(&u2, rr, &w, n);

    jpoint_t G, Q, P1, P2, R;
    jpoint_from_affine(&G, gx, gy);
    jpoint_from_affine(&Q, qx, qy);
    jpoint_scalar_mult(&P1, &G, &u1, p);
    jpoint_scalar_mult(&P2, &Q, &u2, p);
    jpoint_add(&R, &P1, &P2, p);

    bn_t x1, y1;
    if (!jpoint_to_affine(&x1, &y1, &R, p)) return 0; /* infinity -- invalid signature */
    bn_t v;
    if (bn_cmp(&x1, n) >= 0) bn_submod(&v, &x1, n, n); else v = x1;
    return bn_cmp(&v, rr) == 0;
}

#endif /* NANOCURL_PKI_CRYPTO_H */
