/*
 * handshake_crypto.h -- the TLS 1.3 handshake/record crypto nanocurl.c
 * needs: HMAC-SHA256 + HKDF + Expand-Label, X25519, and ChaCha20-Poly1305.
 * Header-only, used only by nanocurl.c (nanocurl-verify.c has no use for
 * any of this -- it never does a key exchange or a symmetric encryption,
 * only signature verification, which is what pki_crypto.h is for).
 *
 * Requires sha256.h to already be included (for sha256_ctx and friends).
 */
#ifndef NANOCURL_HANDSHAKE_CRYPTO_H
#define NANOCURL_HANDSHAKE_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#ifndef NANOCURL_BASIC_TYPES_DEFINED
#define NANOCURL_BASIC_TYPES_DEFINED
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

/* ======================================================================
 * HMAC-SHA256 / HKDF / TLS1.3 Expand-Label
 * ==================================================================== */
static void hmac_sha256(const u8 *key, size_t klen, const u8 *msg, size_t mlen, u8 out[32]) {
    u8 k[64] = {0};
    if (klen > 64) sha256_oneshot(key, klen, k); else memcpy(k, key, klen);
    u8 ipad[64], opad[64];
    for (int i=0;i<64;i++) { ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen);
    u8 inner[32]; sha256_final_copy(c, inner);
    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final_copy(c, out);
}

static void hkdf_extract(const u8 *salt, size_t slen, const u8 *ikm, size_t ilen, u8 out[32]) {
    hmac_sha256(salt, slen, ikm, ilen, out);
}

static void hkdf_expand(const u8 *prk, const u8 *info, size_t ilen, u8 *out, size_t olen) {
    u8 t[32]; size_t tlen = 0; u8 buf[512]; size_t off = 0; u8 ctr = 1;
    while (off < olen) {
        size_t n = 0;
        memcpy(buf+n, t, tlen); n += tlen;
        memcpy(buf+n, info, ilen); n += ilen;
        buf[n++] = ctr++;
        hmac_sha256(prk, 32, buf, n, t);
        tlen = 32;
        size_t take = (olen-off) < 32 ? (olen-off) : 32;
        memcpy(out+off, t, take);
        off += take;
    }
}

/* HkdfLabel = length(2) || "tls13 "+label (1-byte len prefixed) || context (1-byte len prefixed) */
static void expand_label(const u8 secret[32], const char *label, const u8 *ctx, size_t ctxlen,
                          u8 *out, size_t outlen) {
    u8 info[512]; size_t n = 0;
    info[n++] = outlen >> 8; info[n++] = outlen & 0xff;
    size_t llen = strlen(label);
    u8 full_label_len = (u8)(6 + llen);
    info[n++] = full_label_len;
    memcpy(info+n, "tls13 ", 6); n += 6;
    memcpy(info+n, label, llen); n += llen;
    info[n++] = (u8)ctxlen;
    memcpy(info+n, ctx, ctxlen); n += ctxlen;
    hkdf_expand(secret, info, n, out, outlen);
}

static void derive_secret(const u8 secret[32], const char *label, sha256_ctx transcript, u8 out[32]) {
    u8 h[32]; sha256_final_copy(transcript, h);
    expand_label(secret, label, h, 32, out, 32);
}

/* ======================================================================
 * X25519 (field arithmetic derived from the well-known TweetNaCl layout:
 * base-2^16, 16-limb representation of GF(2^255-19))
 * ==================================================================== */
typedef int64_t gf[16];
static const gf _121665 = {0xDB41,1};

static void gf_carry(gf o) {
    int64_t c;
    for (int i=0;i<16;i++) {
        o[i] += (1LL<<16);
        c = o[i] >> 16;
        o[(i+1)*(i<15)] += c-1+37*(c-1)*(i==15);
        o[i] -= c*65536LL; /* equivalent to c<<16, but well-defined when c is negative */
    }
}

static void gf_sel(gf p, gf q, int b) {
    int64_t t, c = ~(int64_t)(b-1);
    for (int i=0;i<16;i++) { t = c & (p[i]^q[i]); p[i]^=t; q[i]^=t; }
}

static void gf_pack(u8 *o, const gf n) {
    gf m, t;
    memcpy(t, n, sizeof(gf));
    gf_carry(t); gf_carry(t); gf_carry(t);
    for (int j=0;j<2;j++) {
        m[0] = t[0]-0xffed;
        for (int i=1;i<15;i++) { m[i] = t[i]-0xffff-((m[i-1]>>16)&1); m[i-1] &= 0xffff; }
        m[15] = t[15]-0x7fff-((m[14]>>16)&1);
        int b = (m[15]>>16)&1;
        m[14] &= 0xffff;
        gf_sel(t, m, 1-b);
    }
    for (int i=0;i<16;i++) { o[2*i]=t[i]&0xff; o[2*i+1]=t[i]>>8; }
}

static void gf_unpack(gf o, const u8 *n) {
    for (int i=0;i<16;i++) o[i] = n[2*i] + ((int64_t)n[2*i+1]<<8);
    o[15] &= 0x7fff;
}

static void gf_add(gf o, const gf a, const gf b){ for(int i=0;i<16;i++) o[i]=a[i]+b[i]; }
static void gf_sub(gf o, const gf a, const gf b){ for(int i=0;i<16;i++) o[i]=a[i]-b[i]; }

static void gf_mul(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i=0;i<16;i++) for (int j=0;j<16;j++) t[i+j] += a[i]*b[j];
    for (int i=0;i<15;i++) t[i] += 38*t[i+16];
    memcpy(o, t, sizeof(gf));
    gf_carry(o); gf_carry(o);
}

static void gf_sq(gf o, const gf a) { gf_mul(o,a,a); }

static void gf_inv(gf o, const gf i) {
    gf c; memcpy(c, i, sizeof(gf));
    for (int a=253;a>=0;a--) {
        gf_sq(c,c);
        if (a!=2 && a!=4) gf_mul(c,c,i);
    }
    memcpy(o, c, sizeof(gf));
}

static void x25519_scalarmult(u8 q[32], const u8 n[32], const u8 p[32]) {
    u8 z[32]; memcpy(z, n, 32); z[31]=(z[31]&127)|64; z[0]&=248;
    gf x, a, bb, c, d, e, f;
    gf_unpack(x, p);
    for (int i=0;i<16;i++) { bb[i]=x[i]; d[i]=a[i]=c[i]=0; }
    a[0]=d[0]=1;
    for (int i=254;i>=0;i--) {
        int64_t r = (z[i>>3]>>(i&7))&1;
        gf_sel(a,bb,r); gf_sel(c,d,r);
        gf_add(e,a,c); gf_sub(a,a,c);
        gf_add(c,bb,d); gf_sub(bb,bb,d);
        gf_sq(d,e); gf_sq(f,a);
        gf_mul(a,c,a); gf_mul(c,bb,e);
        gf_add(e,a,c); gf_sub(a,a,c);
        gf_sq(bb,a);
        gf_sub(c,d,f);
        gf_mul(a,c,_121665);
        gf_add(a,a,d);
        gf_mul(c,c,a);
        gf_mul(a,d,f);
        gf_mul(d,bb,x);
        gf_sq(bb,e);
        gf_sel(a,bb,r); gf_sel(c,d,r);
    }
    gf_inv(c,c);
    gf_mul(a,a,c);
    gf_pack(q,a);
}

static void x25519_base(u8 q[32], const u8 n[32]) {
    static const u8 base[32] = {9};
    x25519_scalarmult(q, n, base);
}

/* ======================================================================
 * ChaCha20 / Poly1305 / AEAD (RFC 8439)
 * ==================================================================== */
#define CROT(x,n) (((x)<<(n))|((x)>>(32-(n))))

static void chacha20_block(const u8 key[32], u32 counter, const u8 nonce[12], u8 out[64]) {
    u32 s[16] = {
        0x61707865,0x3320646e,0x79622d32,0x6b206574,
        0,0,0,0,0,0,0,0, counter,0,0,0
    };
    for (int i=0;i<8;i++) s[4+i] = key[4*i]|(key[4*i+1]<<8)|(key[4*i+2]<<16)|((u32)key[4*i+3]<<24);
    for (int i=0;i<3;i++) s[13+i] = nonce[4*i]|(nonce[4*i+1]<<8)|(nonce[4*i+2]<<16)|((u32)nonce[4*i+3]<<24);
    u32 w[16]; memcpy(w,s,sizeof w);
#define QR(a,b,c,d) a+=b;d^=a;d=CROT(d,16); c+=d;b^=c;b=CROT(b,12); a+=b;d^=a;d=CROT(d,8); c+=d;b^=c;b=CROT(b,7)
    for (int i=0;i<10;i++) {
        QR(w[0],w[4],w[8],w[12]); QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]); QR(w[3],w[4],w[9],w[14]);
    }
    for (int i=0;i<16;i++) w[i]+=s[i];
    for (int i=0;i<16;i++) { out[4*i]=w[i]; out[4*i+1]=w[i]>>8; out[4*i+2]=w[i]>>16; out[4*i+3]=w[i]>>24; }
}
#undef QR

static void chacha20_xor(const u8 key[32], u32 counter, const u8 nonce[12],
                          const u8 *in, u8 *out, size_t len) {
    u8 block[64]; size_t off = 0;
    while (off < len) {
        chacha20_block(key, counter++, nonce, block);
        size_t take = (len-off)<64?(len-off):64;
        for (size_t i=0;i<take;i++) out[off+i] = in[off+i]^block[i];
        off += take;
    }
}

#define M26 0x3ffffffULL
static void poly1305_block(u64 h[5], const u64 r[5], const u8 *m, size_t blocklen /* <=16 */) {
    u8 buf[16] = {0};
    memcpy(buf, m, blocklen);
    if (blocklen < 16) buf[blocklen] = 0x01;
    u64 lo=0, hi=0;
    for (int i=0;i<8;i++) lo |= (u64)buf[i]<<(8*i);
    for (int i=0;i<8;i++) hi |= (u64)buf[8+i]<<(8*i);
    u64 t0 = lo & M26;
    u64 t1 = (lo>>26) & M26;
    u64 t2 = ((lo>>52) | (hi<<12)) & M26;
    u64 t3 = (hi>>14) & M26;
    u64 t4 = (hi>>40) & M26;
    if (blocklen == 16) t4 += (1ULL<<24);
    h[0]+=t0; h[1]+=t1; h[2]+=t2; h[3]+=t3; h[4]+=t4;
    u64 p[9] = {0};
    for (int i=0;i<5;i++) for (int j=0;j<5;j++) p[i+j] += h[i]*r[j];
    for (int k=8;k>=5;k--) { p[k-5] += 5*p[k]; p[k]=0; }
    u64 carry = 0;
    for (int i=0;i<5;i++) { p[i]+=carry; carry = p[i]>>26; p[i]&=M26; }
    p[0] += 5*carry;
    carry = p[0]>>26; p[0]&=M26; p[1]+=carry;
    for (int i=0;i<5;i++) h[i]=p[i];
}

static void poly1305_mac(const u8 key[32], const u8 *msg, size_t len, u8 tag[16]) {
    u8 rraw[16]; memcpy(rraw, key, 16);
    rraw[3]&=15; rraw[7]&=15; rraw[11]&=15; rraw[15]&=15;
    rraw[4]&=252; rraw[8]&=252; rraw[12]&=252;
    u64 lo=0, hi=0;
    for (int i=0;i<8;i++) lo |= (u64)rraw[i]<<(8*i);
    for (int i=0;i<8;i++) hi |= (u64)rraw[8+i]<<(8*i);
    u64 r[5];
    r[0]=lo&M26; r[1]=(lo>>26)&M26; r[2]=((lo>>52)|(hi<<12))&M26; r[3]=(hi>>14)&M26; r[4]=(hi>>40)&M26;
    u64 h[5] = {0,0,0,0,0};
    size_t off = 0;
    while (off < len) {
        size_t take = (len-off)<16?(len-off):16;
        poly1305_block(h, r, msg+off, take);
        off += take;
    }
    /* final full reduce mod p=2^130-5 */
    u64 carry = 0;
    for (int i=0;i<5;i++) { h[i]+=carry; carry=h[i]>>26; h[i]&=M26; }
    h[0] += 5*carry; carry = h[0]>>26; h[0]&=M26; h[1]+=carry;
    u64 g[5];
    u64 c2 = 5;
    for (int i=0;i<5;i++) { g[i] = h[i]+c2; c2 = g[i]>>26; g[i]&=M26; }
    g[4] -= (1ULL<<26); /* subtract 2^130 contribution to compare against p */
    u64 mask = (g[4] >> 63) ? 0 : ~0ULL; /* if g underflowed (h<p), g invalid -> use h */
    for (int i=0;i<5;i++) h[i] = (h[i] & ~mask) | (g[i] & mask);
    /* Pack h's 5x26-bit limbs into a 128-bit value as two u64 halves (lo, hi),
       dropping any bit at position >=128 -- safe because the tag is defined as
       (h+s) mod 2^128 anyway, so those bits would be discarded regardless.
       global bit layout: limb0[0,26) limb1[26,52) limb2[52,78) limb3[78,104) limb4[104,130) */
    u64 t_lo = h[0] | (h[1]<<26) | ((h[2] & 0xfffULL) << 52);
    u64 t_hi = (h[2] >> 12) | (h[3] << 14) | ((h[4] & 0xffffffULL) << 40);
    u64 slo=0, shi=0;
    for (int i=0;i<8;i++) slo |= (u64)key[16+i]<<(8*i);
    for (int i=0;i<8;i++) shi |= (u64)key[24+i]<<(8*i);
    u64 rlo = t_lo + slo;
    u64 rcarry = (rlo < t_lo) ? 1 : 0; /* detect the wraparound manually */
    u64 rhi = t_hi + shi + rcarry; /* mod 2^128 via natural u64 wraparound */
    for (int i=0;i<8;i++) tag[i] = (u8)(rlo >> (8*i));
    for (int i=0;i<8;i++) tag[8+i] = (u8)(rhi >> (8*i));
}
#undef M26

/* Scratch-buffer size for aead_seal/aead_open's MAC-input assembly: must
   fit the largest AAD+ciphertext+padding a TLS 1.3 record can ever contain.
   Deliberately independent of nanocurl.c's own BUFSZ macro (but the same
   value and derivation: 2^14=16384 plaintext bytes, +1 content-type byte,
   + up to 255 bytes of padding, + 16-byte AEAD tag = 16640, +128 slack) so
   this header doesn't depend on a macro defined by whoever includes it. */
#define AEAD_SCRATCH_MAX (16640 + 128)

/* AEAD_CHACHA20_POLY1305 per RFC 8439 */
static void aead_seal(const u8 key[32], const u8 nonce[12], const u8 *aad, size_t aadlen,
                       const u8 *pt, size_t ptlen, u8 *out /* ptlen + 16 */) {
    u8 polykey[64];
    chacha20_block(key, 0, nonce, polykey);
    chacha20_xor(key, 1, nonce, pt, out, ptlen);
    u8 macbuf[AEAD_SCRATCH_MAX]; size_t n = 0;
    memcpy(macbuf+n, aad, aadlen); n += aadlen;
    while (n % 16) macbuf[n++] = 0;
    memcpy(macbuf+n, out, ptlen); n += ptlen;
    while (n % 16) macbuf[n++] = 0;
    u64 al = aadlen, pl = ptlen;
    for (int i=0;i<8;i++) macbuf[n++] = (u8)(al>>(8*i));
    for (int i=0;i<8;i++) macbuf[n++] = (u8)(pl>>(8*i));
    u8 tag[16];
    poly1305_mac(polykey, macbuf, n, tag);
    memcpy(out+ptlen, tag, 16);
}

/* returns 1 on tag mismatch (we log it but, true to the "insecure" spirit,
   do NOT abort -- a real client obviously must) */
static int aead_open(const u8 key[32], const u8 nonce[12], const u8 *aad, size_t aadlen,
                      const u8 *ct, size_t ctlen /* includes 16-byte tag */, u8 *out) {
    size_t ptlen = ctlen - 16;
    u8 polykey[64];
    chacha20_block(key, 0, nonce, polykey);
    u8 macbuf[AEAD_SCRATCH_MAX]; size_t n = 0;
    memcpy(macbuf+n, aad, aadlen); n += aadlen;
    while (n % 16) macbuf[n++] = 0;
    memcpy(macbuf+n, ct, ptlen); n += ptlen;
    while (n % 16) macbuf[n++] = 0;
    u64 al = aadlen, pl = ptlen;
    for (int i=0;i<8;i++) macbuf[n++] = (u8)(al>>(8*i));
    for (int i=0;i<8;i++) macbuf[n++] = (u8)(pl>>(8*i));
    u8 tag[16]; poly1305_mac(polykey, macbuf, n, tag);
    int mismatch = memcmp(tag, ct+ptlen, 16) != 0;
    chacha20_xor(key, 1, nonce, ct, out, ptlen);
    return mismatch;
}

#endif /* NANOCURL_HANDSHAKE_CRYPTO_H */
