/*
 * nanocurl.c -- the absolute tiniest thing that can https-GET a page.
 *
 * TLS 1.3 only. Single ciphersuite: TLS_CHACHA20_POLY1305_SHA256.
 * Single key-exchange group: X25519.
 * NO certificate validation whatsoever (--insecure semantics, permanently).
 * We don't even parse the certificate: we skip Certificate / CertificateVerify
 * as opaque blobs, only feeding their raw bytes into the transcript hash,
 * because the handshake's key schedule and Finished MAC depend on that hash
 * even though we never check the signature it "proves".
 *
 * This is a teaching skeleton, not a library. It will break on:
 *  - servers that don't offer TLS_CHACHA20_POLY1305_SHA256 + x25519
 *  - HelloRetryRequest (server rejects our key_share group) - unhandled
 *  - handshake messages split weirdly across TCP segments in ways the
 *    (deliberately simplistic) reassembly logic doesn't expect
 *  - anything requiring ALPN/h2 fallback (we only ever ask for http/1.1
 *    implicitly by not sending ALPN at all -- most servers still allow
 *    plain HTTP/1.1 on the wire when ALPN is absent, but not universally)
 *
 * Build:  gcc -O2 -o nanocurl nanocurl.c
 * Run:    ./nanocurl example.com /
 *
 * A security expert reading this should be rolling their eyes. That is
 * intentional and the whole point of the exercise.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* TLS 1.3 max ciphertext record size: 2^14 (16384) plaintext bytes, +1 content-type
   byte, + up to 255 bytes of padding, + 16-byte AEAD tag = 16640. Every buffer that
   might hold a full record (ciphertext, plaintext, or the AAD+ciphertext+padding+
   length scratch space used for the Poly1305 MAC) needs to be at least this big --
   getting this wrong is exactly what caused the stack buffer overflow this constant
   now prevents. A little headroom on top costs nothing.  */
#define TLS_MAX_RECORD 16640
#define BUFSZ (TLS_MAX_RECORD + 128)

/* ======================================================================
 * SHA-256 (textbook FIPS 180-4)
 * ==================================================================== */

typedef struct { u32 s[8]; u8 buf[64]; u64 len; } sha256_ctx;

static const u32 SHA256_K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha256_block(sha256_ctx *c, const u8 *p) {
    u32 w[64], a,b,cc,d,e,f,g,h,i,t1,t2;
    for (i=0;i<16;i++) w[i]=((u32)p[4*i]<<24)|((u32)p[4*i+1]<<16)|((u32)p[4*i+2]<<8)|(u32)p[4*i+3];
    for (;i<64;i++) {
        u32 s0 = ROTR(w[i-15],7)^ROTR(w[i-15],18)^(w[i-15]>>3);
        u32 s1 = ROTR(w[i-2],17)^ROTR(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i=0;i<64;i++) {
        u32 S1 = ROTR(e,6)^ROTR(e,11)^ROTR(e,25);
        u32 ch = (e&f)^((~e)&g);
        t1 = h+S1+ch+SHA256_K[i]+w[i];
        u32 S0 = ROTR(a,2)^ROTR(a,13)^ROTR(a,22);
        u32 maj = (a&b)^(a&cc)^(b&cc);
        t2 = S0+maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(sha256_ctx *c) {
    static const u32 iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(c->s, iv, sizeof iv); c->len = 0;
}
static void sha256_update(sha256_ctx *c, const u8 *data, size_t n) {
    size_t off = c->len % 64;
    c->len += n;
    while (n) {
        size_t take = 64-off < n ? 64-off : n;
        memcpy(c->buf+off, data, take);
        off += take; data += take; n -= take;
        if (off == 64) { sha256_block(c, c->buf); off = 0; }
    }
}
/* finalize a *copy* so the running context stays usable (needed for transcript snapshots) */
static void sha256_final_copy(sha256_ctx c, u8 out[32]) {
    u64 bitlen = c.len*8;
    u8 pad = 0x80;
    sha256_update(&c, &pad, 1);
    u8 z = 0;
    while (c.len % 64 != 56) sha256_update(&c, &z, 1);
    u8 lenbytes[8];
    for (int i=0;i<8;i++) lenbytes[i] = (u8)(bitlen >> (56-8*i));
    sha256_update(&c, lenbytes, 8);
    for (int i=0;i<8;i++) {
        out[4*i]=c.s[i]>>24; out[4*i+1]=c.s[i]>>16; out[4*i+2]=c.s[i]>>8; out[4*i+3]=c.s[i];
    }
}
static void sha256(const u8 *data, size_t n, u8 out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, n); sha256_final_copy(c, out);
}

/* ======================================================================
 * HMAC-SHA256 / HKDF / TLS1.3 Expand-Label
 * ==================================================================== */

static void hmac_sha256(const u8 *key, size_t klen, const u8 *msg, size_t mlen, u8 out[32]) {
    u8 k[64] = {0};
    if (klen > 64) sha256(key, klen, k); else memcpy(k, key, klen);
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
 * X25519  (field arithmetic derived from the well-known TweetNaCl layout:
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
 * ChaCha20 / Poly1305 / AEAD  (RFC 8439)
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
    u64 rhi = t_hi + shi + rcarry;     /* mod 2^128 via natural u64 wraparound */
    for (int i=0;i<8;i++) tag[i]   = (u8)(rlo >> (8*i));
    for (int i=0;i<8;i++) tag[8+i] = (u8)(rhi >> (8*i));
}

/* AEAD_CHACHA20_POLY1305 per RFC 8439 */
static void pad16(sha256_ctx *unused){ (void)unused; } /* placeholder, real pad done inline below */

static void aead_seal(const u8 key[32], const u8 nonce[12], const u8 *aad, size_t aadlen,
                       const u8 *pt, size_t ptlen, u8 *out /* ptlen + 16 */) {
    u8 polykey[64];
    chacha20_block(key, 0, nonce, polykey);
    chacha20_xor(key, 1, nonce, pt, out, ptlen);
    u8 macbuf[BUFSZ]; size_t n = 0;
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
    u8 macbuf[BUFSZ]; size_t n = 0;
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

/* ======================================================================
 * TCP plumbing
 * ==================================================================== */
/* Appends a formatted string to buf at offset off, never writing past bufsz
   and never returning an offset that could underflow a later bufsz-off. Used
   to build the HTTP request line-by-line with a variable number of -H
   headers without worrying about snprintf's truncation-return-value trap. */
static size_t buf_append(char *buf, size_t bufsz, size_t off, const char *fmt, ...) {
    if (off >= bufsz) return off;
    va_list ap; va_start(ap, fmt);
    int w = vsnprintf(buf + off, bufsz - off, fmt, ap);
    va_end(ap);
    if (w < 0) return off;
    size_t neww = off + (size_t)w;
    return neww < bufsz ? neww : bufsz;
}

/* True if `line` is (or starts) a header with the given name, e.g.
   header_name_is("Host: example.com", "Host") -> true. Case-insensitive,
   as HTTP header names are. */
static int header_name_is(const char *line, const char *name) {
    size_t nlen = strlen(name);
    return strncasecmp(line, name, nlen) == 0 && line[nlen] == ':';
}
static int has_header(const char *const *headers, int n, const char *name) {
    for (int i = 0; i < n; i++) if (header_name_is(headers[i], name)) return 1;
    return 0;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) { perror("getaddrinfo"); exit(1); }
    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); exit(1); }
    return fd;
}
static void send_all(int fd, const u8 *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf+off, n-off, 0);
        if (w <= 0) { perror("send"); exit(1); }
        off += w;
    }
}
static void recv_all(int fd, u8 *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf+off, n-off, 0);
        if (r <= 0) { fprintf(stderr, "connection closed / recv error\n"); exit(1); }
        off += r;
    }
}

/* ======================================================================
 * TLS 1.3 engine
 * ==================================================================== */

typedef struct {
    int fd;
    sha256_ctx transcript;
    /* record-layer keys currently in force for each direction */
    u8 c_key[32], c_iv[12]; u64 c_seq;
    u8 s_key[32], s_iv[12]; u64 s_seq;
    /* buffer of decrypted-but-unconsumed handshake bytes */
    u8 hsbuf[BUFSZ]; size_t hslen, hsoff;
} tls_t;

static void mk_nonce(u8 out[12], const u8 iv[12], u64 seq) {
    memcpy(out, iv, 12);
    for (int i=0;i<8;i++) out[4+i] ^= (u8)(seq >> (56-8*i));
}

/* read one TLS record, decrypt if type==application_data(23) and s_key is active,
   return the *inner* content type and payload (payload buffer supplied by caller) */
static u8 read_record(tls_t *t, u8 *payload, size_t *paylen, int decrypt) {
    u8 hdr[5];
    recv_all(t->fd, hdr, 5);
    u8 rectype = hdr[0];
    size_t rlen = (hdr[3]<<8) | hdr[4];
    u8 body[BUFSZ];
    recv_all(t->fd, body, rlen);
    if (rectype == 20) { /* change_cipher_spec, ignore entirely */
        *paylen = 0; return 20;
    }
    if (!decrypt) {
        memcpy(payload, body, rlen);
        *paylen = rlen;
        return rectype; /* plaintext handshake (ClientHello/ServerHello phase) */
    }
    u8 nonce[12]; mk_nonce(nonce, t->s_iv, t->s_seq++);
    u8 plain[BUFSZ];
    int bad = aead_open(t->s_key, nonce, hdr, 5, body, rlen, plain);
    if (bad) fprintf(stderr, "[warn] record MAC mismatch (seq %llu) -- decoding anyway\n",
                      (unsigned long long)(t->s_seq-1));
    size_t plen = rlen - 16;
    while (plen > 0 && plain[plen-1] == 0) plen--; /* strip zero padding */
    u8 inner_type = plain[plen-1];
    memcpy(payload, plain, plen-1);
    *paylen = plen-1;
    return inner_type;
}

static void write_record(tls_t *t, u8 type, const u8 *data, size_t len, int encrypt) {
    if (!encrypt) {
        u8 hdr[5] = {type, 0x03, 0x03, (u8)(len>>8), (u8)len};
        send_all(t->fd, hdr, 5);
        send_all(t->fd, data, len);
        return;
    }
    u8 plain[BUFSZ];
    memcpy(plain, data, len);
    plain[len] = type; /* real content type goes at the end before encryption */
    size_t ctlen = len+1+16;
    u8 hdr[5] = {23, 0x03, 0x03, (u8)(ctlen>>8), (u8)ctlen};
    u8 nonce[12]; mk_nonce(nonce, t->c_iv, t->c_seq++);
    u8 out[BUFSZ];
    aead_seal(t->c_key, nonce, hdr, 5, plain, len+1, out);
    send_all(t->fd, hdr, 5);
    send_all(t->fd, out, ctlen);
}

/* pull exactly n bytes of decrypted handshake stream, refilling from records as needed */
static void hs_fill(tls_t *t, int decrypt) {
    u8 payload[BUFSZ]; size_t plen;
    for (;;) {
        u8 type = read_record(t, payload, &plen, decrypt);
        if (type == 20) continue; /* change_cipher_spec, skip */
        if (type == 21) { fprintf(stderr, "TLS alert received, aborting\n"); exit(1); }
        if (type == 22 || type == 24 /* handshake, incl. inner post-decrypt */) {
            memcpy(t->hsbuf+t->hslen, payload, plen);
            t->hslen += plen;
            return;
        }
    }
}
static void hs_read(tls_t *t, u8 *out, size_t n, int decrypt) {
    while (t->hslen - t->hsoff < n) hs_fill(t, decrypt);
    memcpy(out, t->hsbuf+t->hsoff, n);
    t->hsoff += n;
    if (t->hsoff == t->hslen) t->hsoff = t->hslen = 0;
}

/* Reads and hashes handshake messages (EncryptedExtensions, Certificate,
   CertificateVerify, ...) until the server's Finished message, discarding
   their content entirely -- see the top-of-file note on why. Its BUFSZ-sized
   scratch buffer lives in this function's own stack frame, not main's. */
static void consume_handshake_to_finished(tls_t *t) {
    for (;;) {
        u8 hh[4]; hs_read(t, hh, 4, 1);
        size_t hl = (hh[1]<<16)|(hh[2]<<8)|hh[3];
        u8 hb[BUFSZ]; hs_read(t, hb, hl, 1);
        sha256_update(&t->transcript, hh, 4);
        sha256_update(&t->transcript, hb, hl);
        if (hh[0] == 20) break; /* Finished */
        /* EncryptedExtensions / Certificate / CertificateVerify: intentionally
           not parsed at all -- this is the whole point of the exercise. */
    }
}

static void print_tls_alert(const u8 *payload, size_t plen) {
    const char *lvl = (plen>0 && payload[0]==1) ? "warning" :
                       (plen>0 && payload[0]==2) ? "fatal" : "?";
    int desc = plen>1 ? payload[1] : -1;
    const char *name = "unknown";
    switch (desc) {
        case 0: name="close_notify"; break;
        case 10: name="unexpected_message"; break;
        case 20: name="bad_record_mac"; break;
        case 40: name="handshake_failure"; break;
        case 42: name="bad_certificate"; break;
        case 47: name="illegal_parameter"; break;
        case 70: name="protocol_version"; break;
        case 80: name="internal_error"; break;
        case 109: name="missing_extension"; break;
        case 110: name="unsupported_extension"; break;
        case 112: name="unrecognized_name"; break;
        case 116: name="certificate_required"; break;
        case 120: name="no_application_protocol"; break;
    }
    fprintf(stderr, "[tls alert] level=%s description=%d (%s)\n", lvl, desc, name);
}

/* --- minimal response streamer: pulls decrypted application-data records one
   at a time (never more than one BUFSZ-sized record buffered at once -- we
   fully drain each record before fetching the next, so no lookahead buffer
   is needed), and exposes byte-at-a-time and bulk-copy access on top. This
   is what both the header scan and the chunked-encoding parser are built
   from, since both need to react to individual bytes (CRLFs, hex digits)
   without caring how TLS happened to fragment the underlying records. */
typedef struct {
    tls_t *t;
    u8 buf[BUFSZ];
    size_t len, off;
    int done;
} respstream_t;

static void rs_init(respstream_t *rs, tls_t *t) { rs->t = t; rs->len = rs->off = 0; rs->done = 0; }

/* fetch the next non-empty application-data record's payload into buf,
   printing+swallowing an alert (and marking the stream done) if that's
   what arrives instead. Returns 0 once there's nothing more to read. */
static int rs_fill_one_record(respstream_t *rs) {
    if (rs->done) return 0;
    for (;;) {
        u8 payload[BUFSZ]; size_t plen;
        u8 type = read_record(rs->t, payload, &plen, 1);
        if (type == 21) { print_tls_alert(payload, plen); rs->done = 1; return 0; }
        if (type == 23) {
            if (plen == 0) continue; /* empty app-data record: legal, just skip it */
            memcpy(rs->buf, payload, plen);
            rs->len = plen; rs->off = 0;
            return 1;
        }
        /* type 20/22/24: change_cipher_spec / stray post-handshake handshake
           message (e.g. NewSessionTicket) / other -- silently skip, loop for more */
    }
}

static int rs_getc(respstream_t *rs) {
    if (rs->off >= rs->len && !rs_fill_one_record(rs)) return -1;
    return rs->buf[rs->off++];
}

/* copy up to n bytes from the stream to `out` (pass NULL to discard them
   instead of writing). Returns bytes actually copied, which is less than n
   only once the stream has ended. */
static size_t rs_copy(respstream_t *rs, FILE *out, size_t n) {
    size_t copied = 0;
    while (copied < n) {
        if (rs->off >= rs->len && !rs_fill_one_record(rs)) break;
        size_t avail = rs->len - rs->off;
        size_t take = (n - copied) < avail ? (n - copied) : avail;
        if (out) fwrite(rs->buf + rs->off, 1, take, out);
        rs->off += take;
        copied += take;
    }
    return copied;
}

static int ci_contains(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i] && tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) i++;
        if (i == nlen) return 1;
    }
    return 0;
}

/* Reads the HTTP response: the header block (echoed to stdout only if
   show_headers is set), then the body -- transparently stripping chunked
   transfer-encoding framing if the headers declared it, since that framing
   is wire-format plumbing, not content. No decompression, no trailers
   beyond discarding them, no redirect following: matches the rest of this
   program's ambitions exactly. */
static void stream_http_response(tls_t *t, int show_headers) {
    respstream_t rs; rs_init(&rs, t);

    char hdrbuf[8192]; size_t hdrlen = 0;
    int crlf_run = 0;
    for (;;) {
        int c = rs_getc(&rs);
        if (c < 0) return; /* connection ended before headers completed */
        if (show_headers) fputc(c, stdout);
        if (hdrlen < sizeof(hdrbuf) - 1) hdrbuf[hdrlen++] = (char)c;
        if ((crlf_run==0 && c=='\r') || (crlf_run==1 && c=='\n') ||
            (crlf_run==2 && c=='\r') || (crlf_run==3 && c=='\n')) {
            if (++crlf_run == 4) break;
        } else {
            crlf_run = (c == '\r') ? 1 : 0;
        }
    }
    hdrbuf[hdrlen] = '\0';
    int chunked = ci_contains(hdrbuf, "transfer-encoding:") && ci_contains(hdrbuf, "chunked");

    if (!chunked) {
        while (rs_copy(&rs, stdout, BUFSZ) > 0) { /* keep draining until EOF */ }
        return;
    }

    for (;;) {
        char sizeline[64]; size_t sl = 0;
        for (;;) {
            int c = rs_getc(&rs);
            if (c < 0) return; /* connection dropped mid-chunk-stream */
            if (c == '\n') break;
            if (c != '\r' && sl < sizeof(sizeline) - 1) sizeline[sl++] = (char)c;
        }
        sizeline[sl] = '\0';
        unsigned long chunklen = strtoul(sizeline, NULL, 16); /* stops at ';' chunk-extensions, if any */
        if (chunklen == 0) {
            /* final chunk: consume and discard any trailer headers up to the blank line */
            int cr = 0;
            for (;;) {
                int c = rs_getc(&rs);
                if (c < 0) break;
                if ((cr==0 && c=='\r') || (cr==1 && c=='\n')) { if (++cr == 2) break; }
                else cr = (c == '\r') ? 1 : 0;
            }
            return;
        }
        rs_copy(&rs, stdout, chunklen);
        rs_getc(&rs); rs_getc(&rs); /* each chunk is followed by a mandatory CRLF */
    }
}

#define MAX_EXTRA_HEADERS 32
typedef struct {
    int show_headers;
    const char *extra_headers[MAX_EXTRA_HEADERS];
    int n_extra_headers;
    const char *url; /* borrowed pointer into argv */
} parsed_args_t;

/* Parses -D - and any number of -H 'Header: value' flags, in any order,
   preceding the URL. Returns 1 with out->url set on success, 0 if no URL
   token was found (caller should print usage and bail). */
static int parse_args(int argc, char **argv, parsed_args_t *out) {
    out->show_headers = 0;
    out->n_extra_headers = 0;
    int argi = 1;
    while (argi < argc) {
        if (strcmp(argv[argi], "-D") == 0 && argi+1 < argc && strcmp(argv[argi+1], "-") == 0) {
            out->show_headers = 1; argi += 2; continue;
        }
        if (strcmp(argv[argi], "-H") == 0 && argi+1 < argc) {
            if (out->n_extra_headers < MAX_EXTRA_HEADERS)
                out->extra_headers[out->n_extra_headers++] = argv[argi+1];
            else
                fprintf(stderr, "warning: more than %d -H headers given, ignoring the rest\n", MAX_EXTRA_HEADERS);
            argi += 2; continue;
        }
        break; /* first token that isn't a recognized flag is the URL */
    }
    if (argi >= argc) return 0;
    out->url = argv[argi];
    return 1;
}

typedef struct {
    char host[256];
    char port[16];
    char path[1024];
} parsed_url_t;

/* Minimal URL parsing: strips an optional "https://" prefix (any other
   scheme is silently ignored -- this tool only ever speaks TLS), splits
   host[:port] from path at the first '/', and splits an optional ":port"
   (default 443) off the host. No query-string edge cases, IPv6 literal, or
   userinfo handling -- deliberately bare-bones. */
static void parse_url(const char *url, parsed_url_t *out) {
    if (strncmp(url, "https://", 8) == 0) url += 8;
    char hostport[256];
    const char *slash = strchr(url, '/');
    if (slash) {
        size_t hplen = (size_t)(slash - url);
        if (hplen >= sizeof hostport) hplen = sizeof(hostport) - 1;
        memcpy(hostport, url, hplen); hostport[hplen] = '\0';
        snprintf(out->path, sizeof out->path, "%s", slash);
    } else {
        snprintf(hostport, sizeof hostport, "%s", url);
        snprintf(out->path, sizeof out->path, "/");
    }
    snprintf(out->port, sizeof out->port, "443");
    const char *colon = strchr(hostport, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - hostport);
        if (hlen >= sizeof out->host) hlen = sizeof(out->host) - 1;
        memcpy(out->host, hostport, hlen); out->host[hlen] = '\0';
        snprintf(out->port, sizeof out->port, "%s", colon + 1);
    } else {
        snprintf(out->host, sizeof out->host, "%s", hostport);
    }
}

#ifndef NANOCURL_NO_MAIN
int main(int argc, char **argv) {
    parsed_args_t args;
    if (!parse_args(argc, argv, &args)) {
        fprintf(stderr, "usage: %s [-D -] [-H 'Header: value']... [https://]host[:port][/path]\n", argv[0]);
        return 1;
    }
    parsed_url_t u;
    parse_url(args.url, &u);
    const char *host = u.host;
    const char *path = u.path;
    const char *port = u.port;
    int show_headers = args.show_headers;
    const char *const *extra_headers = args.extra_headers;
    int n_extra_headers = args.n_extra_headers;

    tls_t t = {0};
    t.fd = tcp_connect(host, port);
    sha256_init(&t.transcript);

    /* --- keypair --- */
    u8 priv[32], pub[32];
    FILE *rf = fopen("/dev/urandom", "rb"); fread(priv, 1, 32, rf); fclose(rf);
    x25519_base(pub, priv);

    /* --- build ClientHello --- */
    u8 ch[1024]; size_t n = 0;
    u8 crandom[32]; rf = fopen("/dev/urandom","rb"); fread(crandom,1,32,rf); fclose(rf);

    u8 body[900]; size_t bn = 0;
    body[bn++]=0x03; body[bn++]=0x03;               /* legacy_version */
    memcpy(body+bn, crandom, 32); bn += 32;          /* random */
    body[bn++] = 32;                                 /* legacy_session_id len */
    memcpy(body+bn, crandom, 32); bn += 32;           /* (reuse random bytes, doesn't matter) */
    body[bn++]=0x00; body[bn++]=0x02;                 /* cipher_suites len=2 */
    body[bn++]=0x13; body[bn++]=0x03;                  /* TLS_CHACHA20_POLY1305_SHA256 */
    body[bn++]=0x01; body[bn++]=0x00;                 /* compression: len=1, null */

    u8 ext[512]; size_t en = 0;
    /* server_name */
    { size_t hl = strlen(host);
      ext[en++]=0x00; ext[en++]=0x00;
      size_t extlen = 2+1+2+hl;
      ext[en++]=(extlen>>8); ext[en++]=extlen;
      size_t listlen = 1+2+hl;
      ext[en++]=(listlen>>8); ext[en++]=listlen;
      ext[en++]=0x00; /* host_name type */
      ext[en++]=(hl>>8); ext[en++]=hl;
      memcpy(ext+en, host, hl); en += hl;
    }
    /* supported_versions */
    ext[en++]=0x00; ext[en++]=0x2b; ext[en++]=0x00; ext[en++]=0x03;
    ext[en++]=0x02; ext[en++]=0x03; ext[en++]=0x04;
    /* supported_groups: x25519 */
    ext[en++]=0x00; ext[en++]=0x0a; ext[en++]=0x00; ext[en++]=0x04;
    ext[en++]=0x00; ext[en++]=0x02; ext[en++]=0x00; ext[en++]=0x1d;
    /* signature_algorithms (unused by us, but servers require it present) */
    {
        static const u8 sigs[] = {0x04,0x03, 0x08,0x04, 0x04,0x01, 0x08,0x07};
        ext[en++]=0x00; ext[en++]=0x0d;
        size_t l = sizeof(sigs);
        ext[en++]=0; ext[en++]=(u8)(l+2);
        ext[en++]=(l>>8); ext[en++]=l;
        memcpy(ext+en, sigs, l); en += l;
    }
    /* key_share: x25519 */
    {
        ext[en++]=0x00; ext[en++]=0x33;
        size_t l = 2+2+2+32;
        ext[en++]=(l>>8); ext[en++]=l;
        size_t l2 = 2+2+32;
        ext[en++]=(l2>>8); ext[en++]=l2;
        ext[en++]=0x00; ext[en++]=0x1d; /* x25519 */
        ext[en++]=0x00; ext[en++]=0x20; /* 32 bytes */
        memcpy(ext+en, pub, 32); en += 32;
    }
    /* ALPN: offer http/1.1 -- several real-world edges (Fastly/Cloudflare-class)
       send a fatal no_application_protocol alert if this is absent entirely */
    {
        static const char proto[] = "http/1.1";
        size_t plen = sizeof(proto)-1;
        ext[en++]=0x00; ext[en++]=0x10;
        size_t extlen = 2+1+plen;
        ext[en++]=(extlen>>8); ext[en++]=extlen;
        size_t listlen = 1+plen;
        ext[en++]=(listlen>>8); ext[en++]=listlen;
        ext[en++]=(u8)plen;
        memcpy(ext+en, proto, plen); en += plen;
    }
    body[bn++]=(en>>8); body[bn++]=en;
    memcpy(body+bn, ext, en); bn += en;

    ch[n++]=0x01; /* handshake type: client_hello */
    ch[n++]=(bn>>16); ch[n++]=(bn>>8); ch[n++]=bn;
    memcpy(ch+n, body, bn); n += bn;

    sha256_update(&t.transcript, ch, n);
    write_record(&t, 22, ch, n, 0);
    /* fake change_cipher_spec for middlebox compatibility */
    { u8 ccs = 0x01; write_record(&t, 20, &ccs, 1, 0); }

    /* --- read ServerHello (plaintext) --- */
    u8 shdr[4]; hs_read(&t, shdr, 4, 0);
    size_t shlen = (shdr[1]<<16)|(shdr[2]<<8)|shdr[3];
    u8 shbody[1024]; hs_read(&t, shbody, shlen, 0);
    sha256_update(&t.transcript, shdr, 4);
    sha256_update(&t.transcript, shbody, shlen);

    /* parse just enough of ServerHello to get the server's key_share pubkey */
    u8 server_pub[32] = {0};
    { size_t p = 2+32; /* skip legacy_version, random */
      u8 sidlen = shbody[p]; p += 1+sidlen;   /* session_id echo */
      p += 2;                                  /* cipher_suite */
      p += 1;                                  /* legacy_compression_method */
      size_t extlen = (shbody[p]<<8)|shbody[p+1]; p += 2;
      size_t end = p+extlen;
      while (p < end) {
          u32 et = (shbody[p]<<8)|shbody[p+1]; p+=2;
          size_t elen = (shbody[p]<<8)|shbody[p+1]; p+=2;
          if (et == 0x33) { /* key_share */
              /* group(2) + len(2) + key */
              memcpy(server_pub, shbody+p+4, 32);
          }
          p += elen;
      }
    }

    /* --- key schedule --- */
    u8 zero32[32] = {0};
    u8 early[32]; hkdf_extract(zero32, 32, zero32, 32, early);
    u8 derived1[32]; { sha256_ctx snap; sha256_init(&snap); derive_secret(early, "derived", snap, derived1); }

    u8 shared[32]; x25519_scalarmult(shared, priv, server_pub);
    u8 hs_secret[32]; hkdf_extract(derived1, 32, shared, 32, hs_secret);

    u8 c_hs_secret[32], s_hs_secret[32];
    derive_secret(hs_secret, "c hs traffic", t.transcript, c_hs_secret);
    derive_secret(hs_secret, "s hs traffic", t.transcript, s_hs_secret);

    expand_label(c_hs_secret, "key", (u8*)"", 0, t.c_key, 32);
    expand_label(c_hs_secret, "iv",  (u8*)"", 0, t.c_iv, 12);
    expand_label(s_hs_secret, "key", (u8*)"", 0, t.s_key, 32);
    expand_label(s_hs_secret, "iv",  (u8*)"", 0, t.s_iv, 12);
    t.c_seq = t.s_seq = 0;

    /* --- consume EncryptedExtensions, Certificate, CertificateVerify, Finished
           (hash-only skip; see consume_handshake_to_finished) --- */
    consume_handshake_to_finished(&t);
    /* IMPORTANT: application_traffic_secret derivation (RFC 8446 sec 7.1) uses
       the transcript hash through ClientHello...server Finished -- it must NOT
       include our own client Finished, which we're about to hash in next. */
    sha256_ctx transcript_after_server_finished = t.transcript;

    /* client Finished */
    u8 c_fin_key[32]; expand_label(c_hs_secret, "finished", (u8*)"", 0, c_fin_key, 32);
    u8 th[32]; { sha256_ctx snap = t.transcript; sha256_final_copy(snap, th); }
    u8 c_verify[32]; hmac_sha256(c_fin_key, 32, th, 32, c_verify);
    u8 finmsg[4+32];
    finmsg[0]=20; finmsg[1]=0; finmsg[2]=0; finmsg[3]=32;
    memcpy(finmsg+4, c_verify, 32);
    sha256_update(&t.transcript, finmsg, 36);
    write_record(&t, 22, finmsg, 36, 1);

    /* --- application traffic secrets --- */
    u8 derived2[32];
    { sha256_ctx empty; sha256_init(&empty); derive_secret(hs_secret, "derived", empty, derived2); }
    u8 master[32]; hkdf_extract(derived2, 32, zero32, 32, master);

    u8 c_ap_secret[32], s_ap_secret[32];
    derive_secret(master, "c ap traffic", transcript_after_server_finished, c_ap_secret);
    derive_secret(master, "s ap traffic", transcript_after_server_finished, s_ap_secret);
    expand_label(c_ap_secret, "key", (u8*)"", 0, t.c_key, 32);
    expand_label(c_ap_secret, "iv",  (u8*)"", 0, t.c_iv, 12);
    expand_label(s_ap_secret, "key", (u8*)"", 0, t.s_key, 32);
    expand_label(s_ap_secret, "iv",  (u8*)"", 0, t.s_iv, 12);
    t.c_seq = t.s_seq = 0;

    /* --- HTTP/1.1 GET, hand-rolled --- */
    char req[4096];
    size_t rn = 0;
    rn = buf_append(req, sizeof req, rn, "GET %s HTTP/1.1\r\n", path);
    if (!has_header(extra_headers, n_extra_headers, "Host"))
        rn = buf_append(req, sizeof req, rn, "Host: %s\r\n", host);
    if (!has_header(extra_headers, n_extra_headers, "Connection"))
        rn = buf_append(req, sizeof req, rn, "Connection: close\r\n");
    if (!has_header(extra_headers, n_extra_headers, "User-Agent"))
        rn = buf_append(req, sizeof req, rn, "User-Agent: nanocurl/0.0\r\n");
    for (int i = 0; i < n_extra_headers; i++)
        rn = buf_append(req, sizeof req, rn, "%s\r\n", extra_headers[i]);
    rn = buf_append(req, sizeof req, rn, "\r\n");
    write_record(&t, 23, (u8*)req, rn, 1);

    stream_http_response(&t, show_headers);
    close(t.fd);
    return 0;
}
#endif /* NANOCURL_NO_MAIN */
