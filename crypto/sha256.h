/*
 * sha256.h -- textbook FIPS 180-4 SHA-256, header-only.
 *
 * Shared by nanocurl.c (TLS key schedule, HMAC) and nanocurl-verify.c
 * (RSA/PSS padding, hashing TBSCertificate/CertificateVerify content).
 * Before this header existed, both files carried their own byte-for-byte
 * identical copy of this implementation -- exactly the kind of duplication
 * a shared header is for.
 *
 * Every function here is `static`: each translation unit that includes
 * this header gets its own copy of the code, so there's no linkage to
 * worry about, but also no size cost beyond what that one binary actually
 * calls -- an unused static function is dropped by the compiler at -O2.
 */
#ifndef NANOCURL_SHA256_H
#define NANOCURL_SHA256_H

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#ifndef NANOCURL_BASIC_TYPES_DEFINED
#define NANOCURL_BASIC_TYPES_DEFINED
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

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

#define SHA256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_block(sha256_ctx *c, const u8 *p) {
    u32 w[64], a,b,cc,d,e,f,g,h,i,t1,t2;
    for (i=0;i<16;i++) w[i]=((u32)p[4*i]<<24)|((u32)p[4*i+1]<<16)|((u32)p[4*i+2]<<8)|(u32)p[4*i+3];
    for (;i<64;i++) {
        u32 s0 = SHA256_ROTR(w[i-15],7)^SHA256_ROTR(w[i-15],18)^(w[i-15]>>3);
        u32 s1 = SHA256_ROTR(w[i-2],17)^SHA256_ROTR(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (i=0;i<64;i++) {
        u32 S1 = SHA256_ROTR(e,6)^SHA256_ROTR(e,11)^SHA256_ROTR(e,25);
        u32 ch = (e&f)^((~e)&g);
        t1 = h+S1+ch+SHA256_K[i]+w[i];
        u32 S0 = SHA256_ROTR(a,2)^SHA256_ROTR(a,13)^SHA256_ROTR(a,22);
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

/* finalizes a *copy* of the context, leaving the original untouched --
   needed for TLS transcript-hash snapshots (nanocurl.c) and for reusing a
   seed hash repeatedly in MGF1 (nanocurl-verify.c). */
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

static void sha256_oneshot(const u8 *data, size_t n, u8 out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, n); sha256_final_copy(c, out);
}

#endif /* NANOCURL_SHA256_H */
