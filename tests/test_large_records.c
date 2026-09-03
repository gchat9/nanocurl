/* Regression test for the aead_open() stack buffer overflow: macbuf[8192]
   was too small for real-world TLS records once they got past ~8KB, which
   silently corrupted stack memory (and thus decrypted output) rather than
   crashing outright. This reproduces both the exact incident size that
   first exposed it (a ~10.7KB Wikimedia response) and the true TLS 1.3
   protocol maximum, so a future regression can't slip back in unnoticed.
   Build this one with -fsanitize=address,undefined -- see the Makefile. */
#define NANOCURL_NO_MAIN
#include "../nanocurl.c"

static int check_roundtrip(const char *label, size_t ptlen) {
    u8 key[32]; memset(key, 0x11, 32);
    u8 nonce[12]; memset(nonce, 0x22, 12);
    u8 *pt = malloc(ptlen);
    for (size_t i=0;i<ptlen;i++) pt[i] = (u8)(i*7+3);
    u8 *ct = malloc(ptlen+16);
    aead_seal(key, nonce, (u8*)"hdr", 3, pt, ptlen, ct);
    u8 *out = malloc(BUFSZ);
    int bad = aead_open(key, nonce, (u8*)"hdr", 3, ct, ptlen+16, out);
    int match = memcmp(pt, out, ptlen) == 0;
    int ok = !bad && match;
    printf("%s  %s (ptlen=%zu): tag_bad=%d content_match=%s\n",
           ok ? "PASS" : "FAIL", label, ptlen, bad, match ? "yes" : "no");
    free(pt); free(ct); free(out);
    return ok;
}

int main(void) {
    int ok = 1;
    /* the exact size that originally exposed the bug against a live server */
    ok &= check_roundtrip("incident-size record", 10711);
    /* true TLS 1.3 max: 16384 plaintext + 1 content-type byte + 255 padding
       = 16640 ciphertext bytes incl. 16-byte tag -> 16624 plaintext bytes */
    ok &= check_roundtrip("protocol-max record", 16624);
    return ok ? 0 : 1;
}
