/*
 * test_chain.c -- unit tests for nanocurl-verify's hand-rolled trust-store
 * loading and chain-of-trust verification (phase 4 of the OpenSSL
 * migration).
 *
 * Uses a small local root -> intermediate -> leaf hierarchy (see
 * gen_chain_fixtures.sh) rather than the real system trust store, so these
 * tests are hermetic and don't depend on what happens to be installed.
 * The hierarchy deliberately mixes RSA and EC keys/signatures (RSA root
 * signs an EC intermediate; the EC intermediate signs an RSA leaf) so both
 * hand-rolled signature-verification paths get exercised by chain-building,
 * not just by their own dedicated test files.
 *
 * Run: ./run.sh
 * Regenerate fixtures (only if adding/changing one): ./gen_chain_fixtures.sh
 */
#define NANOCURL_VERIFY_NO_MAIN
#include <stdio.h> /* this test file's own printf/fopen/etc. -- nanocurl-verify.c
                      itself no longer pulls this in (see strlite.h) */
#include "../nanocurl-verify.c"

static int failures = 0;

#define CHECK(cond, desc) do { \
    if (cond) printf("  ok   %s\n", desc); \
    else { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

static u8 *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno)); exit(2); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    u8 *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "short read on %s\n", path); exit(2); }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static void test_b64_and_pem(void) {
    printf("base64 / PEM decoding:\n");
    u8 out[16];
    long n = b64_decode("aGVsbG8=", 8, out, sizeof out); /* "hello" */
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64_decode handles padding correctly");
    n = b64_decode("aGVs\nbG8=", 9, out, sizeof out); /* same, with an embedded newline */
    CHECK(n == 5 && memcmp(out, "hello", 5) == 0, "b64_decode tolerates embedded whitespace");
    n = b64_decode("not!valid", 9, out, sizeof out);
    CHECK(n < 0, "b64_decode rejects invalid characters");

    size_t rootlen; u8 *root = read_file("chain_fixtures/root.der", &rootlen);
    char pem[4096];
    int plen = snprintf(pem, sizeof pem, "junk before\n-----BEGIN CERTIFICATE-----\n");
    /* base64-encode root for a round-trip PEM parse test */
    static const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    for (; i + 2 < rootlen; i += 3) {
        u32 v = (root[i]<<16)|(root[i+1]<<8)|root[i+2];
        pem[plen++] = b64chars[(v>>18)&0x3f]; pem[plen++] = b64chars[(v>>12)&0x3f];
        pem[plen++] = b64chars[(v>>6)&0x3f]; pem[plen++] = b64chars[v&0x3f];
        if ((i/3) % 16 == 15) pem[plen++] = '\n';
    }
    size_t remaining = rootlen - i;
    if (remaining == 1) {
        u32 v = root[i] << 16;
        pem[plen++] = b64chars[(v>>18)&0x3f]; pem[plen++] = b64chars[(v>>12)&0x3f];
        pem[plen++] = '='; pem[plen++] = '=';
    } else if (remaining == 2) {
        u32 v = (root[i]<<16)|(root[i+1]<<8);
        pem[plen++] = b64chars[(v>>18)&0x3f]; pem[plen++] = b64chars[(v>>12)&0x3f];
        pem[plen++] = b64chars[(v>>6)&0x3f]; pem[plen++] = '=';
    }
    plen += snprintf(pem+plen, sizeof(pem)-plen, "\n-----END CERTIFICATE-----\ntrailing junk\n");
    u8 decoded[2048]; size_t declen;
    const char *next = pem_next_cert(pem, pem+plen, decoded, sizeof decoded, &declen);
    CHECK(next != NULL && declen == rootlen && memcmp(decoded, root, rootlen) == 0,
          "pem_next_cert extracts and decodes a certificate block correctly (round-trip against root.der)");
    free(root);
}

static trust_store_t g_store;

static void load_fixture_store(void) {
    static const char *paths[] = { "chain_fixtures/trust_store.pem", NULL };
    if (!load_trust_store_from_paths(&g_store, paths)) {
        fprintf(stderr, "could not load chain_fixtures/trust_store.pem\n");
        exit(2);
    }
}

static int verify_chain_files(const char *const *files, int n, char *reason, size_t reasonsz) {
    const u8 *certs[8]; size_t lens[8]; u8 *bufs[8];
    for (int i = 0; i < n; i++) bufs[i] = read_file(files[i], &lens[i]), certs[i] = bufs[i];
    int r = handrolled_verify_chain_with_store(certs, lens, n, &g_store, reason, reasonsz);
    for (int i = 0; i < n; i++) free(bufs[i]);
    return r;
}

static void test_chain_building(void) {
    printf("chain-of-trust verification (local root -> intermediate -> leaf fixture):\n");
    char reason[160];

    { const char *files[] = { "chain_fixtures/leaf.der", "chain_fixtures/inter.der" };
      int r = verify_chain_files(files, 2, reason, sizeof reason);
      if (r != 1) printf("       (reason: %s)\n", reason);
      CHECK(r == 1, "valid leaf+intermediate chains to the trusted root (RSA root, EC intermediate, RSA leaf)"); }

    { const char *files[] = { "chain_fixtures/leaf_badsig.der", "chain_fixtures/inter.der" };
      int r = verify_chain_files(files, 2, reason, sizeof reason);
      CHECK(r == 0, "chain with a corrupted leaf signature is rejected"); }

    { const char *files[] = { "chain_fixtures/leaf_expired.der", "chain_fixtures/inter.der" };
      int r = verify_chain_files(files, 2, reason, sizeof reason);
      CHECK(r == 0, "chain with an expired leaf is rejected regardless of valid signatures"); }

    { const char *files[] = { "chain_fixtures/leaf.der" }; /* no intermediate sent at all */
      int r = verify_chain_files(files, 1, reason, sizeof reason);
      CHECK(r == 0, "leaf alone, without the intermediate, does not chain to anything in the store"); }

    { /* a certificate presented as its own issuer (wrong link) --
         reuse the leaf as both "leaf" and "issuer". This chain must still
         never be accepted as trusted, but *why* it's rejected changed with
         the chain-walking fix above: leaf.der's real issuer (the
         intermediate) isn't a trust anchor, so we fall through to pairing
         it against the next server-supplied cert exactly as before -- and
         since that "next cert" is leaf.der again, and a leaf is never a
         valid CA, it's rejected on that basicConstraints check before a
         signature is even attempted.
         (This used to reuse inter.der instead of leaf.der. That no longer
         demonstrates a rejected chain: inter.der's real issuer is the RSA
         root, which the fixture store legitimately trusts, so per-hop
         anchor matching now correctly terminates trust right there --
         accepting it a hop earlier than this test originally expected is
         the fix working as intended, not a false accept, so the fixture
         pairing moved to leaf.der to keep testing the intended property.) */
      const char *files[] = { "chain_fixtures/leaf.der", "chain_fixtures/leaf.der" };
      int r = verify_chain_files(files, 2, reason, sizeof reason);
      CHECK(r <= 0, "a certificate presented as its own issuer (wrong link) is never accepted as trusted"); }

    { /* the exact shape that surfaced the original gap: a P-256 leaf signed
         by a P-384 intermediate using ecdsa-with-SHA384 -- see
         nanocurl-verify.c's SHA-384/P-384 additions */
      const char *files[] = { "chain_fixtures/leaf384.der", "chain_fixtures/inter384.der" };
      int r = verify_chain_files(files, 2, reason, sizeof reason);
      if (r != 1) printf("       (reason: %s)\n", reason);
      CHECK(r == 1, "P-256 leaf under a P-384/ecdsa-with-SHA384 intermediate chains correctly"); }
}

/* A trust store variant containing only a modern root -- deliberately not
   the separate legacy root that cross-signed it -- for the cross-signed-
   root test below, which needs its own store rather than the main fixture
   root used by everything above. */
static void test_cross_signed_root(void) {
    printf("cross-signed root (trust a root directly even when the server sends a cross-signed copy of it):\n");
    trust_store_t store;
    static const char *paths[] = { "chain_fixtures/crossroot_trust_store.pem", NULL };
    if (!load_trust_store_from_paths(&store, paths)) {
        fprintf(stderr, "could not load chain_fixtures/crossroot_trust_store.pem\n");
        exit(2);
    }
    char reason[160];

    { /* what a real server sends: leaf -> intermediate -> cross-signed
         root. Our store trusts the modern root directly (self-signed) but
         doesn't have the legacy root that cross-signed it -- so this must
         still verify by terminating one hop early, at the intermediate's
         issuer, exactly like a real browser/curl would (see
         nanocurl-verify.c's handrolled_verify_chain_with_store comment;
         this is the real Cloudflare/SSL.com chain shape reported against
         curl's cacert.pem, reproduced here with a throwaway local CA
         hierarchy instead of live internet certificates). */
      const u8 *certs[3]; size_t lens[3]; u8 *bufs[3];
      const char *files[] = { "chain_fixtures/crossleaf.der", "chain_fixtures/crossinter.der", "chain_fixtures/crossroot_new_crosssigned.der" };
      for (int i = 0; i < 3; i++) bufs[i] = read_file(files[i], &lens[i]), certs[i] = bufs[i];
      int r = handrolled_verify_chain_with_store(certs, lens, 3, &store, reason, sizeof reason);
      for (int i = 0; i < 3; i++) free(bufs[i]);
      if (r != 1) printf("       (reason: %s)\n", reason);
      CHECK(r == 1, "chain ending in a cross-signed root verifies by trusting the modern root directly, one hop early"); }

    { /* same leaf+intermediate, but this time the server doesn't bother
         sending the cross-signed root at all (it's redundant once the
         client already trusts the modern root directly) -- must verify
         identically, since the intermediate's issuer is the same modern
         root either way. */
      const u8 *certs[2]; size_t lens[2]; u8 *bufs[2];
      const char *files[] = { "chain_fixtures/crossleaf.der", "chain_fixtures/crossinter.der" };
      for (int i = 0; i < 2; i++) bufs[i] = read_file(files[i], &lens[i]), certs[i] = bufs[i];
      int r = handrolled_verify_chain_with_store(certs, lens, 2, &store, reason, sizeof reason);
      for (int i = 0; i < 2; i++) free(bufs[i]);
      if (r != 1) printf("       (reason: %s)\n", reason);
      CHECK(r == 1, "the same chain verifies without the server sending the redundant cross-signed root at all"); }
}

int main(void) {
    test_b64_and_pem();
    load_fixture_store();
    printf("(loaded %d trust anchor%s from the fixture store)\n", g_store.count, g_store.count == 1 ? "" : "s");
    CHECK(g_store.count == 1, "fixture trust store contains exactly our one test root");
    test_chain_building();
    test_cross_signed_root();
    printf("\n%s (%d failure%s)\n", failures ? "SOME TESTS FAILED" : "all tests passed",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
