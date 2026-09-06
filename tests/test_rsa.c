/*
 * test_rsa.c -- unit tests for nanocurl-verify's hand-rolled bignum + RSA
 * signature verification (phase 2 of the OpenSSL migration).
 *
 * Deliberately tests the primitives directly against real OpenSSL-produced
 * signatures (see rsa/gen_rsa_fixtures.sh), independent of any X.509/TLS
 * machinery -- known-answer vectors are a much stronger correctness check
 * than "it happened to agree on the live sites I tried", which is exactly
 * the lesson tests/test_verify.c's wildcard bug taught: shadow-mode live
 * testing only exercises the code paths real traffic happens to hit.
 *
 * Run: ./run.sh
 * Regenerate fixtures (only if adding/changing one): ./gen_rsa_fixtures.sh
 */
#define NANOCURL_VERIFY_NO_MAIN
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

/* SubjectPublicKeyInfo DER at the top level (what `openssl rsa -pubout`
   produces) -- a standalone entry point alongside extract_rsa_pubkey(),
   which expects a full wrapping Certificate. */
static int parse_rsa_public_key_from_spki_der(const u8 *der, size_t len, bn_t *n, bn_t *e) {
    der_reader_t r = { der, der + len };
    der_tlv_t spki;
    if (!der_read_tlv(&r, &spki) || spki.tag != 0x30) return 0;
    return parse_rsa_spki_fields(spki.value, spki.len, n, e);
}

static void test_bignum_core(void) {
    printf("bignum core:\n");
    bn_t base, exp, mod, r;
    u8 bb[] = {2}, eb[] = {10}, mb[] = {0x03, 0xE8}; /* 2^10 mod 1000 = 24 */
    bn_from_be(&base, bb, 1); bn_from_be(&exp, eb, 1); bn_from_be(&mod, mb, 2);
    bn_modexp(&r, &base, &exp, &mod);
    u8 out[2]; bn_to_be(&r, out, 2);
    int val = out[0] * 256 + out[1];
    CHECK(val == 24, "bn_modexp(2^10 mod 1000) == 24");

    /* a case that exercises real carry propagation across limb boundaries */
    u8 bb2[] = {0xFF,0xFF,0xFF,0xFF,0xFF}; /* 2^40 - 1 */
    u8 eb2[] = {2};
    u8 mb2[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; /* 2^48 - 1 */
    bn_from_be(&base, bb2, 5); bn_from_be(&exp, eb2, 1); bn_from_be(&mod, mb2, 6);
    bn_modexp(&r, &base, &exp, &mod);
    /* (2^40-1)^2 mod (2^48-1), verified independently: python3 -c
       "print(hex(pow(2**40-1,2,2**48-1)))" -> 0xfe0100000000 */
    u8 want[6] = {0xfe,0x01,0x00,0x00,0x00,0x00};
    u8 got[6]; bn_to_be(&r, got, 6);
    CHECK(memcmp(got, want, 6) == 0, "bn_modexp carries correctly across limb boundaries");
}

static void test_rsa(void) {
    printf("RSA signature verification (real OpenSSL-produced signatures):\n");
    size_t pklen; u8 *pkder = read_file("rsa/pub.der", &pklen);
    bn_t n, e;
    CHECK(parse_rsa_public_key_from_spki_der(pkder, pklen, &n, &e), "parse RSA public key from SPKI DER");
    printf("       (modulus is %d bits)\n", bn_bitlen(&n));
    free(pkder);

    size_t msglen; u8 *msg = read_file("rsa/message.txt", &msglen);
    u8 hash[32]; sha256_oneshot(msg, msglen, hash);
    free(msg);
    u8 badhash[32]; memcpy(badhash, hash, 32); badhash[0] ^= 0x01;

    size_t siglen; u8 *sig = read_file("rsa/sig_pkcs1.bin", &siglen);
    CHECK(rsa_pkcs1_verify(&n, &e, sig, siglen, hash), "PKCS#1 v1.5 signature verifies against the correct hash");
    CHECK(!rsa_pkcs1_verify(&n, &e, sig, siglen, badhash), "PKCS#1 v1.5 rejects a tampered hash");
    CHECK(!rsa_pkcs1_verify(&n, &e, sig, siglen - 1, hash), "PKCS#1 v1.5 rejects a truncated signature");
    free(sig);

    size_t sigplen; u8 *sigp = read_file("rsa/sig_pss.bin", &sigplen);
    CHECK(rsa_pss_verify(&n, &e, sigp, sigplen, hash), "RSA-PSS signature verifies against the correct hash");
    CHECK(!rsa_pss_verify(&n, &e, sigp, sigplen, badhash), "RSA-PSS rejects a tampered hash");
    u8 tampered_sig[512]; memcpy(tampered_sig, sigp, sigplen); tampered_sig[10] ^= 0x01;
    CHECK(!rsa_pss_verify(&n, &e, tampered_sig, sigplen, hash), "RSA-PSS rejects a tampered signature");
    free(sigp);

    /* cross-checks: a PSS signature must not verify as PKCS#1 v1.5 and vice versa */
    sig = read_file("rsa/sig_pkcs1.bin", &siglen);
    CHECK(!rsa_pss_verify(&n, &e, sig, siglen, hash), "a PKCS#1 v1.5 signature is correctly NOT a valid PSS signature");
    free(sig);
}

int main(void) {
    test_bignum_core();
    test_rsa();
    printf("\n%s (%d failure%s)\n", failures ? "SOME TESTS FAILED" : "all tests passed",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
