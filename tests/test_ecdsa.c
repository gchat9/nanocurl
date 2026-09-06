/*
 * test_ecdsa.c -- unit tests for nanocurl-verify's hand-rolled ECDSA
 * verification, P-256 and P-384 (phase 3 plus the P-384 follow-on of the
 * OpenSSL migration -- P-384 was added after finding that real-world CA
 * hierarchies commonly pair it with SHA-384 at the intermediate/root level
 * even when leaf certificates stay on P-256/SHA-256; see nanocurl-verify.c's
 * curve_params_p384 comment).
 *
 * Two layers of testing per curve, deliberately independent of each other:
 *
 *   1. Property-based sanity checks on the group arithmetic itself, using
 *      facts about the curve that are true by definition and don't depend
 *      on any external reference: n*G must be the point at infinity (G has
 *      order n), 2*G computed via doubling must equal G+G computed via
 *      addition, and G+infinity must equal G. If the Jacobian formulas or a
 *      curve constant have a transcription bug, these are likely to catch
 *      it even before any real signature is involved.
 *
 *   2. A known-answer test against a real OpenSSL-produced ECDSA signature
 *      (P-256/SHA-256 and P-384/SHA-384 -- see gen_ecdsa_fixtures.sh) --
 *      the same "don't just trust that it happened to agree on live
 *      traffic" standard applied to the RSA and hostname-matching tests.
 *
 * Run: ./run.sh
 */
#define NANOCURL_VERIFY_NO_MAIN
#include "../nanocurl-verify.c"

static int failures = 0;

#define CHECK(cond, desc) do { \
    if (cond) printf("  ok   %s\n", desc); \
    else { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

static int jpoint_eq_affine(const jpoint_t *p, const bn_t *ex, const bn_t *ey, const bn_t *prime) {
    bn_t x, y;
    if (!jpoint_to_affine(&x, &y, p, prime)) return 0;
    return bn_cmp(&x, ex) == 0 && bn_cmp(&y, ey) == 0;
}

static void test_curve_properties(const char *name, const curve_params_t *curve) {
    printf("%s group arithmetic (property-based, no external reference):\n", name);
    const bn_t *p = &curve->p, *b = &curve->b, *n = &curve->n, *gx = &curve->gx, *gy = &curve->gy;

    /* the generator must actually be on the curve: y^2 == x^3 - 3x + b */
    { bn_t x2, x3, ax, y2, rhs;
      bn_mulmod(&x2, gx, gx, p);
      bn_mulmod(&x3, &x2, gx, p);
      bn_mulsmall_mod(&ax, gx, 3, p);
      bn_submod(&rhs, &x3, &ax, p);
      bn_addmod(&rhs, &rhs, b, p);
      bn_mulmod(&y2, gy, gy, p);
      CHECK(bn_cmp(&y2, &rhs) == 0, "generator point G satisfies the curve equation");
    }

    jpoint_t G, G2_dbl, G2_add, Ginf;
    jpoint_from_affine(&G, gx, gy);

    jpoint_double(&G2_dbl, &G, p);
    jpoint_add(&G2_add, &G, &G, p);
    { bn_t x1,y1,x2,y2;
      int ok1 = jpoint_to_affine(&x1,&y1,&G2_dbl,p);
      int ok2 = jpoint_to_affine(&x2,&y2,&G2_add,p);
      CHECK(ok1 && ok2 && bn_cmp(&x1,&x2)==0 && bn_cmp(&y1,&y2)==0,
            "doubling formula agrees with addition formula (2G == G+G)");
    }

    jpoint_set_infinity(&Ginf);
    jpoint_t sum;
    jpoint_add(&sum, &G, &Ginf, p);
    CHECK(jpoint_eq_affine(&sum, gx, gy, p), "G + infinity == G");

    jpoint_t nG;
    jpoint_scalar_mult(&nG, &G, n, p);
    CHECK(jpoint_is_infinity(&nG), "n*G == point at infinity (G has order n)");

    jpoint_t threeG_direct, threeG_addadd;
    bn_t three = {0}; three.limb[0] = 3; three.n = 1;
    jpoint_scalar_mult(&threeG_direct, &G, &three, p);
    jpoint_t twoG; jpoint_double(&twoG, &G, p);
    jpoint_add(&threeG_addadd, &twoG, &G, p);
    { bn_t x1,y1,x2,y2;
      int ok1 = jpoint_to_affine(&x1,&y1,&threeG_direct,p);
      int ok2 = jpoint_to_affine(&x2,&y2,&threeG_addadd,p);
      CHECK(ok1 && ok2 && bn_cmp(&x1,&x2)==0 && bn_cmp(&y1,&y2)==0,
            "scalar_mult(3, G) == double(G) + G");
    }
}

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

/* standalone SPKI-DER entry point mirroring extract_ec_pubkey, for testing
   against `openssl ec -pubout` output directly (no Certificate wrapper). */
static int parse_ec_pubkey_from_spki_der(const u8 *der, size_t len, curve_params_t *curve, bn_t *qx, bn_t *qy) {
    der_reader_t r = { der, der + len };
    der_tlv_t spki;
    if (!der_read_tlv(&r, &spki) || spki.tag != 0x30) return 0;
    return parse_ec_pubkey_from_spki_fields(spki.value, spki.len, curve, qx, qy);
}

static void test_known_answer_256(const char *pubfile, const char *msgfile, const char *sigfile) {
    printf("ECDSA verification, P-256/SHA-256 (real OpenSSL-produced signature):\n");
    size_t pklen; u8 *pkder = read_file(pubfile, &pklen);
    curve_params_t curve; bn_t qx, qy;
    CHECK(parse_ec_pubkey_from_spki_der(pkder, pklen, &curve, &qx, &qy), "parse public key from SPKI DER");
    free(pkder);

    size_t msglen; u8 *msg = read_file(msgfile, &msglen);
    u8 hash[32], badhash[32];
    sha256_oneshot(msg, msglen, hash);
    memcpy(badhash, hash, 32); badhash[0] ^= 0x01;
    free(msg);

    size_t siglen; u8 *sig = read_file(sigfile, &siglen);
    bn_t r, s;
    CHECK(parse_ecdsa_sig(sig, siglen, &r, &s), "parse ECDSA-Sig-Value DER");
    CHECK(ecdsa_verify(&curve, &qx, &qy, &r, &s, hash, 32), "signature verifies against the correct hash");
    CHECK(!ecdsa_verify(&curve, &qx, &qy, &r, &s, badhash, 32), "signature rejected against a tampered hash");
    bn_t r_bad = r; r_bad.limb[0] ^= 1;
    CHECK(!ecdsa_verify(&curve, &qx, &qy, &r_bad, &s, hash, 32), "signature rejected when r is tampered");
    bn_t wrong_qx = qx; wrong_qx.limb[0] ^= 1;
    CHECK(!ecdsa_verify(&curve, &wrong_qx, &qy, &r, &s, hash, 32), "signature rejected against a tampered (likely off-curve) public key");
    free(sig);
}

static void test_known_answer_384(const char *pubfile, const char *msgfile, const char *sigfile) {
    printf("ECDSA verification, P-384/SHA-384 (real OpenSSL-produced signature):\n");
    size_t pklen; u8 *pkder = read_file(pubfile, &pklen);
    curve_params_t curve; bn_t qx, qy;
    CHECK(parse_ec_pubkey_from_spki_der(pkder, pklen, &curve, &qx, &qy), "parse public key from SPKI DER");
    CHECK(curve.field_bytes == 48, "detected curve is P-384 (48-byte field), not P-256");
    free(pkder);

    size_t msglen; u8 *msg = read_file(msgfile, &msglen);
    u8 hash[48], badhash[48];
    sha384_oneshot(msg, msglen, hash);
    memcpy(badhash, hash, 48); badhash[0] ^= 0x01;
    free(msg);

    size_t siglen; u8 *sig = read_file(sigfile, &siglen);
    bn_t r, s;
    CHECK(parse_ecdsa_sig(sig, siglen, &r, &s), "parse ECDSA-Sig-Value DER");
    CHECK(ecdsa_verify(&curve, &qx, &qy, &r, &s, hash, 48), "signature verifies against the correct hash");
    CHECK(!ecdsa_verify(&curve, &qx, &qy, &r, &s, badhash, 48), "signature rejected against a tampered hash");
    bn_t r_bad = r; r_bad.limb[0] ^= 1;
    CHECK(!ecdsa_verify(&curve, &qx, &qy, &r_bad, &s, hash, 48), "signature rejected when r is tampered");
    free(sig);
}

int main(void) {
    curve_params_t p256, p384;
    curve_params_p256(&p256);
    curve_params_p384(&p384);

    test_curve_properties("P-256", &p256);
    test_curve_properties("P-384", &p384);
    test_known_answer_256("ecdsa_fixtures/pub.der", "ecdsa_fixtures/message.txt", "ecdsa_fixtures/sig.der");
    test_known_answer_384("ecdsa_fixtures/pub384.der", "ecdsa_fixtures/message384.txt", "ecdsa_fixtures/sig384.der");

    printf("\n%s (%d failure%s)\n", failures ? "SOME TESTS FAILED" : "all tests passed",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
