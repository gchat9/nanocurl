/*
 * test_verify.c -- unit tests for nanocurl-verify's hand-rolled hostname/
 * SAN/CN/validity logic (phase 1 of the OpenSSL migration).
 *
 * This #includes nanocurl-verify.c directly (with its main() compiled out)
 * to get at the static parsing functions -- same trick nanocurl.c's
 * NANOCURL_NO_MAIN already supports for exactly this purpose.
 *
 * Run: ./run.sh
 * Regenerate fixtures (only if you need to add/change one): ./gen_certs.sh
 */
#define NANOCURL_VERIFY_NO_MAIN
#include "../nanocurl-verify.c"

static int failures = 0;

#define CHECK(cond, desc) do { \
    if (cond) printf("  ok   %s\n", desc); \
    else { printf("  FAIL %s\n", desc); failures++; } \
} while (0)

static void test_hostname_matches(void) {
    printf("hostname_matches (pure string logic, no certs involved):\n");
    CHECK(hostname_matches("example.com", 11, "example.com"), "exact match");
    CHECK(hostname_matches("ExAmPle.COM", 11, "example.com"), "case-insensitive match");
    CHECK(!hostname_matches("example.com", 11, "example.org"), "different domain rejected");
    CHECK(hostname_matches("*.example.com", 13, "www.example.com"), "wildcard matches one subdomain label");
    CHECK(!hostname_matches("*.example.com", 13, "example.com"), "wildcard does NOT match the bare apex");
    CHECK(!hostname_matches("*.example.com", 13, "a.b.example.com"), "wildcard does NOT match multiple labels");
    CHECK(!hostname_matches("f*o.example.com", 15, "foo.example.com"), "partial-label wildcard is not special-cased (literal mismatch)");
    CHECK(!hostname_matches("*.example.com", 13, "examplecom"), "wildcard against a dotless host is rejected");
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

static void test_cert(const char *file, const char *host, int expect, const char *desc) {
    size_t len; u8 *der = read_file(file, &len);
    char reason[128] = {0};
    int r = handrolled_check_leaf(der, len, host, reason, sizeof reason);
    free(der);
    if (r == expect) printf("  ok   %s\n", desc);
    else { printf("  FAIL %s (got %d, wanted %d -- reason: %s)\n", desc, r, expect, reason); failures++; }
}

int main(void) {
    test_hostname_matches();

    printf("handrolled_check_leaf (real DER fixtures in certs/):\n");
    test_cert("certs/exact_san.der",     "test-a.example",     1, "exact SAN dNSName match");
    test_cert("certs/exact_san.der",     "not-test-a.example", 0, "SAN present, no entry matches -> reject");
    test_cert("certs/wildcard_san.der",  "www.test-b.example", 1, "wildcard SAN matches a subdomain");
    test_cert("certs/wildcard_san.der",  "test-b.example",     0, "wildcard SAN does not match the bare apex");
    test_cert("certs/san_no_match.der",  "test-c.example",     0, "SAN present but non-matching -- CN must NOT be used as fallback (this is the exact shape of bug we found against google.com)");
    test_cert("certs/cn_only.der",       "test-d.example",     1, "CN fallback used when there is no SAN extension at all");
    test_cert("certs/cn_only.der",       "other.example",      0, "CN fallback correctly rejects the wrong host");
    test_cert("certs/expired.der",       "test-e.example",     0, "expired certificate rejected regardless of hostname match");
    test_cert("certs/not_yet_valid.der", "test-f.example",     0, "not-yet-valid certificate rejected regardless of hostname match");

    printf("\n%s (%d failure%s)\n", failures ? "SOME TESTS FAILED" : "all tests passed",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
