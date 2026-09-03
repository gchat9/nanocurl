/* Exercises the exact header-assembly logic used in main() -- built-in
   Host/Connection/User-Agent lines, -H additions, and -H overriding a
   built-in header of the same name (case-insensitively) -- by replicating
   main()'s assembly sequence against the real buf_append()/has_header(). */
#define NANOCURL_NO_MAIN
#include "../nanocurl.c"

static int failures = 0;

static size_t build_request(const char *host, const char *path,
                             const char *const *extra, int n,
                             char *req, size_t reqsz) {
    size_t rn = 0;
    rn = buf_append(req, reqsz, rn, "GET %s HTTP/1.1\r\n", path);
    if (!has_header(extra, n, "Host"))
        rn = buf_append(req, reqsz, rn, "Host: %s\r\n", host);
    if (!has_header(extra, n, "Connection"))
        rn = buf_append(req, reqsz, rn, "Connection: close\r\n");
    if (!has_header(extra, n, "User-Agent"))
        rn = buf_append(req, reqsz, rn, "User-Agent: nanocurl/0.0\r\n");
    for (int i = 0; i < n; i++)
        rn = buf_append(req, reqsz, rn, "%s\r\n", extra[i]);
    rn = buf_append(req, reqsz, rn, "\r\n");
    return rn;
}

static void check_contains(const char *label, const char *haystack, const char *needle, int want_present) {
    int present = strstr(haystack, needle) != NULL;
    if (present == want_present) {
        printf("PASS  %s\n", label);
    } else {
        printf("FAIL  %s (needle %s, expected present=%d got=%d)\n", label, needle, want_present, present);
        failures++;
    }
}
static void check_count(const char *label, const char *haystack, const char *needle, int want_count) {
    int count = 0;
    const char *p = haystack;
    size_t nlen = strlen(needle);
    while ((p = strstr(p, needle)) != NULL) { count++; p += nlen; }
    if (count == want_count) {
        printf("PASS  %s (count=%d)\n", label, count);
    } else {
        printf("FAIL  %s (got count=%d want=%d)\n", label, count, want_count);
        failures++;
    }
}

int main(void) {
    char req[4096];

    /* --- no extra headers: all three built-ins present, no Accept-Encoding --- */
    {
        size_t rn = build_request("example.com", "/", NULL, 0, req, sizeof req);
        (void)rn;
        check_contains("default request has Host", req, "Host: example.com\r\n", 1);
        check_contains("default request has Connection: close", req, "Connection: close\r\n", 1);
        check_contains("default request has User-Agent", req, "User-Agent: nanocurl/0.0\r\n", 1);
        check_contains("default request does NOT force Accept-Encoding", req, "Accept-Encoding", 0);
        check_contains("request ends with blank line", req, "\r\n\r\n", 1);
    }

    /* --- -H adds a new header without disturbing built-ins --- */
    {
        const char *extra[] = {"X-Custom: hello"};
        build_request("example.com", "/", extra, 1, req, sizeof req);
        check_contains("added header present", req, "X-Custom: hello\r\n", 1);
        check_contains("Host still present when adding unrelated header", req, "Host: example.com\r\n", 1);
    }

    /* --- -H overriding Host (case-exact) --- */
    {
        const char *extra[] = {"Host: test.mydomain.com"};
        build_request("127.0.0.1", "/test", extra, 1, req, sizeof req);
        check_contains("overridden Host value present", req, "Host: test.mydomain.com\r\n", 1);
        check_contains("original Host value absent", req, "Host: 127.0.0.1\r\n", 0);
        check_count("exactly one Host header line", req, "Host:", 1);
    }

    /* --- -H overriding Host, lowercase header name (case-insensitive match) --- */
    {
        const char *extra[] = {"host: lower.example.com"};
        build_request("127.0.0.1", "/test", extra, 1, req, sizeof req);
        check_contains("lowercase override value present", req, "host: lower.example.com\r\n", 1);
        check_contains("built-in capitalized Host absent when lowercase override given", req, "Host: 127.0.0.1\r\n", 0);
    }

    /* --- -H overriding Connection --- */
    {
        const char *extra[] = {"Connection: keep-alive", "X-Foo: bar"};
        build_request("example.com", "/", extra, 2, req, sizeof req);
        check_contains("overridden Connection value present", req, "Connection: keep-alive\r\n", 1);
        check_contains("default Connection: close absent", req, "Connection: close\r\n", 0);
        check_contains("unrelated extra header still present", req, "X-Foo: bar\r\n", 1);
    }

    if (failures) { printf("\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nall request-building checks passed\n");
    return 0;
}
