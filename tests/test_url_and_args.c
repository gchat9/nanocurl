/* Exercises the real parse_args()/parse_url() functions (the same ones
   main() calls) rather than a hand-copied shadow of the logic, so this
   can't silently drift out of sync with the actual CLI behavior. */
#define NANOCURL_NO_MAIN
#include "../nanocurl.c"

static int failures = 0;

static void check_str(const char *label, const char *got, const char *want) {
    if (strcmp(got, want) == 0) {
        printf("PASS  %s -> %s\n", label, got);
    } else {
        printf("FAIL  %s -> got [%s] want [%s]\n", label, got, want);
        failures++;
    }
}
static void check_int(const char *label, int got, int want) {
    if (got == want) {
        printf("PASS  %s -> %d\n", label, got);
    } else {
        printf("FAIL  %s -> got %d want %d\n", label, got, want);
        failures++;
    }
}

static void check_url(const char *url, const char *want_host, const char *want_port, const char *want_path) {
    parsed_url_t u;
    parse_url(url, &u);
    char label[256]; snprintf(label, sizeof label, "parse_url(%s) host", url);
    check_str(label, u.host, want_host);
    snprintf(label, sizeof label, "parse_url(%s) port", url);
    check_str(label, u.port, want_port);
    snprintf(label, sizeof label, "parse_url(%s) path", url);
    check_str(label, u.path, want_path);
}

int main(void) {
    /* --- URL parsing --- */
    check_url("https://github.com/404", "github.com", "443", "/404");
    check_url("github.com:8443/404", "github.com", "8443", "/404");
    check_url("https://example.com:8443", "example.com", "8443", "/");
    check_url("example.com:8443", "example.com", "8443", "/");
    check_url("example.com", "example.com", "443", "/");
    check_url("https://wikimedia.org/api/rest_v1/media/math/render/svg/xyz",
               "wikimedia.org", "443", "/api/rest_v1/media/math/render/svg/xyz");
    check_url("127.0.0.1:8443/test", "127.0.0.1", "8443", "/test");

    /* --- argument parsing: -D - and -H in various orders/combinations --- */
    {
        char *argv[] = {"nanocurl", "-D", "-", "-H", "If-Modified-Since: Wed, 03 Sep 2026 08:00:00 GMT",
                         "-H", "X-Foo: bar", "https://example.com/"};
        parsed_args_t a;
        int ok = parse_args(8, argv, &a);
        check_int("parse_args: -D - -H -H url : ok", ok, 1);
        check_int("parse_args: -D - -H -H url : show_headers", a.show_headers, 1);
        check_int("parse_args: -D - -H -H url : n_extra_headers", a.n_extra_headers, 2);
        check_str("parse_args: -D - -H -H url : url", a.url, "https://example.com/");
        check_str("parse_args: -D - -H -H url : header[0]", a.extra_headers[0],
                   "If-Modified-Since: Wed, 03 Sep 2026 08:00:00 GMT");
        check_str("parse_args: -D - -H -H url : header[1]", a.extra_headers[1], "X-Foo: bar");
    }
    {
        /* -H before -D -, reversed order from above -- should work identically */
        char *argv[] = {"nanocurl", "-H", "X-Foo: bar", "-D", "-", "https://example.com/"};
        parsed_args_t a;
        int ok = parse_args(6, argv, &a);
        check_int("parse_args: -H -D - url (reversed order) : ok", ok, 1);
        check_int("parse_args: -H -D - url (reversed order) : show_headers", a.show_headers, 1);
        check_int("parse_args: -H -D - url (reversed order) : n_extra_headers", a.n_extra_headers, 1);
    }
    {
        /* no flags at all */
        char *argv[] = {"nanocurl", "https://example.com/"};
        parsed_args_t a;
        int ok = parse_args(2, argv, &a);
        check_int("parse_args: url only : ok", ok, 1);
        check_int("parse_args: url only : show_headers", a.show_headers, 0);
        check_int("parse_args: url only : n_extra_headers", a.n_extra_headers, 0);
    }
    {
        /* no URL at all -- must fail cleanly, not crash */
        char *argv[] = {"nanocurl", "-D", "-"};
        parsed_args_t a;
        int ok = parse_args(3, argv, &a);
        check_int("parse_args: no url given : ok (should fail)", ok, 0);
    }

    /* --- header override detection (has_header/header_name_is) --- */
    {
        const char *hdrs[] = {"Host: test.mydomain.com"};
        check_int("has_header: exact case match", has_header(hdrs, 1, "Host"), 1);
        check_int("has_header: case-insensitive match", has_header(hdrs, 1, "host"), 1);
        check_int("has_header: no match for unrelated name", has_header(hdrs, 1, "Connection"), 0);
        check_int("has_header: no false-positive on prefix ('Ho')", has_header(hdrs, 1, "Ho"), 0);
    }

    if (failures) { printf("\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nall url/arg parsing checks passed\n");
    return 0;
}
