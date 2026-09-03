/* Exercises stream_http_response() end-to-end: real TLS 1.3 application-data
   records (using the real write_record()/read_record()/AEAD code, not a
   shortcut) sent over a socketpair, so this is a genuine test of the wire
   format and not just the parsing logic in isolation. Response bytes are
   deliberately split at awkward points -- mid chunk-size-line, mid
   chunk-data -- across separate TLS records, since that's exactly the kind
   of boundary a byte-at-a-time parser can get subtly wrong.

   Output is captured by redirecting stdout to a pipe and reading it back,
   since stream_http_response() writes directly to stdout by design (it's
   meant to be the tool's actual output path, not a return value). */
#define NANOCURL_NO_MAIN
#include "../nanocurl.c"
#include <sys/socket.h>

static int failures = 0;

/* Sends `resp` as one or more TLS application-data records, split at the
   given offsets (each offset is where the *next* record starts), followed
   by a close_notify alert. */
static void send_response(int fd, tls_t *writer, const char *resp, const size_t *splits, int n_splits) {
    (void)fd;
    size_t start = 0;
    for (int i = 0; i <= n_splits; i++) {
        size_t end = (i < n_splits) ? splits[i] : strlen(resp);
        write_record(writer, 23, (const u8*)(resp + start), end - start, 1);
        start = end;
    }
    u8 alertbuf[2] = {1, 0}; /* warning, close_notify */
    write_record(writer, 21, alertbuf, 2, 1);
}

/* Runs stream_http_response() against a scripted response, capturing
   whatever it writes to stdout, and returns it as a malloc'd NUL-terminated
   string (caller frees). */
static char *capture_response(const char *resp, const size_t *splits, int n_splits, int show_headers) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    tls_t writer = {0}, reader = {0};
    writer.fd = sv[0]; reader.fd = sv[1];
    u8 key[32]; memset(key, 0x55, 32);
    u8 iv[12]; memset(iv, 0x66, 12);
    memcpy(writer.c_key, key, 32); memcpy(writer.c_iv, iv, 12);
    memcpy(reader.s_key, key, 32); memcpy(reader.s_iv, iv, 12);

    send_response(sv[0], &writer, resp, splits, n_splits);
    close(sv[0]);

    /* redirect stdout to a pipe for the duration of the call */
    int outpipe[2]; pipe(outpipe);
    fflush(stdout);
    int saved_stdout = dup(1);
    dup2(outpipe[1], 1);
    close(outpipe[1]);

    stream_http_response(&reader, show_headers);

    fflush(stdout);
    dup2(saved_stdout, 1);
    close(saved_stdout);
    close(reader.fd);

    char *buf = malloc(65536);
    size_t total = 0;
    ssize_t r;
    /* the write end is closed (we closed our dup'd copy above); read until EOF */
    while ((r = read(outpipe[0], buf + total, 65536 - total - 1)) > 0) total += (size_t)r;
    close(outpipe[0]);
    buf[total] = '\0';
    return buf;
}

static void check_streq(const char *label, const char *got, const char *want) {
    if (strcmp(got, want) == 0) {
        printf("PASS  %s\n", label);
    } else {
        printf("FAIL  %s\n  got:  [%s]\n  want: [%s]\n", label, got, want);
        failures++;
    }
}

int main(void) {
    /* --- non-chunked response, headers hidden (default) --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\n"
            "hello world";
        char *out = capture_response(resp, NULL, 0, 0);
        check_streq("non-chunked, headers hidden", out, "hello world");
        free(out);
    }

    /* --- non-chunked response, headers shown via -D - --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\n"
            "hello world";
        char *out = capture_response(resp, NULL, 0, 1);
        check_streq("non-chunked, headers shown", out, resp);
        free(out);
    }

    /* --- chunked response, single record, headers hidden --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n";
        char *out = capture_response(resp, NULL, 0, 0);
        check_streq("chunked, single record, headers hidden", out, "Hello World");
        free(out);
    }

    /* --- chunked response, headers shown: chunk framing still stripped,
           only the header block itself is echoed --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nHello\r\n0\r\n\r\n";
        char *out = capture_response(resp, NULL, 0, 1);
        check_streq("chunked, headers shown (chunk framing still stripped)", out,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nHello");
        free(out);
    }

    /* --- chunked response split across THREE TLS records at awkward
           boundaries: mid chunk-size-line, mid chunk-data --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: image/svg+xml\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5\r\nHello\r\n"
            "6\r\n World\r\n"
            "0\r\n\r\n";
        size_t splits[2] = {30, 50}; /* arbitrary, deliberately mid-token */
        char *out = capture_response(resp, splits, 2, 0);
        check_streq("chunked, split across 3 records at awkward boundaries", out, "Hello World");
        free(out);
    }

    /* --- case-insensitive Transfer-Encoding header detection --- */
    {
        const char *resp =
            "HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n\r\n"
            "3\r\nfoo\r\n0\r\n\r\n";
        char *out = capture_response(resp, NULL, 0, 0);
        check_streq("case-insensitive Transfer-Encoding/chunked detection", out, "foo");
        free(out);
    }

    if (failures) { printf("\n%d check(s) FAILED\n", failures); return 1; }
    printf("\nall response-streaming checks passed\n");
    return 0;
}
