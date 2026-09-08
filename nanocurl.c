/*
 * nanocurl.c -- the absolute tiniest thing that can https-GET a page.
 *
 * TLS 1.3 only. Single ciphersuite: TLS_CHACHA20_POLY1305_SHA256.
 * Single key-exchange group: X25519.
 * NO certificate validation (unless nanocurl-verify helper is used)
 *
 * This *will* break when:
 * - server don't offer TLS_CHACHA20_POLY1305_SHA256 + x25519
 * - we receive HelloRetryRequest (server rejects our key_share group)
 * - handshake messages split weirdly across TCP segments in ways the
 *   (deliberately simplistic) reassembly logic doesn't expect
 * - talking to an http2-only server
 *
 * Build: gcc -O2 -o nanocurl nanocurl.c
 * Run:   ./nanocurl example.com/test
 *
 */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#ifdef __dietlibc__
#include <linux/random.h> /* getrandom() -- dietlibc declares it here */
#else
#include <sys/random.h>   /* getrandom() -- glibc declares it here */
#endif

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* TLS 1.3 max ciphertext record size: 2^14 (16384) plaintext bytes, +1 content-type
   byte, + up to 255 bytes of padding, + 16-byte AEAD tag = 16640. Every buffer that
   might hold a full record (AAD+ciphertext+padding+length scratch space used for
   the Poly1305 MAC) needs to be at least this big. */
#define TLS_MAX_RECORD 16640
#define BUFSZ (TLS_MAX_RECORD + 128)

#include "strlite.h"
#include "crypto/sha256.h"
#include "crypto/handshake_crypto.h"

/* ======================================================================
 * TCP plumbing
 * ==================================================================== */

/* True if `line` is an HTTP header with the name `name` e.g.
   header_name_is("Host: example.com", "Host") -> true.
   Case-insensitive, as HTTP header names are. */
static int header_name_is(const char *line, const char *name) {
    size_t nlen = strlen(name);
    return strncasecmp(line, name, nlen) == 0 && line[nlen] == ':';
}

static int has_header(const char *const *headers, int n, const char *name) {
    for (int i = 0; i < n; i++) if (header_name_is(headers[i], name)) return 1;
    return 0;
}

static int tcp_connect(const char *host, const char *port, int ai_family) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = ai_family; hints.ai_socktype = SOCK_STREAM;
    /* getaddrinfo() doesn't set errno on failure, and its own gai_strerror()
       isn't available on dietlibc, so we don't try to say more than this. */
    if (getaddrinfo(host, port, &hints, &res) != 0) die("nanocurl: getaddrinfo failed\n", WR_END);
    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) die("connect failed\n", WR_END);
    return fd;
}

static void send_all(int fd, const u8 *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf+off, n-off, 0);
        if (w <= 0) die("connection closed / send error\n", WR_END);
        off += w;
    }
}

static void recv_all(int fd, u8 *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf+off, n-off, 0);
        if (r <= 0) die("connection closed / recv error\n", WR_END);
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
    if (bad) wrs(2, "[warn] record MAC mismatch (seq ", utoa((unsigned long long)(t->s_seq-1)),
                 ") -- decoding anyway\n", WR_END);
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
        if (type == 21) die("TLS alert received, aborting\n", WR_END);
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

/* Raw bytes of the two handshake messages the certificate verifier needs,
   plus the one piece of derived state it needs and can't recompute itself:
   the transcript hash as it stood *before* CertificateVerify was hashed in
   (RFC 8446 4.4.3 signs exactly that hash, not the final one). Everything
   else (chain parsing, signature verification, hostname/expiry checks)
   happens out-of-process in the verifier helper -- see verify_certificate(). */
typedef struct {
    u8 cert_msg[BUFSZ];       size_t cert_msg_len;       int have_cert;
    u8 certverify_msg[BUFSZ]; size_t certverify_msg_len; int have_certverify;
    u8 transcript_before_certverify[32];
} handshake_capture_t;

/* Reads and hashes handshake messages (EncryptedExtensions, Certificate,
   CertificateVerify, ...) until the server's Finished message. Certificate
   and CertificateVerify are additionally copied out verbatim into *cap
   (unless cap == NULL, as is the case when -k is specified).
   Either way, we don't parse any of that, cap is passed to a separate
   companion binary, compiled from nanocurl-verify.c */
static void consume_handshake_to_finished(tls_t *t, handshake_capture_t *cap) {
    if (cap) memset(cap, 0, sizeof *cap);
    for (;;) {
        u8 hh[4]; hs_read(t, hh, 4, 1);
        size_t hl = (hh[1]<<16)|(hh[2]<<8)|hh[3];
        u8 hb[BUFSZ]; hs_read(t, hb, hl, 1);
        if (cap && hh[0] == 15 /* CertificateVerify */)
            sha256_final_copy(t->transcript, cap->transcript_before_certverify);
        sha256_update(&t->transcript, hh, 4);
        sha256_update(&t->transcript, hb, hl);
        if (cap && hh[0] == 11 && hl <= sizeof cap->cert_msg) {
            memcpy(cap->cert_msg, hb, hl); cap->cert_msg_len = hl; cap->have_cert = 1;
        }
        if (cap && hh[0] == 15 && hl <= sizeof cap->certverify_msg) {
            memcpy(cap->certverify_msg, hb, hl); cap->certverify_msg_len = hl; cap->have_certverify = 1;
        }
        if (hh[0] == 20) break; /* Finished */
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
    wrs(2, "[tls alert] level=", lvl, " description=", itoa(desc), " (", name, ")\n", WR_END);
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

/* copy up to n bytes from the stream to fd outfd (pass -1 to discard them
   instead of writing). Returns bytes actually copied, which is less than n
   only once the stream has ended. */
static size_t rs_copy(respstream_t *rs, int outfd, size_t n) {
    size_t copied = 0;
    while (copied < n) {
        if (rs->off >= rs->len && !rs_fill_one_record(rs)) break;
        size_t avail = rs->len - rs->off;
        size_t take = (n - copied) < avail ? (n - copied) : avail;
        if (outfd >= 0) wr_all(outfd, rs->buf + rs->off, take);
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
        if (hdrlen < sizeof(hdrbuf) - 1) hdrbuf[hdrlen++] = (char)c;
        if ((crlf_run==0 && c=='\r') || (crlf_run==1 && c=='\n') ||
            (crlf_run==2 && c=='\r') || (crlf_run==3 && c=='\n')) {
            if (++crlf_run == 4) break;
        } else {
            crlf_run = (c == '\r') ? 1 : 0;
        }
    }
    hdrbuf[hdrlen] = '\0';
    /* Echoed in one write() instead of a fputc() per byte -- both leaner
       (no buffered-stdio machinery needed) and fewer syscalls. This means
       -D - only echoes the same (8191-byte-capped) header block that
       chunked-encoding detection below already works from, rather than an
       unbounded byte-at-a-time stream; headers past that cap were already
       invisible to the chunked-detection logic, so nothing that used to
       work correctly gets any less correct here. */
    if (show_headers) wr_all(1, hdrbuf, hdrlen);
    int chunked = ci_contains(hdrbuf, "transfer-encoding:") && ci_contains(hdrbuf, "chunked");
    if (!chunked) {
        while (rs_copy(&rs, 1, BUFSZ) > 0) { /* keep draining until EOF */ }
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
        rs_copy(&rs, 1, chunklen);
        rs_getc(&rs); rs_getc(&rs); /* each chunk is followed by a mandatory CRLF */
    }
}

#define MAX_EXTRA_HEADERS 32
typedef struct {
    int show_headers;
    int insecure; /* -k / --insecure: skip the verifier helper entirely, as before */
    int ai_family; /* -4/-6: force AF_INET/AF_INET6; AF_UNSPEC (default) picks either */
    const char *extra_headers[MAX_EXTRA_HEADERS];
    int n_extra_headers;
    const char *url; /* borrowed pointer into argv */
} parsed_args_t;

/* Parses -D -, -k/--insecure, -4/-6, and any number of -H 'Header: value'
   flags, in any order, preceding the URL. Returns 1 with out->url set on
   success, 0 if no URL token was found (caller should print usage and
   bail). */
static int parse_args(int argc, char **argv, parsed_args_t *out) {
    out->show_headers = 0;
    out->insecure = 0;
    out->ai_family = AF_UNSPEC;
    out->n_extra_headers = 0;
    int argi = 1;
    while (argi < argc) {
        if (strcmp(argv[argi], "-D") == 0 && argi+1 < argc && strcmp(argv[argi+1], "-") == 0) {
            out->show_headers = 1; argi += 2; continue;
        }
        if (strcmp(argv[argi], "-k") == 0 || strcmp(argv[argi], "--insecure") == 0) {
            out->insecure = 1; argi += 1; continue;
        }
        if (strcmp(argv[argi], "-4") == 0) {
            out->ai_family = AF_INET; argi += 1; continue;
        }
        if (strcmp(argv[argi], "-6") == 0) {
            out->ai_family = AF_INET6; argi += 1; continue;
        }
        if (strcmp(argv[argi], "-H") == 0 && argi+1 < argc) {
            if (out->n_extra_headers < MAX_EXTRA_HEADERS)
                out->extra_headers[out->n_extra_headers++] = argv[argi+1];
            else
                /* MAX_EXTRA_HEADERS is stringified at compile time -- no
                   runtime number-to-string conversion needed here at all. */
                wrs(2, "warning: more than " NANOCURL_STR(MAX_EXTRA_HEADERS)
                       " -H headers given, ignoring the rest\n", WR_END);
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
        scopy(out->path, sizeof out->path, slash);
    } else {
        scopy(hostport, sizeof hostport, url);
        scopy(out->path, sizeof out->path, "/");
    }
    scopy(out->port, sizeof out->port, "443");
    const char *colon = strchr(hostport, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - hostport);
        if (hlen >= sizeof out->host) hlen = sizeof(out->host) - 1;
        memcpy(out->host, hostport, hlen); out->host[hlen] = '\0';
        scopy(out->port, sizeof out->port, colon + 1);
    } else {
        scopy(out->host, sizeof out->host, hostport);
    }
}

/* ======================================================================
 * Certificate verification, out-of-process.
 *
 * Everything that actually needs to understand X.509 (ASN.1, RSA/ECDSA/
 * Ed25519 signature checks, trust-store path building, hostname matching)
 * lives in the separate `nanocurl-verify` binary. *This* binary's job is to:
 *   1. serialize the handful of already-captured handshake bytes over a pipe;
 *   2. wait for an exit code from verifier;
 *   3. abort the connection on failure.
 * ==================================================================== */

/* Unlike strlite.h's wr_all() (which gives up quietly -- fine for best-
   effort output like the response body), a short write here means the
   verifier never got a complete, well-formed request, so this one is loud
   about it and aborts instead of silently sending a truncated message. */
static void wr_verify(int fd, const void *buf, size_t n) {
    const u8 *p = buf; size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p+off, n-off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) die("nanocurl: write to verifier failed: ", errname(errno), "\n", WR_END);
        off += (size_t)w;
    }
}

static void wr_u16(int fd, size_t v) { u8 b[2] = {(u8)(v>>8), (u8)v}; wr_verify(fd, b, 2); }
static void wr_u24(int fd, size_t v) { u8 b[3] = {(u8)(v>>16), (u8)(v>>8), (u8)v}; wr_verify(fd, b, 3); }

/* Wire format written to the verifier's stdin (all lengths big-endian):
 *   u8      version (1)
 *   u16     hostname length, then that many bytes
 *   u16     CertificateVerify signature_algorithm (as sent on the wire)
 *   u16     signature length, then that many bytes
 *   32B     transcript hash covering ClientHello..Certificate (not CertVerify)
 *   u16     number of certificates
 *   for each: u24 DER length, then that many DER bytes (leaf first)
 *
 * Parsing the TLS Certificate/CertificateVerify message *framing* below is
 * just reading the length-prefixed fields the TLS RFC defines for them --
 * not X.509 -- so it stays here. Not one byte of the DER payloads themselves
 * is inspected; they're copied through untouched for the helper to parse.
 */
static void send_verify_request(int fd, const handshake_capture_t *cap, const char *host) {
    if (cap->certverify_msg_len < 4) die("nanocurl: malformed CertificateVerify\n", WR_END);
    const u8 *cv = cap->certverify_msg;
    size_t sigalg = ((size_t)cv[0]<<8)|cv[1];
    size_t siglen = ((size_t)cv[2]<<8)|cv[3];
    if (4+siglen > cap->certverify_msg_len) die("nanocurl: malformed CertificateVerify\n", WR_END);
    const u8 *sig = cv+4;

    const u8 *cm = cap->cert_msg;
    size_t cmlen = cap->cert_msg_len;
    if (cmlen < 1) die("nanocurl: malformed Certificate message\n", WR_END);
    size_t p = 0;
    u8 ctxlen = cm[p]; p += 1 + ctxlen;
    if (p+3 > cmlen) die("nanocurl: malformed Certificate message\n", WR_END);
    size_t listlen = ((size_t)cm[p]<<16)|((size_t)cm[p+1]<<8)|cm[p+2]; p += 3;
    size_t listend = p + listlen;
    if (listend > cmlen) die("nanocurl: malformed Certificate message\n", WR_END);

    size_t ncerts = 0;
    for (size_t q = p; q < listend; ncerts++) {
        if (q+3 > listend) die("nanocurl: malformed Certificate message\n", WR_END);
        size_t dl = ((size_t)cm[q]<<16)|((size_t)cm[q+1]<<8)|cm[q+2]; q += 3+dl;
        if (q+2 > listend) die("nanocurl: malformed Certificate message\n", WR_END);
        size_t el = ((size_t)cm[q]<<8)|cm[q+1]; q += 2+el;
        if (q > listend) die("nanocurl: malformed Certificate message\n", WR_END);
    }

    u8 version = 1;
    wr_verify(fd, &version, 1);
    size_t hlen = strlen(host);
    wr_u16(fd, hlen); wr_verify(fd, host, hlen);
    wr_u16(fd, sigalg);
    wr_u16(fd, siglen); wr_verify(fd, sig, siglen);
    wr_verify(fd, cap->transcript_before_certverify, 32);
    wr_u16(fd, ncerts);
    for (size_t q = p; q < listend; ) {
        size_t dl = ((size_t)cm[q]<<16)|((size_t)cm[q+1]<<8)|cm[q+2]; q += 3;
        wr_u24(fd, dl); wr_verify(fd, cm+q, dl); q += dl;
        size_t el = ((size_t)cm[q]<<8)|cm[q+1]; q += 2+el;
    }
}

/* Forks nanocurl-verify (found via $PATH), feeds it the wire-format request
   above on its stdin, and returns 1 iff it exits 0. The helper's stderr is
   inherited, so on failure it has already printed the reason itself --
   that's the whole reason it's a fork+exit-code away rather than a linked-in
   function call. Returns 0 (fail closed) if we fail to run the verifier */
static int verify_certificate(const handshake_capture_t *cap, const char *host) {
    if (!cap->have_cert) { wrs(2, "nanocurl: server sent no certificate\n", WR_END); return 0; }
    if (!cap->have_certverify) { wrs(2, "nanocurl: server sent no CertificateVerify\n", WR_END); return 0; }

    int pipefd[2];
    if (pipe(pipefd) != 0) { wrs(2, "nanocurl: pipe: ", errname(errno), "\n", WR_END); return 0; }
    pid_t pid = fork();
    if (pid < 0) { wrs(2, "nanocurl: fork: ", errname(errno), "\n", WR_END); return 0; }
    if (pid == 0) {
        dup2(pipefd[0], 0);
        close(pipefd[0]); close(pipefd[1]);
        execlp("nanocurl-verify", "nanocurl-verify", (char *)NULL);
        wrs(2, "nanocurl: cannot exec nanocurl-verify (is it installed and on $PATH?): ",
               errname(errno), "\n", WR_END);
        _exit(127);
    }
    close(pipefd[0]);
    send_verify_request(pipefd[1], cap, host);
    close(pipefd[1]);
    int status;
    if (waitpid(pid, &status, 0) < 0) { wrs(2, "nanocurl: waitpid: ", errname(errno), "\n", WR_END); return 0; }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

#ifndef NANOCURL_NO_MAIN
int main(int argc, char **argv) {
    parsed_args_t args;
    if (!parse_args(argc, argv, &args)) {
        wrs(2, "usage: ", argv[0],
               " [-D -] [-k] [-4] [-6] [-H 'Header: value']... [https://]host[:port][/path]\n", WR_END);
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
    t.fd = tcp_connect(host, port, args.ai_family);
    sha256_init(&t.transcript);

    /* --- keypair --- */
    u8 priv[32], pub[32];
    if (getrandom(priv, 32, 0) != 32) die("nanocurl: getrandom failed: ", errname(errno), "\n", WR_END);
    x25519_base(pub, priv);

    /* --- build ClientHello --- */
    u8 ch[1024]; size_t n = 0;
    u8 crandom[32];
    if (getrandom(crandom, 32, 0) != 32) die("nanocurl: getrandom failed: ", errname(errno), "\n", WR_END);
    u8 body[900]; size_t bn = 0;
    body[bn++]=0x03; body[bn++]=0x03; /* legacy_version */
    memcpy(body+bn, crandom, 32); bn += 32; /* random */
    body[bn++] = 32; /* legacy_session_id len */
    memcpy(body+bn, crandom, 32); bn += 32; /* (reuse random bytes, doesn't matter) */
    body[bn++]=0x00; body[bn++]=0x02; /* cipher_suites len=2 */
    body[bn++]=0x13; body[bn++]=0x03; /* TLS_CHACHA20_POLY1305_SHA256 */
    body[bn++]=0x01; body[bn++]=0x00; /* compression: len=1, null */

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
      u8 sidlen = shbody[p]; p += 1+sidlen; /* session_id echo */
      p += 2; /* cipher_suite */
      p += 1; /* legacy_compression_method */
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
    expand_label(c_hs_secret, "iv", (u8*)"", 0, t.c_iv, 12);
    expand_label(s_hs_secret, "key", (u8*)"", 0, t.s_key, 32);
    expand_label(s_hs_secret, "iv", (u8*)"", 0, t.s_iv, 12);
    t.c_seq = t.s_seq = 0;

    /* consume EncryptedExtensions, Certificate, CertificateVerify, Finished. */
    handshake_capture_t cap;
    consume_handshake_to_finished(&t, args.insecure ? NULL : &cap);
    if (!args.insecure && !verify_certificate(&cap, host)) {
        wrs(2, "nanocurl: aborting (use -k to skip certificate verification)\n", WR_END);
        close(t.fd);
        return 1;
    }

    /* application_traffic_secret derivation (RFC 8446 sec 7.1) uses the
       transcript hash through ClientHello...server Finished -- it must NOT
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
    expand_label(c_ap_secret, "iv", (u8*)"", 0, t.c_iv, 12);
    expand_label(s_ap_secret, "key", (u8*)"", 0, t.s_key, 32);
    expand_label(s_ap_secret, "iv", (u8*)"", 0, t.s_iv, 12);
    t.c_seq = t.s_seq = 0;

    /* --- HTTP/1.1 GET, hand-rolled --- */
    char req[4096];
    size_t rn = 0;
    rn = cat(req, sizeof req, rn, "GET ");
    rn = cat(req, sizeof req, rn, path);
    rn = cat(req, sizeof req, rn, " HTTP/1.1\r\n");
    if (!has_header(extra_headers, n_extra_headers, "Host")) {
        rn = cat(req, sizeof req, rn, "Host: ");
        rn = cat(req, sizeof req, rn, host);
        rn = cat(req, sizeof req, rn, "\r\n");
    }
    if (!has_header(extra_headers, n_extra_headers, "Connection"))
        rn = cat(req, sizeof req, rn, "Connection: close\r\n");
    if (!has_header(extra_headers, n_extra_headers, "User-Agent"))
        rn = cat(req, sizeof req, rn, "User-Agent: nanocurl/0.0\r\n");
    for (int i = 0; i < n_extra_headers; i++) {
        rn = cat(req, sizeof req, rn, extra_headers[i]);
        rn = cat(req, sizeof req, rn, "\r\n");
    }
    rn = cat(req, sizeof req, rn, "\r\n");
    write_record(&t, 23, (u8*)req, rn, 1);

    stream_http_response(&t, show_headers);
    close(t.fd);
    return 0;
}
#endif /* NANOCURL_NO_MAIN */
