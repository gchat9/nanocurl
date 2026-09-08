/*
 * strlite.h -- the handful of string/output primitives nanocurl.c needs,
 * built entirely on write(2)/memcpy/strlen instead of the printf family.
 *
 * Why this exists: on a statically-linked libc built for size (dietlibc is
 * the motivating case: `diet gcc`), pulling in *any* of printf/fprintf/
 * snprintf/vsnprintf drags in the whole format-string engine -- several
 * kilobytes of bloat that show up as linker warnings ("the printf functions
 * add several kilobytes of bloat"), even if the actual format strings used
 * are trivial. nanocurl.c's needs are trivial: emit a handful of fixed
 * strings, one decimal number here and there, and build a request buffer
 * out of literal pieces plus a couple of caller-supplied substrings. None
 * of that needs a real formatter, so this header provides exactly that
 * subset by hand, header-only, `static`, same convention as crypto headers.
 *
 * Everything here is straight libc (write, strlen, memcpy) -- no syscalls
 * are hand-rolled, this is just "don't ask for more machinery than the job
 * needs".
 */
#ifndef NANOCURL_STRLITE_H
#define NANOCURL_STRLITE_H

#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>

/* Stringify a macro's expanded value at compile time, e.g.
   NANOCURL_STR(MAX_CERTS) -> "16" -- lets a handful of messages embed a
   compile-time constant without any runtime number formatting. */
#define NANOCURL_STR_(x) #x
#define NANOCURL_STR(x) NANOCURL_STR_(x)

/* Sentinel for the variadic string lists below -- wrs(2, "a", "b", WR_END). */
#define WR_END ((const char *)0)

/* write() can return short or be interrupted; keep going until all n bytes
   are out (or a real, non-EINTR error happens, in which case we just give
   up -- there's nothing more useful to do from inside an error path). */
static void wr_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        if (w == 0) break;
        off += (size_t)w;
    }
}

/* Writes each of a WR_END-terminated list of NUL-terminated strings to fd,
   in order -- i.e. string concatenation done at the syscall boundary
   instead of in a formatting buffer. This is the replacement for every
   fprintf(stderr, "...%s...", x) call site that just needed to interpolate
   one or two substrings into a fixed message. */
static void vwrs(int fd, const char *first, va_list ap) {
    for (const char *s = first; s; s = va_arg(ap, const char *))
        wr_all(fd, s, strlen(s));
}
static void wrs(int fd, const char *first, ...) {
    va_list ap; va_start(ap, first);
    vwrs(fd, first, ap);
    va_end(ap);
}

/* Same, but always to stderr and never returns -- the replacement for the
   very common "fprintf(stderr, ...); exit(1);" pattern. */
static void die(const char *first, ...) {
    va_list ap; va_start(ap, first);
    vwrs(2, first, ap);
    va_end(ap);
    exit(1);
}

/* Render an unsigned/signed decimal number into a small static buffer and
   return a pointer to it -- enough to hand straight to wrs()/die(). Only
   ever one such buffer is live at a time, which is all a single-threaded
   CLI tool needs; if a call site ever needs two numbers rendered at once,
   it should copy the first result out before formatting the second. */
static const char *utoa(unsigned long long v) {
    static char buf[24];
    char *p = buf + sizeof buf - 1;
    *p = '\0';
    do { *--p = (char)('0' + (v % 10)); v /= 10; } while (v);
    return p;
}
static const char *itoa(long long v) {
    static char buf[24];
    unsigned long long uv = (v < 0) ? (unsigned long long)(-(v + 1)) + 1 : (unsigned long long)v;
    char *p = buf + sizeof buf - 1;
    *p = '\0';
    do { *--p = (char)('0' + (uv % 10)); uv /= 10; } while (uv);
    if (v < 0) *--p = '-';
    return p;
}

/* Render a 16-bit value as "0x" + 4 lowercase hex digits, e.g. for TLS
   signature-scheme IDs (which are always exactly 16 bits) -- the
   replacement for the one "0x%04zx"-style format site nanocurl-verify.c
   needs. Not a general hex formatter on purpose: nanocurl doesn't have a
   second use case, and a fixed 4-digit width is all a u16 ever needs. */
static const char *u16hex(unsigned v) {
    static const char hexdigit[] = "0123456789abcdef";
    static char buf[7]; /* "0x" + 4 digits + NUL */
    buf[0] = '0'; buf[1] = 'x';
    buf[2] = hexdigit[(v >> 12) & 0xf];
    buf[3] = hexdigit[(v >> 8) & 0xf];
    buf[4] = hexdigit[(v >> 4) & 0xf];
    buf[5] = hexdigit[v & 0xf];
    buf[6] = '\0';
    return buf;
}

/* Bounded string copy -- the replacement for snprintf(dst, dstsz, "%s", src).
   Always NUL-terminates within [dst, dst+dstsz), truncating src if needed. */
static void scopy(char *dst, size_t dstsz, const char *src) {
    if (dstsz == 0) return;
    size_t n = strlen(src);
    if (n >= dstsz) n = dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Bounded buffer append -- the replacement for the old vsnprintf-based
   buf_append(). Appends src at buf[off], never writing past bufsz and
   never returning an offset that could underflow a later bufsz-off.
   Used to build the HTTP request line-by-line out of literal pieces and
   a handful of substrings (path, host, extra headers) with no format
   string needed at all. */
static size_t cat(char *buf, size_t bufsz, size_t off, const char *src) {
    if (off >= bufsz) return off;
    size_t room = bufsz - off;
    size_t n = strlen(src);
    if (n > room) n = room;
    memcpy(buf + off, src, n);
    return off + n;
}

/* A curated, hand-picked replacement for strerror(): nanocurl's own
   syscall failure paths (pipe/fork/exec/waitpid/getrandom) can only
   realistically produce a small, known set of errno values, so the ones
   most likely to occur in practice (an exec()'d helper missing, a
   permission problem, or the process/system running out of resources)
   get a real name and everything else -- which would be a genuinely
   unusual condition if it ever showed up here -- is reported as a bare
   number instead of guessing. This is never wrong (a number is always an
   accurate description of itself), and on a statically linked libc built
   for size it means the ~4KB table of all ~130 POSIX error strings
   (almost all of which nanocurl could never actually trigger) never gets
   linked into the binary at all. Returns a pointer good until the next
   call. */
static const char *errname(int e) {
    switch (e) {
        case ENOENT: return "ENOENT";
        case EACCES: return "EACCES";
        case ENOMEM: return "ENOMEM";
        case EAGAIN: return "EAGAIN";
        default: {
            static char buf[24];
            size_t off = cat(buf, sizeof buf, 0, "errno ");
            off = cat(buf, sizeof buf, off, utoa((unsigned long long)e));
            buf[off] = '\0';
            return buf;
        }
    }
}

#endif /* NANOCURL_STRLITE_H */
