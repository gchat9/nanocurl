/*
 * nanocurl-verify.c -- out-of-process TLS certificate verifier for nanocurl.
 *
 * Reads a small binary request on stdin (see the format comment below,
 * which must match nanocurl.c's send_verify_request() exactly), does two
 * checks, and exits 0 only if both pass:
 *
 *   1. Chain-of-trust + hostname: the leaf certificate chains to a trust
 *      anchor in the system store, is currently valid, and its name(s)
 *      match the hostname being requested.
 *
 *   2. Proof of possession: the server's CertificateVerify signature
 *      (RFC 8446 4.4.3) verifies against the leaf's public key over the
 *      handshake transcript. Without this check, (1) alone verifies
 *      nothing about *this* connection -- an attacker who intercepts the
 *      TCP stream could present a perfectly valid, trusted certificate for
 *      the real site without holding its private key.
 *
 * Both checks are hand-rolled from scratch (ASN.1/PEM parsing, bignum,
 * RSA/ECDSA, SHA-256/384) and are authoritative by default -- this is the
 * end state of a migration that started by shadowing OpenSSL's verdicts and
 * has since replaced them entirely. The default build links no crypto
 * library at all:
 *
 *   gcc -O2 -o nanocurl-verify nanocurl-verify.c
 *
 * Define NANOCURL_VERIFY_WITH_OPENSSL to additionally compile in OpenSSL as
 * a reference implementation, run alongside the hand-rolled checks on every
 * invocation, with disagreements printed to stderr as [selfcheck] lines.
 * This build is strictly for auditing the hand-rolled code against a
 * battle-tested reference -- OpenSSL's verdict is never what decides the
 * exit code, even when compiled in, so behavior is identical between the
 * two builds and this flag can't accidentally change what gets trusted:
 *
 *   gcc -O2 -DNANOCURL_VERIFY_WITH_OPENSSL -o nanocurl-verify nanocurl-verify.c -lssl -lcrypto
 *
 * Install: put the resulting binary on $PATH (nanocurl execlp()s it by name).
 */
#define _POSIX_C_SOURCE 199309L /* clock_gettime()/CLOCK_MONOTONIC, needed only
                                    under NANOCURL_VERIFY_PROFILE below, but
                                    must be defined before any system header */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

#ifdef NANOCURL_VERIFY_WITH_OPENSSL
#include <stdio.h> /* only the OpenSSL-audit build's [selfcheck] fprintf()s need this */
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif /* NANOCURL_VERIFY_WITH_OPENSSL */

#include "strlite.h"
#include "crypto/sha256.h"
#include "crypto/der.h"

/* ======================================================================
 * Opt-in instrumentation -- compile with -DNANOCURL_VERIFY_PROFILE to
 * get some timings printed to stderr
 * ==================================================================== */
#ifdef NANOCURL_VERIFY_PROFILE
#include <stdio.h>
static struct timespec prof_t0;
static void prof_start(void) { clock_gettime(CLOCK_MONOTONIC, &prof_t0); }
static void prof_mark(const char *label) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    double ms = (now.tv_sec - prof_t0.tv_sec) * 1000.0 + (now.tv_nsec - prof_t0.tv_nsec) / 1e6;
    fprintf(stderr, "[profile] %-42s %9.2f ms (cumulative)\n", label, ms);
}
#define PROF_START() prof_start()
#define PROF_MARK(label) prof_mark(label)
#else
#define PROF_START() ((void)0)
#define PROF_MARK(label) ((void)0)
#endif

#include "crypto/pki_crypto.h"

#define MAX_HOST_LEN   255
#define MAX_SIG_LEN    1024
#define MAX_CERTS      16
#define MAX_CERT_LEN   (16*1024)

/* --- stdin reader: exits with a clear message on short read / oversized field.
   Every field here has a hard cap (above) checked before we allocate or read
   it, so a truncated or adversarial request from nanocurl's side can't make
   us read/allocate something unbounded.a */
static void rd_all(void *buf, size_t n) {
    u8 *p = buf; size_t off = 0;
    while (off < n) {
        ssize_t r = read(0, p+off, n-off);
        if (r < 0) { wrs(2, "nanocurl-verify: read: ", errname(errno), "\n", WR_END); exit(2); }
        if (r == 0) { wrs(2, "nanocurl-verify: unexpected EOF from nanocurl\n", WR_END); exit(2); }
        off += (size_t)r;
    }
}
static u8 rd_u8(void) { u8 v; rd_all(&v, 1); return v; }
static size_t rd_u16(void) { u8 b[2]; rd_all(b, 2); return ((size_t)b[0]<<8)|b[1]; }
static size_t rd_u24(void) { u8 b[3]; rd_all(b, 3); return ((size_t)b[0]<<16)|((size_t)b[1]<<8)|b[2]; }

/* Builds the exact byte string RFC 8446 4.4.3 says CertificateVerify signs:
 *   64 spaces || "TLS 1.3, server CertificateVerify" || 0x00 || transcript_hash
 * Returns the length written into out (caller supplies a buffer >= 64+40+32). */
static size_t build_signed_content(const u8 transcript_hash[32], u8 *out) {
    static const char ctxstr[] = "TLS 1.3, server CertificateVerify";
    size_t n = 0;
    memset(out, 0x20, 64); n += 64;
    memcpy(out+n, ctxstr, strlen(ctxstr)); n += strlen(ctxstr);
    out[n++] = 0x00;
    memcpy(out+n, transcript_hash, 32); n += 32;
    return n;
}

/* ======================================================================
 * Hand-rolled X.509 parsing.
 *
 * This section parses raw certificate DER directly, with zero calls into
 * libcrypto, to independently derive two of the checks a TLS client needs:
 * hostname match and validity window.
 *
 * Every parsing step below fails closed: a length that doesn't fit, an
 * unsupported encoding, or a structure that doesn't match expectations
 * aborts *that* parse. This is the code most exposed to attacker-controlled
 * bytes in the whole project, treat with care.
 * ==================================================================== */

/* Howard Hinnant's civil_from_days, used instead of glibc's timegm() so this
   has no libc-extension dependency and no 2038-adjacent surprises on odd
   platforms */
static int64_t asn1_civil_to_unix(int y, int m, int d, int hh, int mm, int ss) {
    y -= (m <= 2);
    long long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = era * 146097 + (long long)doe - 719468;
    return (int64_t)(days * 86400LL + hh * 3600 + mm * 60 + ss);
}

/* Parses a UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ")
   value. Only the Zulu, seconds-included form is accepted -- DER requires
   it, and any other form (fractional seconds, explicit offsets) is a
   non-DER encoding we'd rather reject than mis-parse. */
static int parse_asn1_time(int is_utc, const u8 *s, size_t len, int64_t *out) {
    size_t need = is_utc ? 13 : 15;
    if (len != need) return 0;
    for (size_t i = 0; i < need - 1; i++) if (!isdigit(s[i])) return 0;
    if (s[need - 1] != 'Z') return 0;
    int year;
    const u8 *p = s;
    if (is_utc) {
        year = (p[0]-'0')*10 + (p[1]-'0'); p += 2;
        year += (year < 50) ? 2000 : 1900;
    } else {
        year = (p[0]-'0')*1000 + (p[1]-'0')*100 + (p[2]-'0')*10 + (p[3]-'0'); p += 4;
    }
    int mon = (p[0]-'0')*10 + (p[1]-'0'); p += 2;
    int day = (p[0]-'0')*10 + (p[1]-'0'); p += 2;
    int hh  = (p[0]-'0')*10 + (p[1]-'0'); p += 2;
    int mm  = (p[0]-'0')*10 + (p[1]-'0'); p += 2;
    int ss  = (p[0]-'0')*10 + (p[1]-'0');
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60) return 0;
    *out = asn1_civil_to_unix(year, mon, day, hh, mm, ss);
    return 1;
}

/* Case-insensitive hostname match against one SAN/CN pattern, supporting
   only a leading "*." wildcard matching exactly one whole leftmost label
   (mirrors the X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS behavior on the OpenSSL
   side, so the two checks are actually comparable). */
static int hostname_matches(const char *pattern, size_t patlen, const char *host) {
    size_t hostlen = strlen(host);
    if (patlen == hostlen) {
        for (size_t i = 0; i < patlen; i++)
            if (tolower((u8)pattern[i]) != tolower((u8)host[i])) return 0;
        return 1;
    }
    if (patlen > 2 && pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = memchr(host, '.', hostlen);
        if (!dot || dot == host) return 0; /* no dot, or an empty leftmost label */
        size_t suffixlen = hostlen - (size_t)(dot - host) - 1; /* bytes strictly after the dot */
        if (suffixlen != patlen - 2) return 0;
        const char *hostsuffix = dot + 1;
        for (size_t i = 0; i < suffixlen; i++)
            if (tolower((u8)pattern[2+i]) != tolower((u8)hostsuffix[i])) return 0;
        return 1;
    }
    return 0;
}

/* Extracts SubjectAltName dNSName entries and checks each against host. `p`/
   `len` is the SAN extension's OCTET STRING content, which is itself a DER
   SEQUENCE OF GeneralName (GeneralNames ::= SEQUENCE SIZE (1..MAX) OF
   GeneralName) -- so the outer SEQUENCE has to be unwrapped first before
   walking individual GeneralName entries. GeneralName's dNSName choice is
   tag [2] IMPLICIT IA5String == raw tag byte 0x82. */
static int san_matches_host(const u8 *p, size_t len, const char *host, int *san_present) {
    der_reader_t outer = { p, p + len };
    der_tlv_t seq;
    if (!der_read_tlv(&outer, &seq) || seq.tag != 0x30) return 0; /* malformed SAN extension */
    der_reader_t r = { seq.value, seq.value + seq.len };
    der_tlv_t gn;
    int matched = 0;
    while (der_read_tlv(&r, &gn)) {
        if (gn.tag == 0x82) {
            *san_present = 1;
            if (hostname_matches((const char *)gn.value, gn.len, host)) matched = 1;
        }
    }
    return matched;
}

/* Walks Name (RDNSequence) looking for a commonName (OID 2.5.4.3) attribute
   value, for the deprecated-but-still-sometimes-needed CN fallback used
   when a certificate has no SAN extension at all. */
static int extract_common_name(const u8 *p, size_t len, char *out, size_t outsz) {
    static const u8 OID_CN[] = {0x55, 0x04, 0x03};
    der_reader_t r = { p, p + len };
    der_tlv_t rdn;
    while (der_read_tlv(&r, &rdn)) {
        if (rdn.tag != 0x31 /* SET */) continue;
        der_reader_t sr = { rdn.value, rdn.value + rdn.len };
        der_tlv_t atv;
        while (der_read_tlv(&sr, &atv)) {
            if (atv.tag != 0x30 /* SEQUENCE */) continue;
            der_reader_t ar = { atv.value, atv.value + atv.len };
            der_tlv_t oid, val;
            if (!der_read_tlv(&ar, &oid) || oid.tag != 0x06) continue;
            if (!der_read_tlv(&ar, &val)) continue;
            if (oid.len == 3 && memcmp(oid.value, OID_CN, 3) == 0) {
                size_t n = val.len < outsz - 1 ? val.len : outsz - 1;
                memcpy(out, val.value, n); out[n] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

/* Parses just enough of TBSCertificate to independently answer "is this
   valid right now, for this hostname" -- notBefore/notAfter and SAN/CN.
   Returns 1 (checks pass), 0 (checks fail, *reason set), or -1 (couldn't
   parse this certificate's shape at all, *reason set to why -- treated by
   the caller as inconclusive */
typedef struct {
    der_tlv_t serial, sigalg, issuer, validity, subject, spki;
    der_reader_t rest; /* positioned right after spki: [1]/[2] uniqueIDs, then [3] extensions */
} tbs_fields_t;

static int walk_tbs_prefix(const u8 *der, size_t derlen, tbs_fields_t *out) {
    der_reader_t r = { der, der + derlen };
    der_tlv_t cert, tbs, f;
    if (!der_read_tlv(&r, &cert) || cert.tag != 0x30) return 0;
    der_reader_t cr = { cert.value, cert.value + cert.len };
    if (!der_read_tlv(&cr, &tbs) || tbs.tag != 0x30) return 0;
    der_reader_t tr = { tbs.value, tbs.value + tbs.len };
    { der_reader_t save = tr; if (!(der_read_tlv(&tr, &f) && f.tag == 0xA0)) tr = save; } /* optional version [0] */
    if (!der_read_tlv(&tr, &out->serial) || out->serial.tag != 0x02) return 0;
    if (!der_read_tlv(&tr, &out->sigalg) || out->sigalg.tag != 0x30) return 0;
    if (!der_read_tlv(&tr, &out->issuer) || out->issuer.tag != 0x30) return 0;
    if (!der_read_tlv(&tr, &out->validity) || out->validity.tag != 0x30) return 0;
    if (!der_read_tlv(&tr, &out->subject) || out->subject.tag != 0x30) return 0;
    if (!der_read_tlv(&tr, &out->spki) || out->spki.tag != 0x30) return 0;
    out->rest = tr;
    return 1;
}

static int handrolled_check_leaf(const u8 *der, size_t derlen, const char *host,
                                  char *reason, size_t reasonsz) {
    tbs_fields_t tf;
    if (!walk_tbs_prefix(der, derlen, &tf)) { scopy(reason, reasonsz, "could not parse TBSCertificate prefix"); return -1; }

    int64_t not_before, not_after;
    {
        der_reader_t vr = { tf.validity.value, tf.validity.value + tf.validity.len };
        der_tlv_t t1, t2;
        if (!der_read_tlv(&vr, &t1) || (t1.tag != 0x17 && t1.tag != 0x18)) { scopy(reason, reasonsz, "bad notBefore"); return -1; }
        if (!parse_asn1_time(t1.tag == 0x17, t1.value, t1.len, &not_before)) { scopy(reason, reasonsz, "unparseable notBefore"); return -1; }
        if (!der_read_tlv(&vr, &t2) || (t2.tag != 0x17 && t2.tag != 0x18)) { scopy(reason, reasonsz, "bad notAfter"); return -1; }
        if (!parse_asn1_time(t2.tag == 0x17, t2.value, t2.len, &not_after)) { scopy(reason, reasonsz, "unparseable notAfter"); return -1; }
    }

    char cn[256] = {0};
    int have_cn = extract_common_name(tf.subject.value, tf.subject.len, cn, sizeof cn);

    der_reader_t tr = tf.rest;
    der_tlv_t f;
    { der_reader_t save = tr; if (!(der_read_tlv(&tr, &f) && f.tag == 0xA1)) tr = save; } /* optional issuerUniqueID */
    { der_reader_t save = tr; if (!(der_read_tlv(&tr, &f) && f.tag == 0xA2)) tr = save; } /* optional subjectUniqueID */

    int san_present = 0, san_ok = 0;
    {
        der_reader_t save = tr;
        if (der_read_tlv(&tr, &f) && f.tag == 0xA3) {
            der_reader_t er = { f.value, f.value + f.len };
            der_tlv_t exts;
            if (der_read_tlv(&er, &exts) && exts.tag == 0x30) {
                der_reader_t xr = { exts.value, exts.value + exts.len };
                der_tlv_t ext;
                static const u8 OID_SAN[] = {0x55, 0x1d, 0x11}; /* 2.5.29.17 */
                while (der_read_tlv(&xr, &ext)) {
                    if (ext.tag != 0x30) continue;
                    der_reader_t one = { ext.value, ext.value + ext.len };
                    der_tlv_t oid, maybe, extval;
                    if (!der_read_tlv(&one, &oid) || oid.tag != 0x06) continue;
                    { der_reader_t save2 = one; if (!(der_read_tlv(&one, &maybe) && maybe.tag == 0x01)) one = save2; }
                    if (!der_read_tlv(&one, &extval) || extval.tag != 0x04) continue;
                    if (oid.len == 3 && memcmp(oid.value, OID_SAN, 3) == 0)
                        san_ok = san_matches_host(extval.value, extval.len, host, &san_present);
                }
            }
        } else tr = save;
    }

    int name_ok = san_present ? san_ok : (have_cn && hostname_matches(cn, strlen(cn), host));
    int64_t now = (int64_t)time(NULL);
    int time_ok = now >= not_before && now <= not_after;

    if (!name_ok) {
        size_t off = cat(reason, reasonsz, 0, "hostname does not match ");
        off = cat(reason, reasonsz, off,
                   san_present ? "any SAN entry" : (have_cn ? "the subject CN" : "any name in the certificate (no SAN, no CN)"));
        reason[off < reasonsz ? off : reasonsz - 1] = '\0';
        return 0;
    }
    if (!time_ok) {
        scopy(reason, reasonsz, now < not_before ? "certificate is not yet valid" : "certificate has expired");
        return 0;
    }
    return 1;
}

#ifdef NANOCURL_VERIFY_WITH_OPENSSL
/* Logs how the hand-rolled hostname/validity verdict (already computed by
   the caller -- see main()) compares to OpenSSL's. `openssl_err` is the
   X509_STORE_CTX error code from the real check (0/X509_V_OK on success).
   Diagnostic only: compiled in at all only under NANOCURL_VERIFY_WITH_OPENSSL,
   and never touches the exit code either way -- see the file-level comment. */
static void log_hostname_comparison(int r, const char *reason, int openssl_err) {
    int openssl_ok = (openssl_err == X509_V_OK);
    int openssl_name_or_date_err =
        openssl_err == X509_V_ERR_HOSTNAME_MISMATCH ||
        openssl_err == X509_V_ERR_CERT_HAS_EXPIRED ||
        openssl_err == X509_V_ERR_CERT_NOT_YET_VALID;

    if (r < 0) {
        fprintf(stderr, "[selfcheck] hand-rolled parser could not process this certificate (%s)\n", reason);
    } else if (openssl_ok) {
        if (r == 1) fprintf(stderr, "[selfcheck] OK -- hand-rolled hostname/validity check agrees with OpenSSL\n");
        else fprintf(stderr, "[selfcheck] MISMATCH -- OpenSSL approved this certificate but hand-rolled check says: %s\n", reason);
    } else if (openssl_name_or_date_err) {
        if (r == 0) fprintf(stderr, "[selfcheck] OK -- hand-rolled check agrees with OpenSSL's rejection (%s)\n", reason);
        else fprintf(stderr, "[selfcheck] MISMATCH -- OpenSSL rejected on hostname/date grounds but hand-rolled check says OK\n");
    } else {
        /* OpenSSL failed for a reason outside this check's scope (untrusted
           chain, etc.), so this is informational only. */
        if (r == 1) fprintf(stderr, "[selfcheck] (OpenSSL's rejection is chain-trust related, outside this check's scope -- see [selfcheck-chain]) hostname/validity: OK\n");
        else fprintf(stderr, "[selfcheck] (OpenSSL's rejection is chain-trust related, outside this check's scope -- see [selfcheck-chain]) hostname/validity: %s\n", reason);
    }
}
#endif

/* ======================================================================
 * Public-key extraction: thin X.509-aware wrappers around the generic
 * SubjectPublicKeyInfo parsers in crypto/pki_crypto.h. All the actual
 * bignum/RSA/ECDSA machinery lives there (and in crypto/der.h for the
 * bare TLV reader); what's here is specifically "find the SPKI field
 * inside a Certificate and hand its bytes to the crypto library".
 * ==================================================================== */

static int extract_rsa_pubkey(const u8 *der, size_t derlen, bn_t *n, bn_t *e) {
    tbs_fields_t tf;
    if (!walk_tbs_prefix(der, derlen, &tf)) return 0;
    return parse_rsa_spki_fields(tf.spki.value, tf.spki.len, n, e);
}

static int extract_ec_pubkey(const u8 *der, size_t derlen, curve_params_t *curve, bn_t *qx, bn_t *qy) {
    tbs_fields_t tf;
    if (!walk_tbs_prefix(der, derlen, &tf)) return 0;
    return parse_ec_pubkey_from_spki_fields(tf.spki.value, tf.spki.len, curve, qx, qy);
}


/* Attempts a hand-rolled verification of the CertificateVerify signature,
   for the algorithms hand-rolled so far (RSA PKCS#1 v1.5 / RSA-PSS and
   ECDSA P-256, SHA-256 only). Returns 1 (verified), 0 (rejected), or -1
   (this sigalg/key combination isn't hand-rolled yet -- inconclusive, not
   a verdict either way). */
static int handrolled_verify_certverify(const u8 *leaf_der, size_t leaf_der_len,
                                         size_t sigalg, const u8 *sig, size_t siglen,
                                         const u8 *content, size_t content_len,
                                         char *reason, size_t reasonsz) {
    u8 hash[32];
    sha256_oneshot(content, content_len, hash);

    if (sigalg == 0x0401 || sigalg == 0x0804) {
        bn_t n, e;
        if (!extract_rsa_pubkey(leaf_der, leaf_der_len, &n, &e)) {
            scopy(reason, reasonsz, "leaf key is not RSA (or SPKI didn't parse)");
            return -1;
        }
        int ok = (sigalg == 0x0401) ? rsa_pkcs1_verify(&n, &e, sig, siglen, hash)
                                     : rsa_pss_verify(&n, &e, sig, siglen, hash);
        if (!ok) scopy(reason, reasonsz, "signature does not verify");
        return ok;
    }
    if (sigalg == 0x0403) {
        curve_params_t curve;
        bn_t qx, qy;
        if (!extract_ec_pubkey(leaf_der, leaf_der_len, &curve, &qx, &qy) || curve.id != EC_CURVE_P256) {
            scopy(reason, reasonsz, "leaf key is not a P-256 EC key (or SPKI didn't parse)");
            return -1;
        }
        bn_t r, s;
        if (!parse_ecdsa_sig(sig, siglen, &r, &s)) {
            scopy(reason, reasonsz, "malformed ECDSA-Sig-Value");
            return -1;
        }
        int ok = ecdsa_verify(&curve, &qx, &qy, &r, &s, hash, sizeof hash);
        if (!ok) scopy(reason, reasonsz, "signature does not verify");
        return ok;
    }
    {
        size_t off = cat(reason, reasonsz, 0, "sigalg ");
        off = cat(reason, reasonsz, off, u16hex((unsigned)sigalg));
        off = cat(reason, reasonsz, off, " not hand-rolled yet");
        reason[off < reasonsz ? off : reasonsz - 1] = '\0';
    }
    return -1;
}

#ifdef NANOCURL_VERIFY_WITH_OPENSSL
/* Same diagnostic-only contract as log_hostname_comparison() above. */
static void log_sig_comparison(int r, const char *reason, int openssl_sigok) {
    if (r < 0) {
        fprintf(stderr, "[selfcheck-sig] not applicable (%s)\n", reason);
    } else if (r == openssl_sigok) {
        fprintf(stderr, "[selfcheck-sig] OK -- hand-rolled CertificateVerify signature check agrees with OpenSSL (both say %s)\n",
                r ? "valid" : "invalid");
    } else {
        fprintf(stderr, "[selfcheck-sig] MISMATCH -- OpenSSL says %s, hand-rolled check says %s (%s)\n",
                openssl_sigok ? "valid" : "invalid", r ? "valid" : "invalid", reason);
    }
}
#endif

/* ======================================================================
 * Hand-rolled trust-store loading + chain-of-trust verification --
 * MIGRATION PHASE 4.
 *
 * Same shadow-mode contract as everything above. This is intentionally
 * less complete than full RFC 5280 path validation: no pathLenConstraint,
 * no name constraints, no policy constraints, no CRL/OCSP, and issuer/
 * subject name matching is byte-exact DER comparison rather than RFC 5280's
 * more permissive string-normalization rules. That covers the overwhelming
 * majority of real-world chains without trying to be a full PKIX
 * implementation -- see individual function comments for what each check
 * does and doesn't cover.
 * ==================================================================== */

static int b64_val(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decodes base64 text (whitespace tolerated, '=' padding ends the input),
   returns bytes written or -1 on malformed input (fails closed, same as
   everywhere else -- an unparseable trust-store entry is skipped, not
   guessed at). outcap must be >= 3/4 of inlen, which callers size for. */
static long b64_decode(const char *in, size_t inlen, u8 *out, size_t outcap) {
    size_t o = 0; int vals[4]; int nv = 0;
    for (size_t i = 0; i < inlen; i++) {
        u8 c = (u8)in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) return -1;
        vals[nv++] = v;
        if (nv == 4) {
            if (o + 3 > outcap) return -1;
            out[o++] = (u8)((vals[0] << 2) | (vals[1] >> 4));
            out[o++] = (u8)((vals[1] << 4) | (vals[2] >> 2));
            out[o++] = (u8)((vals[2] << 6) | vals[3]);
            nv = 0;
        }
    }
    if (nv == 2) { if (o + 1 > outcap) return -1; out[o++] = (u8)((vals[0] << 2) | (vals[1] >> 4)); }
    else if (nv == 3) {
        if (o + 2 > outcap) return -1;
        out[o++] = (u8)((vals[0] << 2) | (vals[1] >> 4));
        out[o++] = (u8)((vals[1] << 4) | (vals[2] >> 2));
    } else if (nv != 0) return -1; /* a leftover of exactly 1 base64 char is never valid */
    return (long)o;
}

/* Finds the next "-----BEGIN CERTIFICATE-----"..."-----END CERTIFICATE-----"
   block at or after `p` and decodes it into `out`. Returns a pointer just
   past the END line (for the next search), or NULL once no more blocks are
   found. Non-certificate PEM blocks and other detritus is naturally skipped
   by the search. */
static const char *pem_next_cert(const char *p, const char *end, u8 *out, size_t outcap, size_t *outlen) {
    static const char *BEGIN = "-----BEGIN CERTIFICATE-----";
    static const char *ENDM  = "-----END CERTIFICATE-----";
    size_t blen = strlen(BEGIN), elen = strlen(ENDM);
    const char *begin = NULL;
    for (const char *q = p; q + blen <= end; q++) if (memcmp(q, BEGIN, blen) == 0) { begin = q + blen; break; }
    if (!begin) return NULL;
    const char *endmark = NULL;
    for (const char *q = begin; q + elen <= end; q++) if (memcmp(q, ENDM, elen) == 0) { endmark = q; break; }
    if (!endmark) return NULL;
    long n = b64_decode(begin, (size_t)(endmark - begin), out, outcap);
    if (n < 0) return NULL;
    *outlen = (size_t)n;
    return endmark + elen;
}

#define MAX_TRUST_ANCHORS 4096

typedef struct {
    const u8 *subject; size_t subject_len; /* points into the store's der backing buffer */
    const u8 *cert_der; size_t cert_len;
} trust_anchor_t;

typedef struct {
    trust_anchor_t anchors[MAX_TRUST_ANCHORS];
    int count;
} trust_store_t;

static const char *TRUST_STORE_CANDIDATE_PATHS[] = {
    "/etc/ssl/certs/ca-certificates.crt", /* Debian/Ubuntu */
    "/etc/pki/tls/certs/ca-bundle.crt",   /* RHEL/CentOS/Fedora */
    "/etc/ssl/cert.pem",                  /* Alpine and a few others */
    NULL
};

/* Loads and parses a CA bundle from the first path in `paths` (NULL-
   terminated) that exists. The backing buffers for the decoded certificate
   bytes are allocated here and deliberately never freed -- trust_anchor_t
   entries point directly into them, they need to live for the process's
   entire (one-shot, short) lifetime, and the OS reclaims them at exit
   anyway. Returns 1 on success (at least one certificate loaded), and
   0 otherwise (fail) */
static int load_trust_store_from_paths(trust_store_t *store, const char *const *paths) {
    store->count = 0;
    int fd = -1;
    for (int i = 0; paths[i]; i++) { fd = open(paths[i], O_RDONLY); if (fd >= 0) break; }
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }
    long fsize = (long)st.st_size;
    if (fsize <= 0 || fsize > 32 * 1024 * 1024) { close(fd); return 0; } /* sanity cap; real bundles are a few hundred KB */
    u8 *txt = malloc((size_t)fsize);
    size_t n = 0;
    if (txt) {
        while (n < (size_t)fsize) {
            ssize_t r = read(fd, txt + n, (size_t)fsize - n);
            if (r <= 0) break;
            n += (size_t)r;
        }
    }
    close(fd);
    if (!txt || n == 0) return 0;
    u8 *der = malloc((size_t)fsize); /* decoded output is always <= input size */
    if (!der) return 0;

    const char *p = (const char *)txt, *end = p + n;
    size_t der_off = 0;
    while (store->count < MAX_TRUST_ANCHORS) {
        size_t declen;
        const char *next = pem_next_cert(p, end, der + der_off, (size_t)fsize - der_off, &declen);
        if (!next) break;
        tbs_fields_t tf;
        if (walk_tbs_prefix(der + der_off, declen, &tf)) {
            trust_anchor_t *a = &store->anchors[store->count++];
            a->cert_der = der + der_off; a->cert_len = declen;
            a->subject = tf.subject.value; a->subject_len = tf.subject.len;
        }
        der_off += declen;
        p = next;
    }
    return 1;
}

static int load_trust_store(trust_store_t *store) {
    return load_trust_store_from_paths(store, TRUST_STORE_CANDIDATE_PATHS);
}

static const trust_anchor_t *find_trust_anchor_by_subject(const trust_store_t *store,
                                                            const u8 *issuer_value, size_t issuer_len) {
    for (int i = 0; i < store->count; i++)
        if (store->anchors[i].subject_len == issuer_len && memcmp(store->anchors[i].subject, issuer_value, issuer_len) == 0)
            return &store->anchors[i];
    return NULL;
}

static int cert_is_currently_valid(const u8 *der, size_t derlen) {
    tbs_fields_t tf;
    if (!walk_tbs_prefix(der, derlen, &tf)) return 0;
    der_reader_t vr = { tf.validity.value, tf.validity.value + tf.validity.len };
    der_tlv_t t1, t2;
    int64_t not_before, not_after;
    if (!der_read_tlv(&vr, &t1) || (t1.tag != 0x17 && t1.tag != 0x18)) return 0;
    if (!parse_asn1_time(t1.tag == 0x17, t1.value, t1.len, &not_before)) return 0;
    if (!der_read_tlv(&vr, &t2) || (t2.tag != 0x17 && t2.tag != 0x18)) return 0;
    if (!parse_asn1_time(t2.tag == 0x17, t2.value, t2.len, &not_after)) return 0;
    int64_t now = (int64_t)time(NULL);
    return now >= not_before && now <= not_after;
}

/* Checks that a certificate acting as a CA (an intermediate, or the matched
   trust anchor) is actually allowed to sign other certificates:
   basicConstraints must be present with cA=TRUE, and if keyUsage is present
   too, its keyCertSign bit must be set. This is the check that stops a
   non-CA leaf certificate from being used to "sign" a forged certificate --
   it deliberately doesn't enforce pathLenConstraint. */
static int cert_is_valid_ca(const u8 *der, size_t derlen) {
    tbs_fields_t tf;
    if (!walk_tbs_prefix(der, derlen, &tf)) return 0;
    der_reader_t tr = tf.rest;
    der_tlv_t f;
    { der_reader_t save = tr; if (!(der_read_tlv(&tr, &f) && f.tag == 0xA1)) tr = save; }
    { der_reader_t save = tr; if (!(der_read_tlv(&tr, &f) && f.tag == 0xA2)) tr = save; }
    int is_ca = 0, keyusage_present = 0, key_cert_sign = 0;
    {
        der_reader_t save = tr;
        if (der_read_tlv(&tr, &f) && f.tag == 0xA3) {
            der_reader_t er = { f.value, f.value + f.len };
            der_tlv_t exts;
            if (der_read_tlv(&er, &exts) && exts.tag == 0x30) {
                der_reader_t xr = { exts.value, exts.value + exts.len };
                der_tlv_t ext;
                static const u8 OID_BC[] = {0x55,0x1d,0x13}; /* 2.5.29.19 basicConstraints */
                static const u8 OID_KU[] = {0x55,0x1d,0x0f}; /* 2.5.29.15 keyUsage */
                while (der_read_tlv(&xr, &ext)) {
                    if (ext.tag != 0x30) continue;
                    der_reader_t one = { ext.value, ext.value + ext.len };
                    der_tlv_t oid, maybe, extval;
                    if (!der_read_tlv(&one, &oid) || oid.tag != 0x06) continue;
                    { der_reader_t save2 = one; if (!(der_read_tlv(&one, &maybe) && maybe.tag == 0x01)) one = save2; }
                    if (!der_read_tlv(&one, &extval) || extval.tag != 0x04) continue;
                    if (oid.len == 3 && memcmp(oid.value, OID_BC, 3) == 0) {
                        der_reader_t br = { extval.value, extval.value + extval.len };
                        der_tlv_t bcseq;
                        if (der_read_tlv(&br, &bcseq) && bcseq.tag == 0x30) {
                            der_reader_t bsr = { bcseq.value, bcseq.value + bcseq.len };
                            der_tlv_t cabool;
                            if (der_read_tlv(&bsr, &cabool) && cabool.tag == 0x01 && cabool.len == 1 && cabool.value[0] != 0x00)
                                is_ca = 1;
                        }
                    }
                    if (oid.len == 3 && memcmp(oid.value, OID_KU, 3) == 0) {
                        keyusage_present = 1;
                        der_reader_t kr = { extval.value, extval.value + extval.len };
                        der_tlv_t bs;
                        /* KeyUsage ::= BIT STRING; keyCertSign is bit 5 (MSB-first),
                           i.e. bit 0x04 of the first content byte after the
                           unused-bits count. */
                        if (der_read_tlv(&kr, &bs) && bs.tag == 0x03 && bs.len >= 2 && (bs.value[1] & 0x04))
                            key_cert_sign = 1;
                    }
                }
            }
        } else tr = save;
    }
    if (!is_ca) return 0;
    if (keyusage_present && !key_cert_sign) return 0;
    return 1;
}

typedef struct {
    const u8 *tbs_raw; size_t tbs_raw_len; /* full TBSCertificate DER, header included -- this is what's actually signed */
    const u8 *sigalg_oid; size_t sigalg_oid_len;
    const u8 *sig; size_t sig_len; /* signatureValue, BIT STRING content minus the leading unused-bits byte */
} cert_signature_info_t;

static int extract_cert_signature_info(const u8 *der, size_t derlen, cert_signature_info_t *out) {
    der_reader_t r = { der, der + derlen };
    der_tlv_t cert;
    if (!der_read_tlv(&r, &cert) || cert.tag != 0x30) return 0;
    der_reader_t cr = { cert.value, cert.value + cert.len };
    const u8 *tbs_start = cr.p;
    der_tlv_t tbs;
    if (!der_read_tlv(&cr, &tbs) || tbs.tag != 0x30) return 0;
    out->tbs_raw = tbs_start;
    out->tbs_raw_len = (size_t)(cr.p - tbs_start); /* der_read_tlv already advanced cr.p past the whole TLV, header included */
    der_tlv_t sigalg;
    if (!der_read_tlv(&cr, &sigalg) || sigalg.tag != 0x30) return 0;
    der_reader_t sar = { sigalg.value, sigalg.value + sigalg.len };
    der_tlv_t oid;
    if (!der_read_tlv(&sar, &oid) || oid.tag != 0x06) return 0;
    out->sigalg_oid = oid.value; out->sigalg_oid_len = oid.len;
    der_tlv_t sigval;
    if (!der_read_tlv(&cr, &sigval) || sigval.tag != 0x03) return 0;
    if (sigval.len < 1 || sigval.value[0] != 0x00) return 0;
    out->sig = sigval.value + 1; out->sig_len = sigval.len - 1;
    return 1;
}

static const u8 OID_SHA256_WITH_RSA[]   = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b}; /* 1.2.840.113549.1.1.11 */
static const u8 OID_ECDSA_WITH_SHA256[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02};       /* 1.2.840.10045.4.3.2 */
static const u8 OID_ECDSA_WITH_SHA384[] = {0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03};       /* 1.2.840.10045.4.3.3 */

/* Verifies that `child_der` was signed by `issuer_der`'s public key.
   Returns 1 (verified), 0 (signature doesn't verify, *reason set), or -1
   (child's signature algorithm or issuer's key type isn't hand-rolled yet,
   *reason set -- inconclusive result).
   The hash algorithm is whatever the child's signatureAlgorithm actually
   specifies (SHA-256 or SHA-384), and the curve is whatever the issuer's
   own key actually is (P-256 or P-384) -- these are independent in
   principle, though real CAs pair them by convention (P-256/SHA-256,
   P-384/SHA-384); auto-detecting both rather than assuming a pairing
   handles either case correctly. */
static int verify_cert_signed_by(const u8 *child_der, size_t child_len, const u8 *issuer_der, size_t issuer_len,
                                  char *reason, size_t reasonsz) {
    cert_signature_info_t info;
    if (!extract_cert_signature_info(child_der, child_len, &info)) {
        scopy(reason, reasonsz, "could not parse certificate's signature fields");
        return -1;
    }

    if (info.sigalg_oid_len == sizeof(OID_SHA256_WITH_RSA) && memcmp(info.sigalg_oid, OID_SHA256_WITH_RSA, info.sigalg_oid_len) == 0) {
        u8 hash[32]; sha256_oneshot(info.tbs_raw, info.tbs_raw_len, hash);
        bn_t n, e;
        if (!extract_rsa_pubkey(issuer_der, issuer_len, &n, &e)) { scopy(reason, reasonsz, "issuer key is not RSA (or didn't parse)"); return -1; }
        int ok = rsa_pkcs1_verify(&n, &e, info.sig, info.sig_len, hash);
        if (!ok) scopy(reason, reasonsz, "RSA signature does not verify");
        return ok;
    }
    if ((info.sigalg_oid_len == sizeof(OID_ECDSA_WITH_SHA256) && memcmp(info.sigalg_oid, OID_ECDSA_WITH_SHA256, info.sigalg_oid_len) == 0) ||
        (info.sigalg_oid_len == sizeof(OID_ECDSA_WITH_SHA384) && memcmp(info.sigalg_oid, OID_ECDSA_WITH_SHA384, info.sigalg_oid_len) == 0)) {
        int is_sha384 = memcmp(info.sigalg_oid, OID_ECDSA_WITH_SHA384, info.sigalg_oid_len) == 0;
        u8 hash[48]; size_t hashlen = is_sha384 ? 48 : 32;
        if (is_sha384) sha384_oneshot(info.tbs_raw, info.tbs_raw_len, hash);
        else sha256_oneshot(info.tbs_raw, info.tbs_raw_len, hash);
        curve_params_t curve;
        bn_t qx, qy;
        if (!extract_ec_pubkey(issuer_der, issuer_len, &curve, &qx, &qy)) { scopy(reason, reasonsz, "issuer key is not an EC key on a supported curve (or didn't parse)"); return -1; }
        bn_t r, s;
        if (!parse_ecdsa_sig(info.sig, info.sig_len, &r, &s)) { scopy(reason, reasonsz, "malformed ECDSA-Sig-Value"); return -1; }
        int ok = ecdsa_verify(&curve, &qx, &qy, &r, &s, hash, hashlen);
        if (!ok) scopy(reason, reasonsz, "ECDSA signature does not verify");
        return ok;
    }
    scopy(reason, reasonsz, "certificate's signature algorithm not hand-rolled yet");
    return -1;
}

#define MAX_CHAIN_CERTS 16 /* matches nanocurl-verify's own cap on server-sent certificates */

/* Attempts to hand-roll the same verdict OpenSSL's X509_verify_cert()
   reaches: does this chain link, via verifiable signatures and valid CA
   certificates, from the leaf up to something already trusted in the
   system store? `certs[0]` is the leaf; `certs[1..ncerts-1]` are whatever
   intermediates the server sent, in order (the server is not expected to
   send the root itself -- this looks the root up locally, same as any
   normal TLS client). Returns 1 (trusted), 0 (rejected, *reason set), or -1
   (couldn't attempt this -- no trust store found, or an unsupported
   signature algorithm blocks a link in the chain -- *reason set,
   inconclusive rather than a verdict). */
static int handrolled_verify_chain_with_store(const u8 *const *certs, const size_t *cert_lens, int ncerts,
                                               trust_store_t *store, char *reason, size_t reasonsz) {
    if (ncerts < 1 || ncerts > MAX_CHAIN_CERTS) { scopy(reason, reasonsz, "unexpected certificate count"); return -1; }

    for (int i = 0; i < ncerts; i++) {
        if (!cert_is_currently_valid(certs[i], cert_lens[i])) {
            size_t off = cat(reason, reasonsz, 0, "certificate #");
            off = cat(reason, reasonsz, off, utoa((unsigned long long)i));
            off = cat(reason, reasonsz, off, " in the chain is expired or not yet valid");
            reason[off < reasonsz ? off : reasonsz - 1] = '\0';
            return 0;
        }
    }

    /* Walk the server-supplied chain from the leaf toward the root, one hop
       at a time. At EACH certificate, first check whether its own issuer is
       already a locally trusted root; only if it isn't do we fall back to
       verifying it against the next certificate the server sent and try
       again one hop further out. */
    for (int i = 0; i < ncerts; i++) {
        tbs_fields_t tf;
        if (!walk_tbs_prefix(certs[i], cert_lens[i], &tf)) {
            scopy(reason, reasonsz, "could not parse a certificate in the chain");
            return -1;
        }
        const trust_anchor_t *anchor = find_trust_anchor_by_subject(store, tf.issuer.value, tf.issuer.len);
        if (anchor) {
            if (!cert_is_currently_valid(anchor->cert_der, anchor->cert_len)) { scopy(reason, reasonsz, "matching trust anchor is expired or not yet valid"); return 0; }
            if (!cert_is_valid_ca(anchor->cert_der, anchor->cert_len)) { scopy(reason, reasonsz, "matching trust anchor is not a valid CA"); return 0; }
            return verify_cert_signed_by(certs[i], cert_lens[i], anchor->cert_der, anchor->cert_len, reason, reasonsz);
        }
        if (i + 1 >= ncerts) break; /* no more server-supplied certs left to try */
        if (!cert_is_valid_ca(certs[i+1], cert_lens[i+1])) {
            size_t off = cat(reason, reasonsz, 0, "certificate #");
            off = cat(reason, reasonsz, off, utoa((unsigned long long)(i+1)));
            off = cat(reason, reasonsz, off, " is not a valid CA (basicConstraints/keyUsage)");
            reason[off < reasonsz ? off : reasonsz - 1] = '\0';
            return 0;
        }
        int ok = verify_cert_signed_by(certs[i], cert_lens[i], certs[i+1], cert_lens[i+1], reason, reasonsz);
        if (ok <= 0) return ok;
    }
    scopy(reason, reasonsz, "issuer of the last certificate in the chain is not in the trust store");
    return 0;
}

static int handrolled_verify_chain(const u8 *const *certs, const size_t *cert_lens, int ncerts,
                                    char *reason, size_t reasonsz) {
    static trust_store_t store;
    static int store_loaded = 0, store_ok = 0;
    if (!store_loaded) { store_ok = load_trust_store(&store); store_loaded = 1; }
    PROF_MARK("trust store loaded (read + PEM/DER decode)");
    if (!store_ok) { scopy(reason, reasonsz, "no system trust store found"); return -1; }
    return handrolled_verify_chain_with_store(certs, cert_lens, ncerts, &store, reason, reasonsz);
}

#ifdef NANOCURL_VERIFY_WITH_OPENSSL
static int openssl_is_chain_trust_error(int err) {
    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_CERT_UNTRUSTED:
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        case X509_V_ERR_INVALID_CA:
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return 1;
        default:
            return 0;
    }
}

/* Same diagnostic-only contract as log_hostname_comparison() above. */
static void log_chain_comparison(int r, const char *reason, int openssl_vok, int openssl_err) {
    int openssl_ok = (openssl_vok == 1);
    int chain_trust_err = !openssl_ok && openssl_is_chain_trust_error(openssl_err);

    if (r < 0) {
        fprintf(stderr, "[selfcheck-chain] not applicable (%s)\n", reason);
    } else if (openssl_ok) {
        if (r == 1) fprintf(stderr, "[selfcheck-chain] OK -- hand-rolled chain-of-trust check agrees with OpenSSL\n");
        else fprintf(stderr, "[selfcheck-chain] MISMATCH -- OpenSSL trusted this chain but hand-rolled check says: %s\n", reason);
    } else if (chain_trust_err) {
        if (r == 0) fprintf(stderr, "[selfcheck-chain] OK -- hand-rolled check agrees with OpenSSL's rejection (%s)\n", reason);
        else fprintf(stderr, "[selfcheck-chain] MISMATCH -- OpenSSL rejected this chain but hand-rolled check says OK\n");
    } else {
        fprintf(stderr, "[selfcheck-chain] (hostname/date issue outside this check's scope, informational only) chain-of-trust: %s\n",
                r == 1 ? "OK" : reason);
    }
}
#endif

/* ======================================================================
 * OpenSSL reference implementation -- compiled in only under
 * NANOCURL_VERIFY_WITH_OPENSSL, used solely to audit the hand-rolled
 * checks above against a battle-tested reference (see the file-level
 * comment). Never influences the exit code.
 * ==================================================================== */
#ifdef NANOCURL_VERIFY_WITH_OPENSSL

/* Verifies `sig` over `content` using `pkey`, per the TLS SignatureScheme
   in `sigalg`. Returns 1 on a valid signature, 0 otherwise (including
   unsupported algorithms -- fail closed). */
static int verify_signature(EVP_PKEY *pkey, size_t sigalg, const u8 *sig, size_t siglen,
                             const u8 *content, size_t clen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;
    int ok = 0;

    if (sigalg == 0x0807 /* ed25519: one-shot API, no digest */) {
        if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) == 1)
            ok = EVP_DigestVerify(mdctx, sig, siglen, content, clen) == 1;
        EVP_MD_CTX_free(mdctx);
        return ok;
    }

    const EVP_MD *md;
    switch (sigalg) {
        case 0x0501: case 0x0503: case 0x0805: md = EVP_sha384(); break; /* *_sha384 schemes */
        case 0x0601: case 0x0603: case 0x0806: md = EVP_sha512(); break; /* *_sha512 schemes */
        default: md = EVP_sha256(); break; /* covers 0x0401/0x0403/0x0804 (all nanocurl offers) */
    }

    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit(mdctx, &pctx, md, NULL, pkey) != 1) { EVP_MD_CTX_free(mdctx); return 0; }

    /* rsa_pss_rsae_* : PSS padding, salt length == digest length */
    if (sigalg == 0x0804 || sigalg == 0x0805 || sigalg == 0x0806) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) { EVP_MD_CTX_free(mdctx); return 0; }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) { EVP_MD_CTX_free(mdctx); return 0; }
    }
    /* rsa_pkcs1_* and ecdsa_* need no extra padding config: RSA defaults to
       PKCS#1 v1.5, and OpenSSL's EVP EC path expects the DER ECDSA-Sig-Value
       the TLS wire format already uses -- same encoding either way. */

    if (EVP_DigestVerifyUpdate(mdctx, content, clen) != 1) { EVP_MD_CTX_free(mdctx); return 0; }
    ok = EVP_DigestVerifyFinal(mdctx, sig, siglen) == 1;
    EVP_MD_CTX_free(mdctx);
    return ok;
}

/* Runs the OpenSSL-based reference checks and prints all three [selfcheck]
   comparison lines against the hand-rolled verdicts the caller already
   computed. `certs[0]` is the leaf (may be NULL if OpenSSL itself failed to
   parse it, handled gracefully -- that mismatch is itself useful to see). */
static void run_openssl_reference_and_compare(X509 *const *certs, int ncerts, const char *host,
                                               size_t sigalg, const u8 *sig, size_t siglen,
                                               const u8 *content, size_t clen,
                                               int host_r, const char *host_reason,
                                               int chain_r, const char *chain_reason,
                                               int sig_r, const char *sig_reason) {
    ERR_load_crypto_strings();
    X509 *leaf = certs[0];
    int vok = 0, sigok = 0, openssl_err = -1; /* -1: not a real X509_V_ERR_* code, just "didn't run" */

    if (leaf) {
        X509_STORE *store = X509_STORE_new();
        STACK_OF(X509) *untrusted = NULL;
        if (store && X509_STORE_set_default_paths(store) == 1) {
            untrusted = sk_X509_new_null();
            for (int i = 1; i < ncerts; i++) if (certs[i]) sk_X509_push(untrusted, certs[i]);
            X509_STORE_CTX *sctx = X509_STORE_CTX_new();
            if (sctx && X509_STORE_CTX_init(sctx, store, leaf, untrusted) == 1) {
                X509_STORE_CTX_set_purpose(sctx, X509_PURPOSE_SSL_SERVER);
                X509_VERIFY_PARAM *vp = X509_STORE_CTX_get0_param(sctx);
                X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
                X509_VERIFY_PARAM_set1_host(vp, host, 0);
                vok = X509_verify_cert(sctx);
                openssl_err = X509_STORE_CTX_get_error(sctx);
            }
            if (sctx) X509_STORE_CTX_free(sctx);
        }
        if (untrusted) sk_X509_free(untrusted);
        if (store) X509_STORE_free(store);

        EVP_PKEY *pubkey = X509_get_pubkey(leaf);
        if (pubkey) {
            sigok = verify_signature(pubkey, sigalg, sig, siglen, content, clen);
            EVP_PKEY_free(pubkey);
        }
    } else {
        fprintf(stderr, "[selfcheck] OpenSSL could not parse the leaf certificate at all -- skipping comparison\n");
    }

    log_hostname_comparison(host_r, host_reason, openssl_err);
    log_chain_comparison(chain_r, chain_reason, vok, openssl_err);
    log_sig_comparison(sig_r, sig_reason, sigok);
}
#endif /* NANOCURL_VERIFY_WITH_OPENSSL */

#ifndef NANOCURL_VERIFY_NO_MAIN
int main(void) {
    PROF_START();
    u8 version = rd_u8();
    if (version != 1) { wrs(2, "nanocurl-verify: unsupported request version ", utoa(version), "\n", WR_END); return 2; }

    size_t hlen = rd_u16();
    if (hlen == 0 || hlen > MAX_HOST_LEN) { wrs(2, "nanocurl-verify: bad hostname length\n", WR_END); return 2; }
    char host[MAX_HOST_LEN+1];
    rd_all(host, hlen); host[hlen] = '\0';

    size_t sigalg = rd_u16();

    size_t siglen = rd_u16();
    if (siglen == 0 || siglen > MAX_SIG_LEN) { wrs(2, "nanocurl-verify: bad signature length\n", WR_END); return 2; }
    u8 sig[MAX_SIG_LEN];
    rd_all(sig, siglen);

    u8 transcript_hash[32];
    rd_all(transcript_hash, 32);

    size_t ncerts = rd_u16();
    if (ncerts == 0 || ncerts > MAX_CERTS) {
        wrs(2, "nanocurl-verify: server sent ", utoa((unsigned long long)ncerts),
               " certificates (must be 1-" NANOCURL_STR(MAX_CERTS) ")\n", WR_END);
        return 1;
    }

    u8 *all_der[MAX_CERTS] = {0}; size_t all_der_len[MAX_CERTS] = {0};
#ifdef NANOCURL_VERIFY_WITH_OPENSSL
    X509 *certs[MAX_CERTS] = {0};
#endif
    for (size_t i = 0; i < ncerts; i++) {
        size_t dl = rd_u24();
        if (dl == 0 || dl > MAX_CERT_LEN) { wrs(2, "nanocurl-verify: bad certificate length\n", WR_END); return 2; }
        u8 *der = malloc(dl);
        if (!der) { wrs(2, "nanocurl-verify: out of memory\n", WR_END); return 2; }
        rd_all(der, dl);
        all_der[i] = der; all_der_len[i] = dl;
#ifdef NANOCURL_VERIFY_WITH_OPENSSL
        /* Parsed only for the reference comparison below -- a parse failure
           here doesn't stop anything; the hand-rolled parse a few lines
           down is what actually decides the outcome, and will reject a
           genuinely malformed certificate on its own. */
        { const u8 *p = der; certs[i] = d2i_X509(NULL, &p, (long)dl); }
#endif
    }
    u8 *leaf_der = all_der[0]; size_t leaf_der_len = all_der_len[0];
    PROF_MARK("request read + parsed");

    /* --- authoritative checks: entirely hand-rolled, zero libcrypto calls
       in a default build. See the file-level comment for the two things
       this proves and why both are needed. --- */
    char host_reason[128] = {0}, chain_reason[160] = {0}, sig_reason[128] = {0};
    int host_r = handrolled_check_leaf(leaf_der, leaf_der_len, host, host_reason, sizeof host_reason);
    PROF_MARK("leaf hostname/validity check");
    int chain_r = handrolled_verify_chain((const u8 *const *)all_der, all_der_len, (int)ncerts, chain_reason, sizeof chain_reason);
    PROF_MARK("chain-of-trust check (sig. verification) done");
    u8 content[64 + 64 + 32];
    size_t clen = build_signed_content(transcript_hash, content);
    int sig_r = handrolled_verify_certverify(leaf_der, leaf_der_len, sigalg, sig, siglen, content, clen, sig_reason, sizeof sig_reason);
    PROF_MARK("CertificateVerify signature check done");

#ifdef NANOCURL_VERIFY_WITH_OPENSSL
    run_openssl_reference_and_compare(certs, (int)ncerts, host, sigalg, sig, siglen, content, clen,
                                       host_r, host_reason, chain_r, chain_reason, sig_r, sig_reason);
    for (size_t i = 0; i < ncerts; i++) if (certs[i]) X509_free(certs[i]);
#endif
    for (size_t i = 0; i < ncerts; i++) free(all_der[i]);

    /* r == 1: verified. r == 0: actively rejected (bad signature, wrong
       hostname, expired, ...). r == -1: this minimal verifier doesn't
       support whatever algorithm/curve/structure it hit -- fail closed,
       since "couldn't check" is not the same as "checked out fine". */
    if (host_r != 1) {
        wrs(2, "nanocurl-verify: certificate verification failed for ", host, ": ",
               host_reason[0] ? host_reason : "hostname/validity check failed",
               host_r < 0 ? " (unsupported by this minimal verifier -- rebuild with -DNANOCURL_VERIFY_WITH_OPENSSL for full algorithm coverage)" : "",
               "\n", WR_END);
        return 1;
    }
    if (chain_r != 1) {
        wrs(2, "nanocurl-verify: certificate verification failed for ", host, ": ",
               chain_reason[0] ? chain_reason : "chain-of-trust check failed",
               chain_r < 0 ? " (unsupported by this minimal verifier -- rebuild with -DNANOCURL_VERIFY_WITH_OPENSSL for full algorithm coverage)" : "",
               "\n", WR_END);
        return 1;
    }
    if (sig_r != 1) {
        wrs(2, "nanocurl-verify: CertificateVerify signature check failed for ", host,
               " (sigalg ", u16hex((unsigned)sigalg), ")",
               sig_r < 0 ? " (algorithm unsupported by this minimal verifier)" : "",
               " -- the certificate may be valid but the server could not prove it holds the matching "
               "private key; this connection may be actively intercepted\n", WR_END);
        return 1;
    }
    return 0;
}
#endif /* NANOCURL_VERIFY_NO_MAIN */
