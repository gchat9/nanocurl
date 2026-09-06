/*
 * der.h -- minimal bounded ASN.1 DER TLV reader, header-only.
 *
 * Not cryptographic itself, but pulled into its own header rather than
 * left inline because both pki_crypto.h (parsing key/signature encodings)
 * and nanocurl-verify.c (walking certificate structure) need it, and
 * duplicating even this small a parser between them would be exactly the
 * kind of avoidable divergence this whole header split is meant to prevent.
 *
 * DER only (definite lengths, minimal encoding) -- indefinite-length BER
 * and non-minimal length encodings are rejected outright, not "handled
 * leniently", since leniency here is exactly the kind of parser
 * disagreement that becomes a signature-verification bypass elsewhere.
 */
#ifndef NANOCURL_DER_H
#define NANOCURL_DER_H

#include <stdint.h>
#include <stddef.h>

#ifndef NANOCURL_BASIC_TYPES_DEFINED
#define NANOCURL_BASIC_TYPES_DEFINED
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

typedef struct { const u8 *p, *end; } der_reader_t;
typedef struct { u8 tag; int constructed; const u8 *value; size_t len; } der_tlv_t;

/* Reads exactly one DER TLV at r->p and advances r->p past it (header
   included). Returns 0 on any malformed or truncated encoding -- callers
   treat that as "reject", never as "guess and continue". */
static int der_read_tlv(der_reader_t *r, der_tlv_t *out) {
    if (r->end - r->p < 2) return 0;
    u8 tag = *r->p;
    if ((tag & 0x1f) == 0x1f) return 0; /* high-tag-number form: unused by anything we parse */
    const u8 *p = r->p + 1;
    u8 lb = *p++;
    size_t len;
    if (lb < 0x80) {
        len = lb;
    } else {
        int nbytes = lb & 0x7f;
        if (nbytes == 0 || nbytes > 4) return 0; /* indefinite-length or absurdly large */
        if ((size_t)(r->end - p) < (size_t)nbytes) return 0;
        len = 0;
        for (int i = 0; i < nbytes; i++) len = (len << 8) | *p++;
        if (len < 0x80) return 0; /* non-minimal length encoding */
    }
    if ((size_t)(r->end - p) < len) return 0;
    out->tag = tag;
    out->constructed = (tag & 0x20) != 0;
    out->value = p;
    out->len = len;
    r->p = p + len;
    return 1;
}

#endif /* NANOCURL_DER_H */
