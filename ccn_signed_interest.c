#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ccn/ccn.h>
#include <ccn/charbuf.h>
#include <ccn/coding.h>
#include <ccn/indexbuf.h>
#include <ccn/signing.h>

#include "signed_interest.h"

// Borrowed verbatim from ccn_buf_encoder.c
// Static with no headers, so...
//
static int
ccn_encode_Signature(struct ccn_charbuf *buf,
                     const char *digest_algorithm,
                     const void *witness,
                     size_t witness_size,
                     const struct ccn_signature *signature,
                     size_t signature_size)
{
    int res = 0;

    if (signature == NULL)
        return(-1);

    res |= ccn_charbuf_append_tt(buf, CCN_DTAG_Signature, CCN_DTAG);

    if (digest_algorithm != NULL) {
        res |= ccn_charbuf_append_tt(buf, CCN_DTAG_DigestAlgorithm, CCN_DTAG);
        res |= ccn_charbuf_append_tt(buf, strlen(digest_algorithm), CCN_UDATA);
        res |= ccn_charbuf_append_string(buf, digest_algorithm);
        res |= ccn_charbuf_append_closer(buf);
    }

    if (witness != NULL) {
        res |= ccn_charbuf_append_tt(buf, CCN_DTAG_Witness, CCN_DTAG);
        res |= ccn_charbuf_append_tt(buf, witness_size, CCN_BLOB);
        res |= ccn_charbuf_append(buf, witness, witness_size);
        res |= ccn_charbuf_append_closer(buf);
    }

    res |= ccn_charbuf_append_tt(buf, CCN_DTAG_SignatureBits, CCN_DTAG);
    res |= ccn_charbuf_append_tt(buf, signature_size, CCN_BLOB);
    res |= ccn_charbuf_append(buf, signature, signature_size);
    res |= ccn_charbuf_append_closer(buf);

    res |= ccn_charbuf_append_closer(buf);

    return(res == 0 ? 0 : -1);
}

// Slightly modified from ccn_buf_encoder.c
//
int
ccn_encode_ContentObjectWithoutName(struct ccn_charbuf *buf,
                         const struct ccn_charbuf *Name,
                         const struct ccn_charbuf *SignedInfo,
                         const void *data,
                         size_t size,
                         const char *digest_algorithm,
                         const struct ccn_pkey *private_key
                         )
{
    int res = 0;
    struct ccn_sigc *sig_ctx;
    struct ccn_signature *signature;
    size_t signature_size;
    struct ccn_charbuf *content_header;
    size_t closer_start;

    // Added:
    struct ccn_charbuf *empty_name = ccn_charbuf_create();
    ccn_name_init(empty_name);

    content_header = ccn_charbuf_create();
    res |= ccn_charbuf_append_tt(content_header, CCN_DTAG_Content, CCN_DTAG);
    if (size != 0)
        res |= ccn_charbuf_append_tt(content_header, size, CCN_BLOB);
    closer_start = content_header->length;
    res |= ccn_charbuf_append_closer(content_header);
    if (res < 0)
        return(-1);
    sig_ctx = ccn_sigc_create();
    if (sig_ctx == NULL)
        return(-1);
    if (0 != ccn_sigc_init(sig_ctx, digest_algorithm))
        return(-1);
    if (0 != ccn_sigc_update(sig_ctx, Name->buf, Name->length))
        return(-1);
    if (0 != ccn_sigc_update(sig_ctx, SignedInfo->buf, SignedInfo->length))
        return(-1);
    if (0 != ccn_sigc_update(sig_ctx, content_header->buf, closer_start))
        return(-1);
    if (0 != ccn_sigc_update(sig_ctx, data, size))
        return(-1);
    if (0 != ccn_sigc_update(sig_ctx, content_header->buf + closer_start,
                             content_header->length - closer_start))
        return(-1);
    signature = calloc(1, ccn_sigc_signature_max_size(sig_ctx, private_key));
    if (signature == NULL)
        return(-1);
    res = ccn_sigc_final(sig_ctx, signature, &signature_size, private_key);
    if (0 != res) {
        free(signature);
        return(-1);
    }
    ccn_sigc_destroy(&sig_ctx);
    res |= ccn_charbuf_append_tt(buf, CCN_DTAG_ContentObject, CCN_DTAG);
    res |= ccn_encode_Signature(buf, digest_algorithm,
                                NULL, 0, signature, signature_size);
    res |= ccn_charbuf_append_charbuf(buf, empty_name); // modified
    res |= ccn_charbuf_append_charbuf(buf, SignedInfo);
    res |= ccnb_append_tagged_blob(buf, CCN_DTAG_Content, data, size);
    res |= ccn_charbuf_append_closer(buf);
    free(signature);
    ccn_charbuf_destroy(&content_header);

    // Added:
    ccn_charbuf_destroy(&empty_name);

    return(res == 0 ? 0 : -1);
}

