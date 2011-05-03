
#ifndef SIGNED_INTEREST_H_
#define SIGNED_INTEREST_H_



// Our new func
int
ccn_encode_ContentObjectWithoutName(struct ccn_charbuf *buf,
                         const struct ccn_charbuf *Name,
                         const struct ccn_charbuf *SignedInfo,
                         const void *data,
                         size_t size,
                         const char *digest_algorithm,
                         const struct ccn_pkey *private_key
                         );

#endif /* SIGNED_INTEREST_H_ */
