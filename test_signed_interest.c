
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/signing.h>
#include <ccn/keystore.h>
#include <ccn/hashtb.h>

#include "signed_interest.h"

// for hashtable of keystore via ccn handle - we should not need this
#include "ccn_internal_structs.h"

enum ccn_upcall_res packet_handler(struct ccn_closure *selfp,
                                     enum ccn_upcall_kind,
                                     struct ccn_upcall_info *info);

void print_hex(FILE* fp, unsigned char* buf, int length, int  W) {
	int k;
	for (k=0; k< length; k++) {
		fprintf(fp, "%02X ", buf[k]);
		if ((k+1) % W == 0) fprintf(fp,"\n");
	}
}

struct ccn_pkey* public_key = NULL;
struct ccn_pkey* private_key = NULL;

const char* NS_SIGNATURE = "org.named-data.sig";		// namespace (proposed)
int NS_SIGNATURE_LEN = 0;

const char* TEST_URI = "ccnx:/data_for_a_signed_interest";



int main(int argc, char** argv) {
	int res = 0;
	struct ccn* ccn_pub;
	struct ccn* ccn_rec;
	int complete=0;

	NS_SIGNATURE_LEN = (int) strlen(NS_SIGNATURE) + 1 ;

	ccn_pub = ccn_create();
    if (ccn_connect(ccn_pub, NULL) == -1) {
        fprintf(stderr, "Could not connect to ccnd");
        return(1);
    }
    ccn_rec = ccn_create();
    if (ccn_connect(ccn_rec, NULL) == -1) {
        fprintf(stderr, "Could not connect to ccnd");
        return(1);
    }


    // Create a single packet handler for interest and data upcalls
    struct ccn_closure *cl = NULL;
    cl = calloc(1, sizeof(*cl));
    cl->p = &packet_handler;
    cl->data = &complete;

    // Setup the name
    struct ccn_charbuf* name;
    name = ccn_charbuf_create();
    ccn_name_from_uri(name, TEST_URI);
    ccn_name_append_nonce(name);

    // Set up a handler for interest - using unsigned name as the prefix
    res = ccn_set_interest_filter(ccn_pub, name, cl);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        return(1);
    }

    // Get our default keys -- Why do we have to do all this work??
    // Borrowed from ccn_client.c
    struct ccn_signing_params name_sp = CCN_SIGNING_PARAMS_INIT;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ccn_signing_params p = CCN_SIGNING_PARAMS_INIT;
    struct ccn_keystore *keystore = NULL;
    struct ccn_charbuf *timestamp = NULL;
    struct ccn_charbuf *finalblockid = NULL;
    struct ccn_charbuf *keylocator = NULL;
    res = ccn_chk_signing_params(ccn_pub,&name_sp, &p,
                                 &timestamp, &finalblockid, &keylocator);
    if (res < 0)
        return(res);
    hashtb_start(ccn_pub->keystores, e);
	    if (hashtb_seek(e, p.pubid, sizeof(p.pubid), 0) != HT_OLD_ENTRY) {
	    	fprintf(stderr,"No default keystore?\n");
	    	res = -1;
	    } else {
	        struct ccn_keystore **pk = e->data;
	        keystore = *pk;
	        public_key = (struct ccn_pkey*) ccn_keystore_public_key(keystore);
	        private_key = (struct ccn_pkey*) ccn_keystore_private_key(keystore);
	    }




    // Create a signed version using the default key
    struct ccn_charbuf *sigContentObj = ccn_charbuf_create();
    struct ccn_charbuf *name_signed = ccn_charbuf_create();
    ccn_charbuf_append(sigContentObj, NS_SIGNATURE, NS_SIGNATURE_LEN);




    // Continue the part borrowed from ccn_client.c
    if (keylocator == NULL && (p.sp_flags & CCN_SP_OMIT_KEY_LOCATOR) == 0) {
        /* Construct a key locator containing the key itself */
        keylocator = ccn_charbuf_create();
        ccn_charbuf_append_tt(keylocator, CCN_DTAG_KeyLocator, CCN_DTAG);
        ccn_charbuf_append_tt(keylocator, CCN_DTAG_Key, CCN_DTAG);
        res = ccn_append_pubkey_blob(keylocator,
                                     ccn_keystore_public_key(keystore));
        ccn_charbuf_append_closer(keylocator); /* </Key> */
        ccn_charbuf_append_closer(keylocator); /* </KeyLocator> */
    }
    //...
    struct ccn_charbuf *signed_info = ccn_charbuf_create();
    res = ccn_signed_info_create(signed_info,
			 ccn_keystore_public_key_digest(keystore),
			 ccn_keystore_public_key_digest_length(keystore),
			 timestamp,
			 p.type,
			 p.freshness,
			 0,  /* FinalBlockID is optional */
			 keylocator);

    // Use this call so we can sign with a private key of our choice
    // Modified helper function that doesn't encode them name
    res = ccn_encode_ContentObjectWithoutName(sigContentObj, name, signed_info, NULL, 0, NULL /* default sig alg */, private_key);

    // TODO: rewrite to parse the content object and remove the name.

    if (res < 0) {
        fprintf(stderr, "Error signing (res == %d)\n", res);
        return(1);
    }
    ccn_charbuf_append_charbuf(name_signed, name);
    ccn_name_append(name_signed, sigContentObj->buf, sigContentObj->length);

    // Dump the signature
    // fprintf(stderr,"Signature without header:\n");
    // print_hex(stderr,&(sigContentObj->buf)[NS_SIGNATURE_LEN],sigContentObj->length - NS_SIGNATURE_LEN,12);
    // fprintf(stderr,"\n");
	//

    hashtb_end(e);
    ccn_charbuf_destroy(&timestamp);
    ccn_charbuf_destroy(&keylocator);
    ccn_charbuf_destroy(&finalblockid);
    ccn_charbuf_destroy(&signed_info);


    // Express the interest from a different ccn handle so we get the packet
    res = ccn_express_interest(ccn_rec, name_signed, cl, NULL);			// TODO: AnswerOriginKind could limit to signed interest?
    if (res < 0) {
    	fprintf(stderr, "Error expressing interest (res == %d)\n", res);
    }
    cl = NULL;  						// freed by ccn?
    ccn_charbuf_destroy(&name);

    // Do the work
    while(1) {
        ccn_run(ccn_pub, 100); /* stop if we run dry for 1 sec */
        ccn_run(ccn_rec, 100); /* stop if we run dry for 1 sec */
        if (complete) break;
        fflush(stdout);
    }

    ccn_destroy(&ccn_pub);
    ccn_destroy(&ccn_rec);
    fflush(stderr);
	return(0);
}

enum ccn_upcall_res
packet_handler(struct ccn_closure *selfp,
                 enum ccn_upcall_kind upcall_kind,
                 struct ccn_upcall_info *info)
{

	// End the main loop
	(*(int*)selfp->data) = 1;
	ccn_set_run_timeout(info->h, 0); // Return to client faster

    switch(upcall_kind) {
    case CCN_UPCALL_FINAL:
        fprintf(stderr, "CCN_UPCALL_FINAL\n");
        return (0);
    case CCN_UPCALL_INTEREST_TIMED_OUT:
        fprintf(stderr, "CCN_UPCALL_INTEREST_TIMED_OUT\n");
        return (0);
    case CCN_UPCALL_CONTENT:
        fprintf(stderr, "CCN_UPCALL_CONTENT\n");
        return (0);
    case CCN_UPCALL_CONTENT_UNVERIFIED:
        fprintf(stderr, "CCN_UPCALL_CONTENT_UNVERIFIED\n");
        return (0);
    case CCN_UPCALL_CONTENT_BAD:
        fprintf(stderr, "CCN_UPCALL_CONTENT_BAD\n");
        return (0);
    case CCN_UPCALL_CONSUMED_INTEREST:
        fprintf(stderr, "CCN_UPCALL_CONSUMED_INTEREST\n");
        return (0);

    case CCN_UPCALL_INTEREST:

    	fprintf(stderr, "CCN_UPCALL_INTEREST, (matched comps == %d)\n", info->matched_comps);

        // What is this count?
        //fprintf(stderr, "Interest components %d\n", (int) info->interest_comps->n);

        unsigned char* comp;
        size_t size;
        int res;

        // Matched interest name
		struct ccn_charbuf* name = ccn_charbuf_create();
	    ccn_name_init(name);
	    res = ccn_name_append_components(name, info->interest_ccnb,
	                                     info->interest_comps->buf[0],
	                                     info->interest_comps->buf[info->matched_comps]);


	    // Last component, should be the signature
        res = ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                                info->matched_comps,
                                (const unsigned char**)&comp, &size);
		if (memcmp(NS_SIGNATURE, comp, NS_SIGNATURE_LEN) != 0) {
			fprintf(stderr, "Last component not tagged as a signature.\n");
			return(0);
		}

		// Parse our nameless, dataless content object that follows the namespace
		struct ccn_parsed_ContentObject pco = {0};
	    unsigned char* co = &comp[NS_SIGNATURE_LEN];
		res = ccn_parse_ContentObject(co, size-NS_SIGNATURE_LEN, &pco, NULL);
		fprintf(stderr, "ccn_parseContentObject == %d\n", res);


		// Reassemble a Content object with the name so we can use off the shelf sig verification
		struct ccn_charbuf* co_with_name = NULL;
		co_with_name = ccn_charbuf_create();

		ccn_charbuf_append_tt(co_with_name, CCN_DTAG_ContentObject, CCN_DTAG);
		// The CCN_PCO_B_* offsets point to the beginning of *tagged* content, don't retag them.
		ccn_charbuf_append(co_with_name, &co[pco.offset[CCN_PCO_B_Signature]], pco.offset[CCN_PCO_E_Signature] - pco.offset[CCN_PCO_B_Signature]);
		ccn_charbuf_append_charbuf(co_with_name, name); // Already tagged
		ccn_charbuf_append(co_with_name, &co[pco.offset[CCN_PCO_B_SignedInfo]], pco.offset[CCN_PCO_E_SignedInfo] - pco.offset[CCN_PCO_B_SignedInfo]);
		ccnb_append_tagged_blob(co_with_name, CCN_DTAG_Content, NULL, 0);
		ccn_charbuf_append_closer(co_with_name);
		//print_hex(stderr, co_with_name->buf,buf->length,12);

		res = ccn_parse_ContentObject(co_with_name->buf, co_with_name->length, &pco, NULL);
		if (!res) {
			// Verify the signature against the previously retrieved public key
			res = ccn_verify_signature(co_with_name->buf, pco.offset[CCN_PCO_E], &pco, public_key);
			fprintf(stderr, "ccn_verify_signature == %d (%s)\n", res, (res==1)?"verified":"unverified");
		} else {
			fprintf(stderr, "Constructed content object parse failed\n");
		}

		ccn_charbuf_destroy(&co_with_name);

        return (0);
    }

    return (-1);

}
