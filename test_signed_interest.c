#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/signing.h>
#include <ccn/keystore.h>
#include <ccn/hashtb.h>
#include "signed_interest.h"
#include "ccn_internal_structs.h" // To use hashtable of keystore via ccn handle - we should not need this

// NDN Signed interest demonstration code
// jburke@ucla.edu 03 May 2011
//
// Signed interest format:
// <prefix>/<sig_namespace><sigContentObject>
// where <sigContentObject> is a ContentObject with no name (it is implicitly named <prefix>) and no data
//

// ccnx API tutorials / descriptions that should be written:
// - parsedContentObject
// - using data structures associated with upcalls
//


// replace_name()
// Helper funtion to replace names in content objects
// Could build another version that works on already parsed content objects
// But as seen below it would be better to use a modified encoding call that
// didn't include the name at all.
//
int replace_name(struct ccn_charbuf* dest, unsigned char* src,  size_t src_size, struct ccn_charbuf* name) {
	struct ccn_parsed_ContentObject* pco = (struct ccn_parsed_ContentObject*) calloc(sizeof(struct ccn_parsed_ContentObject), 1);
	int res = 0;
	res = ccn_parse_ContentObject(src,src_size, pco, NULL);
    if (res < 0) {
    	free(pco);
    	return (res);
    }
	ccn_charbuf_append_tt(dest, CCN_DTAG_ContentObject, CCN_DTAG);
	ccn_charbuf_append(dest, &src[pco->offset[CCN_PCO_B_Signature]], pco->offset[CCN_PCO_E_Signature] - pco->offset[CCN_PCO_B_Signature]);
	ccn_charbuf_append_charbuf(dest, name); // Already tagged
	ccn_charbuf_append(dest, &src[pco->offset[CCN_PCO_B_SignedInfo]], pco->offset[CCN_PCO_E_SignedInfo] - pco->offset[CCN_PCO_B_SignedInfo]);
	ccnb_append_tagged_blob(dest, CCN_DTAG_Content, NULL, 0);
	ccn_charbuf_append_closer(dest);
	free(pco);
	return (0);
}

// print_hex()
// Utility func to dump binary data to a handle.
void print_hex(FILE* fp, unsigned char* buf, int length, int  W) {
	int k;
	for (k=0; k< length; k++) {
		fprintf(fp, "%02X ", buf[k]);
		if ((k+1) % W == 0) fprintf(fp,"\n");
	}
}

// Our single packet handler for interest and data upcalls
enum ccn_upcall_res packet_handler(struct ccn_closure *selfp, enum ccn_upcall_kind, struct ccn_upcall_info *info);
typedef struct {
	int* complete;
	struct ccn_pkey** public_key;
} handler_data;


// The namespace we propose
const char* NS_SIGNATURE = "org.named-data.sig";
int NS_SIGNATURE_LEN = 0;

// Our test content URI; the code appends a nonce.
const char* TEST_URI = "ccnx:/data_for_a_signed_interest";

int main(int argc, char** argv) {
	int res = 0;
	struct ccn* ccn_pub;
	struct ccn* ccn_rec;

	// Will hold the public/private key used for signing
	struct ccn_pkey* public_key = NULL;
	struct ccn_pkey* private_key = NULL;

	int complete=0;

	NS_SIGNATURE_LEN = (int) strlen(NS_SIGNATURE) + 1 ;

	// We need two ccn handles because the same handle cannot be used
	// to answer interests it issues.
	//
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

    // Closure to handle upcalls
    struct ccn_closure *cl = NULL;
    cl = calloc(1, sizeof(*cl));
    cl->p = &packet_handler;
    handler_data h_data = { &complete, &public_key };
    cl->data = &h_data;

    // Setup our one test name without signature
    struct ccn_charbuf* name;
    name = ccn_charbuf_create();
    ccn_name_from_uri(name, TEST_URI);
    ccn_name_append_nonce(name);
    fprintf(stderr, "Our name: %s/<nonce>\n", TEST_URI);

    // Set up a filter for interests in that name
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
    // These structures are supposed to be internal to the libs but
    // there doesn't appear to be an API to deal with the keystores -
    //
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

    // We'll need  a KeyLocator for our ContentObject
	// So continue borrowed code
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
    // And a SignedInfo too
    struct ccn_charbuf *signed_info = ccn_charbuf_create();
    res = ccn_signed_info_create(signed_info,
			 ccn_keystore_public_key_digest(keystore),
			 ccn_keystore_public_key_digest_length(keystore),
			 timestamp,
			 p.type,
			 p.freshness,
			 0,  /* FinalBlockID is optional */
			 keylocator);

	// Now assemble a signed Content object
    // Use ccn_encode_ContentObject so we can specify the key of our choice
    struct ccn_charbuf *tempContentObj = ccn_charbuf_create();
    res = ccn_encode_ContentObject(tempContentObj, name, signed_info, NULL /* no data */, 0,
    							   NULL /* default sig alg */, private_key);
    if (res < 0) {
        fprintf(stderr, "Error building content object (res == %d)\n", res);
        return(1);
    }
    // Call replace_name to knock out the name;
    // it would be more efficient to assemble this with no name a modified ccn_encode_ContentObject() call
    // but that requires modification to the library function
    struct ccn_charbuf *empty_name = ccn_charbuf_create();
    struct ccn_charbuf *sigContentObj = ccn_charbuf_create();
    ccn_name_init(empty_name);
    // First prepend the namespace; (should this be done as a "name component"?)
    ccn_charbuf_append(sigContentObj, NS_SIGNATURE, NS_SIGNATURE_LEN);
    replace_name(sigContentObj, tempContentObj->buf, tempContentObj->length, empty_name);
	fprintf(stderr, "replace_name == %d (%s)\n", res, (res==0)?"ok":"fail");
    /*
    // Check that we didn't break things
	struct ccn_parsed_ContentObject pco = {0};
	res = ccn_parse_ContentObject(&sigContentObj->buf[NS_SIGNATURE_LEN], sigContentObj->length - NS_SIGNATURE_LEN, &pco, NULL);
    if (res < 0) {
        fprintf(stderr, "Error parsing built content object (res == %d)\n", res);
        return(1);
    }
    */
	ccn_charbuf_destroy(&empty_name);
	ccn_charbuf_destroy(&tempContentObj);

	// Build the final name for the interest  <prefix>/<namespace><contentObj>
    struct ccn_charbuf *name_signed = ccn_charbuf_create();
    ccn_charbuf_append_charbuf(name_signed, name); // Copy the name
    ccn_name_append(name_signed, sigContentObj->buf, sigContentObj->length);  // Concatenate the new component

    // Dump the signature
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

    while(1) {
    	// Not sure how to handle two ccn_runs?
        ccn_run(ccn_pub, 100); /* stop if we run dry for .1 sec */
        ccn_run(ccn_rec, 100); /* stop if we run dry for .1 sec */
        if (complete) break;
        fflush(stdout);
    }

    ccn_destroy(&ccn_pub);
    ccn_destroy(&ccn_rec);
    fflush(stderr);
	return(0);
}

// packet_handler()
//
enum ccn_upcall_res
packet_handler(struct ccn_closure *selfp,
                 enum ccn_upcall_kind upcall_kind,
                 struct ccn_upcall_info *info)
{
	handler_data* h_data = (handler_data*) selfp->data; // Client data returned
	(*h_data->complete) = 1; 	      // End the main loop
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

        // What is info->interest_comps->n ?
        //fprintf(stderr, "Interest components %d\n", (int) info->interest_comps->n);

        unsigned char* comp;
        size_t size;
        int res;

        // Create a charbuf with the matched interest name incl nonce
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
		// and replace the name with the implicit name from the interest, so that
		// we can use the standard signature verification calls.  Could be made
		// more efficient with different library calls.
		struct ccn_charbuf* co_with_name = ccn_charbuf_create();
	    unsigned char* co = &comp[NS_SIGNATURE_LEN];
	    replace_name(co_with_name, co, size-NS_SIGNATURE_LEN, name);
		fprintf(stderr, "replace_name == %d (%s)\n", res, (res==0)?"ok":"fail");

		// For now, use standard routines to verify signature
		struct ccn_parsed_ContentObject pco = {0};
		res = ccn_parse_ContentObject(co_with_name->buf, co_with_name->length, &pco, NULL);
		if (!res) {
			// Verify the signature against the authorized public key given to us, passed through to the handler
			res = ccn_verify_signature(co_with_name->buf, pco.offset[CCN_PCO_E], &pco, (*h_data->public_key));
			fprintf(stderr, "ccn_verify_signature == %d (%s)\n", res, (res==1)?"verified":"unverified");
		} else {
			fprintf(stderr, "Constructed content object parse failed (res==%d)\n", res);
		}
		ccn_charbuf_destroy(&co_with_name);
        return (0);
    }
    return (-1);

}
