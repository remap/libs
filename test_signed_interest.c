
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
const unsigned char NS_SIGNATURE[4] = { 0xC1, '.', 'S', 0 };		// %C1.S signature namespace (proposed)
const char* TEST_URI = "ccnx:/data_for_a_signed_interest";

int main(int argc, char** argv) {
	int res = 0;
	struct ccn* ccn_pub;
	struct ccn* ccn_rec;
	int complete=0;


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

    // Create a signed version using the default key
    struct ccn_charbuf *signature = ccn_charbuf_create();
    struct ccn_charbuf *name_signed = ccn_charbuf_create();
    struct ccn_signing_params name_sp = CCN_SIGNING_PARAMS_INIT;
    ccn_charbuf_append(signature, NS_SIGNATURE, 4);
    res = ccn_sign_content(ccn_pub, signature, name, &name_sp, NULL, 0);			// Inefficient - repeats name?
    if (res < 0) {
        fprintf(stderr, "Error signing (res == %d)\n", res);
        return(1);
    }
    ccn_charbuf_append_charbuf(name_signed, name);
    ccn_name_append(name_signed, signature->buf, signature->length);

    /* Dump the signature
    fprintf(stderr,"Signature with header %%C1.S:\n");
    print_hex(stderr,signature->buf,signature->length,12);
    fprintf(stderr,"\n");
	*/

    // Get that default key -- Why do we have to do all this work??
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
	    }


    // Express the interest from a different ccn handle so we get the packet
    ccn_express_interest(ccn_rec, name_signed, cl, NULL);			// TODO: AnswerOriginKind could limit to signed interest?

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
        fprintf(stderr, "Interest components %d\n", (int) info->interest_comps->n);
        unsigned char* comp;
        size_t size;
        int res;
		int i;

		for (i=0; i<info->interest_comps->n; i++) {
			// We have to iterate through this?
	        res = ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
	                                i,
	                                (const unsigned char**)&comp, &size);
	       /* fprintf(stderr, "%d: ", (int)i);
	        fwrite(comp,size,1,stderr);
	        fprintf(stderr, "\n");
	        print_hex(stderr,comp,size,12);
	        fprintf(stderr,"\n");
	       */
		}

		// Last component should be the signature, components are base 1?

		// Can't just grab the fourth?? Q for parc
		//ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
        //									info->interest_comps->n,
        //	                                (const unsigned char**)&comp, &size);

		// Check for tag
		int siglen = (int) sizeof(NS_SIGNATURE);
		if (memcmp(NS_SIGNATURE, comp, siglen) != 0) {
			fprintf(stderr, "Last component not tagged as a signature.\n");
			return(0);
		}

		// Parse our empty content object
		struct ccn_parsed_ContentObject pco = {0};
		res = ccn_parse_ContentObject(&comp[siglen], size-siglen, &pco, NULL);
		fprintf(stderr, "ccn_parseContentObject == %d\n", res);

		if (!res) {
			// Verify the signature against the previously retrieved public key
			res = ccn_verify_signature(&comp[siglen], pco.offset[CCN_PCO_E], &pco, public_key);
			fprintf(stderr, "ccn_verify_signature == %d (%s)\n", res, (res==1)?"verified":"unverified");
		}

        return (0);
    }

    return (-1);

}
