
#include <vector>
#include <string>
#include <boost/unordered_map.hpp>
#include <iostream>
using namespace std;
using namespace boost;
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


extern "C" {
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/signing.h>
#include <ccn/keystore.h>
}

// On MacOS X, need to have the latest version from MacPorts
// and add /opt/local/include as an include path
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ossl_typ.h>

#include "key_utils.hpp"

// print_hex()
// Utility func to dump binary data to a handle.
void print_hex(FILE* fp, unsigned char* buf, int length, int  W) {
	int k;
	for (k=0; k< length; k++) {
		fprintf(fp, "%02X ", buf[k]);
		if ((k+1) % W == 0) fprintf(fp,"\n");
	}
}


void to_SHA1_hex(const unsigned char* buf, size_t n, char* name_hash_str) {
	unsigned char name_hash[20];
	SHA1(buf, n, (unsigned char*)&name_hash);
	for (int k=0; k< 20; k++) {
		sprintf(&name_hash_str[k*2], "%02X ", (unsigned char)name_hash[k]);
	}
	name_hash_str[40]=0;
}

// Our packet handler for interest upcalls
enum ccn_upcall_res interest_handler (struct ccn_closure *selfp, enum ccn_upcall_kind, struct ccn_upcall_info *info);


int complete = 0;

// TODO:
// If we link against /opt/local/lib we have problems
// with openssl - need to check out what's going on

int main(int argc, char** argv) {

	 struct ccn* ccn = ccn_create();
	 if (ccn_connect(ccn, NULL) == -1) {
		 fprintf(stderr, "Could not connect to ccnd\n");
		 return(1);
	 } else {
		 fprintf(stderr, "Connected to ccnd\n");
	 }

// Some basic examples

	 // 1. Generate a key
	 struct ccn_pkey *private_key, *public_key;
	 unsigned char* public_key_digest;
	 size_t public_key_digest_len;
	 generate_key(1024, &private_key, &public_key, &public_key_digest, &public_key_digest_len);

	 // 2. Write it to a file
	 // No encryption:  App needs to develop a protection scheme,
	 // which could later be supported int his library
	 FILE* pem_file = fopen("test.pem", "w");
	 write_key_pem(pem_file, private_key);
	 fclose(pem_file);
	 write_key_pem(stderr, private_key);
	 write_key_pem_public(stderr, private_key);
	 release_key(&private_key, &public_key, &public_key_digest);

	 // 3. Read the key back in, this time use a keypair
	 // struct
	 pem_file = fopen("test.pem", "r");
	 read_key_pem(pem_file, &private_key, &public_key, &public_key_digest, &public_key_digest_len);
	 fclose(pem_file);
	 write_key_pem(stderr, private_key);
	 write_key_pem_public(stderr, private_key);

	 // 4. Use these keys to sign a content object
	 struct ccn_charbuf* buf = ccn_charbuf_create();
	 struct ccn_charbuf* name = ccn_charbuf_create();
	 ccn_name_init(name);
	 ccn_name_append_str(name, "hello, world");
	 struct ccn_signing_params p = CCN_SIGNING_PARAMS_INIT;
	 const char* data = "foo";

	 // We'll need  a KeyLocator for our ContentObject
	 struct ccn_charbuf *timestamp = NULL;
	 struct ccn_charbuf *keylocator = NULL;
	 build_keylocator_from_key(&keylocator, public_key);

	 int res = 0;
	 // Make SignedInfo
	struct ccn_charbuf *signed_info = ccn_charbuf_create();
	res = ccn_signed_info_create(signed_info,
		 public_key_digest,
		 public_key_digest_len,
		 timestamp,
		 p.type,
		 p.freshness,
		 0,  /* FinalBlockID is optional */
		 keylocator);
	 fprintf(stderr, "result of ccn_signed_info_create == %d\n", res);

	res = ccn_encode_ContentObject(buf, name, signed_info, data, strlen(data)+1, NULL, private_key);
	fprintf(stderr, "result of ccn_encodeContentObject == %d\n", res);

	struct ccn_indexbuf *comps = ccn_indexbuf_create();
	struct ccn_parsed_ContentObject pco = {0};
	ccn_parse_ContentObject(buf->buf, buf->length, &pco, comps);
	res = ccn_verify_content (ccn, buf->buf, &pco);
	fprintf(stderr, "ccn_verify_content == %d (%s)\n", res, (res==0)?"success":"failure");

	release_key(&private_key, &public_key, &public_key_digest);


	// 5.  Lighting specific example

	fprintf(stderr, "\n\nBegin lighting example -- \n\n");
	// Gumstix code would discover serial numbers for gumstix, data enabler(s), and fixture(s)
	// and generate or load keypairs
	// Gumstix serial number is mac address of eth0
	// So, make a list of serial numbers
	vector<string> device_serial_numbers;
	device_serial_numbers.push_back(string("60:33:4B:0E:74:94"));
	device_serial_numbers.push_back(string("serial-number"));
	device_serial_numbers.push_back(string("44129DL92"));

	// There should be keypairs for each device
	// We manage this in a hashtable
	// Boost has a good implementation
	//
	unordered_map<string, keypair*> device_keypairs;

	// We could just store the serial number to keypair mapping
	// in a database.
	// For simplicity, here, we store them in files named by the SHA1 hash of the
	// serial number.
	//
	FILE* pem;


	for (vector<string>::iterator it = device_serial_numbers.begin();  it != device_serial_numbers.end(); it++) {
		const char* name = &(*it->c_str());
	    char name_hash_str[41];	// 20 byte hash * 2 chars * term.
	    keypair *KP;
	    to_SHA1_hex((const unsigned char*)name, strlen(name), name_hash_str);
		fprintf(stderr, "'%s' %s\n", name, name_hash_str);

		// Load the key if available
		// Generate and save if not
		pem = fopen(name_hash_str, "r");
		if (pem != NULL) {
			 read_keypair_pem(pem, &KP);
			 fprintf(stderr, "loaded %s\n", name_hash_str);
			 fclose(pem);
		} else {
			generate_keypair(1024, &KP);
			pem = fopen(name_hash_str, "w");
			write_key_pem(pem, KP->private_key);
			fprintf(stderr, "generated and saved %s\n", name_hash_str);
		}
		fclose(pem);

		// Add to hashtable
		device_keypairs[*it] = KP;
	}

	// Example - print out our public keys.
	fprintf(stderr, "\n\nPrinting out our public keys, for example - \n");
	for (vector<string>::iterator it = device_serial_numbers.begin();  it != device_serial_numbers.end(); it++) {
		fprintf(stderr, "\nDevice serial '%s'\n", &(*it->c_str()));
		write_key_pem_public(stderr, device_keypairs[*it]->private_key);
	}

	// Now, let's provide these keys for others to get
	// Not using the real hierarchy yet
    struct ccn_charbuf* prefix = ccn_charbuf_create();
    const char* TEST_URI = "ccnx:/some/keys";
    ccn_name_from_uri(prefix, TEST_URI);
    fprintf(stderr, "Listening for key interests at %s\n", TEST_URI);


    // Setup closure to handle upcalls
    struct ccn_closure *cl = NULL;
    cl = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
    cl->p = &interest_handler;
    cl->data = &device_keypairs;	// we'll need this!

    // Set up a filter for interests in that name
    res = ccn_set_interest_filter(ccn, prefix, cl);
    if (res < 0) {
        fprintf(stderr, "Failed to register interest (res == %d)\n", res);
        return(1);
    } else {
    	fprintf(stderr, "Registered interest (res == %d)\n", res);
    }

    // Explain
    //
    fprintf(stderr, "\n");
    fprintf(stderr, "Now, issue an interest for a serial number to get a key\n");
    fprintf(stderr, "Format is ccnx:/some/keys/<serial>/<record_type>/<nonce>\n");
    fprintf(stderr, "Where <record_type> is key, for ASN encoding, or key_pem, for PEM encoding\n");
    fprintf(stderr, "And nonce is anything you haven't already requested, to avoid cache'd replies.\n");
    fprintf(stderr, "For example: \n");
	for (vector<string>::iterator it = device_serial_numbers.begin();  it != device_serial_numbers.end(); it++) {
		fprintf(stderr, "\t ccnget -c ccnx:/some/keys/%s/key\n", &(*it->c_str()));
		fprintf(stderr, "\t ccnget -c ccnx:/some/keys/%s/key_pem\n", &(*it->c_str()));
	}
	  fprintf(stderr, "\nTo quit, use Ctrl-C\n");

    // Handle events
    // (Answer just one)

    while(complete != 1) {
        ccn_run(ccn, 100); /* stop if we run dry for .1 sec */
        fflush(stdout);
        fflush(stderr);
    }

	 // Other cleanup to be done
	// Haven't checked that all memory leaks are closed yet
	// But, here's the device keypair cleanup -
	for (vector<string>::iterator it = device_serial_numbers.begin();  it != device_serial_numbers.end(); it++) {
		release_keypair(&device_keypairs[*it]);
	}

    ccn_charbuf_destroy(&name);
    ccn_destroy(&ccn);
    free (cl);
	return (0);
}

// packet_handler()
//
// For example 5.
//
enum ccn_upcall_res
interest_handler(struct ccn_closure *selfp,
                 enum ccn_upcall_kind upcall_kind,
                 struct ccn_upcall_info *info)
{

	// Get a pointer to our keypair hashmap from main()
	//
	unordered_map<string, keypair*> *p_device_keypairs = (unordered_map<string, keypair*> *) selfp->data;

	ccn_set_run_timeout(info->h, 0); // Return to client faster

	switch(upcall_kind) {
	case CCN_UPCALL_FINAL:
		fprintf(stderr, "CCN_UPCALL_FINAL\n");
		return (CCN_UPCALL_RESULT_OK);
	case CCN_UPCALL_CONTENT:
		fprintf(stderr, "CCN_UPCALL_CONTENT\n");
		return (CCN_UPCALL_RESULT_OK);
	case CCN_UPCALL_CONTENT_UNVERIFIED:
		fprintf(stderr, "CCN_UPCALL_CONTENT_UNVERIFIED\n");
		return (CCN_UPCALL_RESULT_OK);
	case CCN_UPCALL_CONTENT_BAD:
		fprintf(stderr, "CCN_UPCALL_CONTENT_BAD\n");
	case CCN_UPCALL_INTEREST_TIMED_OUT:
		fprintf(stderr, "CCN_UPCALL_INTEREST_TIMED_OUT\n");
		complete=1; 	      // End the main loop, some sort of problem
		return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_CONSUMED_INTEREST:
        fprintf(stderr, "CCN_UPCALL_CONSUMED_INTEREST\n");
        return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_INTEREST:
    	fprintf(stderr, "CCN_UPCALL_INTEREST, (matched comps == %d, interest comps = %zu)\n", info->matched_comps, info->interest_comps->n);
    	int res;
    	for (int k=0; k< info->interest_comps->n - 1; k++) {
    		// Need to better understand interest helper functions to make this easier?
    		fprintf(stderr, "comp %2d: %s\n", k,(char*) &info->interest_ccnb[info->interest_comps->buf[k]+2]);
    	}

    	// Check that its ours - there are helper functions for matching interest to data, use them here instead.
    	//
    	// Interest of format
    	// /some/keys/<serial_number>/<record_type>
    	// where <record_type> is key (for ASN encoding) or key_pem (for PEM encoding)
    	//
    	if ( (strcmp((char*) &info->interest_ccnb[info->interest_comps->buf[0]+2], "some") == 0)
    			&& (strcmp((char*) &info->interest_ccnb[info->interest_comps->buf[1]+2], "keys") == 0)
    			&& (info->interest_comps->n >= 5) )
    	{
    		fprintf(stderr,"Matched prefix and have minimum number of components.\n");
    		char *serial_num = (char*)&info->interest_ccnb[info->interest_comps->buf[2]+2];
    		char *record_type = (char*)&info->interest_ccnb[info->interest_comps->buf[3]+2];
    		// Security - need to protect against overflow attacks from large packets?

    		// Output the serial number and record type from the interest
    		//
    		fprintf(stderr, "Serial number: %s\n", serial_num);
    		fprintf(stderr, "Record type: %s\n", record_type);

    		// Check if we have a key for this serial number
    		//
    		keypair* KP = (*p_device_keypairs)[string(serial_num)];
    		if (KP != NULL) {
    			fprintf(stderr,"Matches a key we have, returning it self-signed by the same key.\n");

    			// Provide it in the requested encoding or return an error
    			//
    			unsigned char* reply_data;
    			int reply_len=0;
    			if (strcmp(record_type, "key")==0) {
    				get_ASN_public_key(&reply_data,&reply_len, KP->private_key);
    			} else if (strcmp(record_type, "key_pem")==0) {
    			    get_key_pem_public((char**)&reply_data, &reply_len, KP->private_key);		// zero term'd in memory.
    			} else {
    				reply_data = (unsigned char*)malloc(16);
    				strcpy((char*)reply_data, "BAD RECORD TYPE");
    				reply_len=16;
    			}

    			// We'll need  a KeyLocator for our ContentObject
    			struct ccn_charbuf *timestamp = NULL;
    			struct ccn_charbuf *keylocator = NULL;
    			build_keylocator_from_key(&keylocator, KP->public_key); // TODO: this should use name rather than the key itself

    			struct ccn_charbuf* reply = ccn_charbuf_create();
    			struct ccn_charbuf* name = ccn_charbuf_create();
    			struct ccn_signing_params p = CCN_SIGNING_PARAMS_INIT;

    			// Build the name
    			ccn_name_init(name); // Provide old name
    			res = ccn_name_append_components(name, info->interest_ccnb,
    					info->interest_comps->buf[0], info->interest_comps->buf[info->interest_comps->n - 1]);
    			// Build the signed info
    			struct ccn_charbuf *signed_info = ccn_charbuf_create();
    			res = ccn_signed_info_create(signed_info,
    					KP->public_key_digest,
    					KP->public_key_digest_len,
    					timestamp,
    					p.type,
    					p.freshness,
    					0,  /* FinalBlockID is optional */
    					keylocator);
    			fprintf(stderr, "result of ccn_signed_info_create == %d\n", res);

    			// Encode and send the contet object
    			res = ccn_encode_ContentObject(reply, name, signed_info, reply_data, reply_len, NULL, KP->private_key);
    			fprintf(stderr, "result of ccn_encodeContentObject == %d\n", res);
    			res = ccn_put(info->h, reply->buf, reply->length);
    			if (res >=0)
    				fprintf (stderr, "Returned Content: \n%s\n", reply_data);

    			// For good measure (and since ccnget command line doesn't do it?)
    			// see that our own content object verifies.  This is just for
    			// testing purposes.
    			//
    			struct ccn_parsed_ContentObject pco = {0};
    			res = ccn_parse_ContentObject(reply->buf, reply->length, &pco, NULL);
    			if (!res) {
    				res = ccn_verify_signature(reply->buf, pco.offset[CCN_PCO_E], &pco, KP->public_key );
    				fprintf(stderr, "Check - Constructed content object signature verify result == %d (%s)\n", res, (res==1)?"verified":"unverified");
    			} else {
    				fprintf(stderr, "Check - Constructed content object parse failure (res==%d)\n", res);
    			}

    			ccn_charbuf_destroy(&reply);
    			ccn_charbuf_destroy(&name);
    			free(reply_data);

    			if (res >= 0)
    				return (CCN_UPCALL_RESULT_INTEREST_CONSUMED);

    		} else {
    			fprintf(stderr,"Didn't match a stored serial number.\n");
    			// We leave this unanswered to avoid DOS.
    		}

    	} else {
    		fprintf(stderr, "Didn't match interest prefix and number of componets\n");
    	}
     return CCN_UPCALL_RESULT_OK;

    }
    return (CCN_UPCALL_RESULT_ERR);
}
