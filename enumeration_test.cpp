#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <vector>
#include <list>
#include <string>
using namespace std;

extern "C" {
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/signing.h>
#include <ccn/keystore.h>
#include <ccn/hashtb.h>
#include <ccn/bloom.h>
}

// NDN Name discovery example
//
// using explicit excludes and active responses from
// content source.
//
// jburke@ucla.edu 14-May-2011
//

#include "key_utils.hpp"

// Helpers functions
// Sort with CCNx canonical ordering, http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
bool compare_with_length(const string &first, const string &second) {
	if (first.size()==second.size())
		return (first < second) ? true : false;
	return (first.size() < second.size()) ? true : false;
}

// Builds the interest template we'll use for discovery.
//
int create_interest_template(ccn_charbuf** templ, list<string>* exclude_list, bool force_new) {
	*templ = ccn_charbuf_create();
	ccn_charbuf_append_tt(*templ, CCN_DTAG_Interest, CCN_DTAG);
	ccn_charbuf_append_tt(*templ, CCN_DTAG_Name, CCN_DTAG);
	ccn_charbuf_append_closer(*templ); /* </Name> */
	//  Build exclusion list - This uses explicit exclusion rather than Bloom filters
	//  as there are fewer examples around for this; bloom examples can be found in ccnx distro.
	//  IMPORTANT:  Exclusion component list must be sorted following "Canonical CCNx ordering"
	//              http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
	// 				in which shortest components go first.
	if (exclude_list != NULL) {
		exclude_list->sort(compare_with_length);
		ccn_charbuf_append_tt(*templ, CCN_DTAG_Exclude, CCN_DTAG);
		for (list<string>::iterator it = exclude_list->begin();  it != exclude_list->end(); it++) {
			const char* name = (*it).c_str();
			ccnb_append_tagged_blob(*templ, CCN_DTAG_Component, name, strlen(name));		// Note that we need a data type within the component tag, so blob
		}
		ccn_charbuf_append_closer(*templ); /* </Exclude> */
	}
	if (force_new) {
		// We set AnswerOriginKind to 0 if we want the application to generate the data dynamically
		// rather than get it from the content store.
		ccn_charbuf_append_tt(*templ, CCN_DTAG_AnswerOriginKind, CCN_DTAG);
		ccn_charbuf_append_tt(*templ, 1, CCN_UDATA);
		ccn_charbuf_append(*templ, "0", 1);   // "do-not-answer-from-content-store" // seems to work but generates error -73 in content upcall
		ccn_charbuf_append_closer(*templ); /* </CCN_DTAG_AnswerOriginKind> */
	}
	ccn_charbuf_append_closer(*templ); /* </Interest> */
	return 0;
}

void dump_charbuf (struct ccn_charbuf* c, FILE* fp) {
	for (int i=0; i < c->length; i++) {
		if (c->buf[i]<0x20 || c->buf[i]>0x7E)
			fprintf(fp,"\\(%i)", c->buf[i]);
		else
			putc(c->buf[i], fp);
	}
}
#define FPRINTF_CHARBUF(A, B, C) fprintf(A, B); dump_charbuf(C, A); fprintf(A, "\n");


// We pass around an already assembled suffix for ease of use
// along with the pre-built content objects.
typedef struct {
	struct ccn_charbuf co;
	string suffix;
} child_contentObject;

// Our single packet handler for interest and data upcalls
enum ccn_upcall_res packet_handler(struct ccn_closure *selfp, enum ccn_upcall_kind, struct ccn_upcall_info *info);

// Application data structure passed to packet_handler in upcall
typedef struct {
	struct ccn** ccn_pub;
	struct ccn** ccn_rec;
	struct ccn_charbuf** root_prefix;
	struct ccn_indexbuf** root_prefix_comps;
	vector<child_contentObject>* device_content_objects;
	list<string>* discovered_children;		// Not generalizable if names are not strings
} handler_data;

// Our test content URI;
const char* TEST_URI = "ccnx:/root_of_enumeration_test/";

int main(int argc, char** argv) {
	int res = 0;
	struct ccn* ccn_pub;
	struct ccn* ccn_rec;

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

	 // Generate an ephemeral key for this demonstration
	 keypair* KP;
	 generate_keypair(1024, &KP);

	// DISCOVERY SUPPORT EXAMPLE - NAME PUBLISHER / CONTENT PRODUCERS
	//

	// Note we are only handling discovery for one prefix
	// Would need to be more clever to handle greater depths efficiently
	// Register the parent to enable enumeration
	struct ccn_charbuf* root_prefix = NULL;	// will hold our root
	root_prefix = ccn_charbuf_create();
	ccn_name_from_uri(root_prefix, TEST_URI);

	// Split our content_name into components
    struct ccn_indexbuf* root_prefix_comps = ccn_indexbuf_create();
    ccn_name_split(root_prefix, root_prefix_comps);
    fprintf(stderr, "Our root prefix has %d comps.\n", root_prefix_comps->n);

	// External registration of children is not necessary for enumeration
	// of this kind, so in the interest of simplicity for this example
	// we don't register them, just keep a list.  Make some samples.
	vector<string> device_serial_numbers;
	device_serial_numbers.push_back(string("cheese"));
	device_serial_numbers.push_back(string("word"));
	device_serial_numbers.push_back(string("60:33:4B:0E:74:94"));
	device_serial_numbers.push_back(string("61:33:4B:0E:74:94"));
	device_serial_numbers.push_back(string("44129DL92"));
	device_serial_numbers.push_back(string("serial-number"));

	// We prebuild content objects for each of these, which allows us to
	// use content_matches_interest for exclusion filter mapping
	// Note that the content itself is static and boring, so if it
	// were dynamic, we'd need to make sure it was regularly updated.
	vector<child_contentObject> device_content_objects;

	// We'll need  a KeyLocator for our ContentObjects
	struct ccn_charbuf *timestamp = NULL;
	struct ccn_charbuf *keylocator = NULL;
	struct ccn_signing_params p = CCN_SIGNING_PARAMS_INIT;
	build_keylocator_from_key(&keylocator, KP->public_key);
	// Build the signed info
	struct ccn_charbuf *signed_info = ccn_charbuf_create();
	res = ccn_signed_info_create(signed_info,
			KP->public_key_digest, KP->public_key_digest_len,
			timestamp, p.type, p.freshness, 0, keylocator);
	if (res<0)
		fprintf(stderr, "Error in ccn_signed_info_create == %d\n", res);

	// Put some reply data in our Content Objects for these children
	const char* reply_data = "ACK";
	size_t reply_len = strlen(reply_data);

	// Pre-build the ContentObjects
	for (vector<string>::iterator it = device_serial_numbers.begin();  it != device_serial_numbers.end(); it++) {
		struct ccn_charbuf* reply_name = ccn_charbuf_create();
		ccn_charbuf_append_charbuf(reply_name, root_prefix);
		ccn_name_append_str(reply_name, (*it).c_str());
		struct ccn_charbuf* reply = ccn_charbuf_create();
		if ((res = ccn_encode_ContentObject(reply, reply_name, signed_info, reply_data, reply_len, NULL, KP->private_key)) < 0)
			fprintf(stderr, "Failed to create content object: res==%d\n", res);
		else
			fprintf(stderr, "Cached content object for %s\n",(*it).c_str() );
		child_contentObject co = { *reply, *it };
		device_content_objects.push_back(co);
		ccn_charbuf_destroy(&reply_name);
	    }

	// DISCOVERY EXAMPLE - NAME SEEKER - FIND THE CHILDREN
	//

	// We will store the children here... strings only, no ccnb encoding (not generalized)
	//
	list<string> discovered_children;		// Not generalizable if names are not strings

    // Closure to handle upcalls
    struct ccn_closure *cl = NULL;
    cl = (struct ccn_closure*) calloc(1, sizeof(struct ccn_closure));
    cl->p = &packet_handler;
    handler_data h_data = { &ccn_pub, &ccn_rec, &root_prefix, &root_prefix_comps, &device_content_objects, &discovered_children};
    cl->data = &h_data;

    // This is the prefix for which we want to discover the children
	res = ccn_set_interest_filter(ccn_pub, root_prefix, cl);

	int n=0;
	struct ccn_charbuf* name;
	struct ccn_charbuf* templ;

	// Discover for 5 seconds
	//
	time_t t0;
	t0 = time(NULL);
    while(time(NULL) - t0 < 5) {
    	name = ccn_charbuf_create();
    	templ = ccn_charbuf_create();
    	ccn_name_from_uri(name, TEST_URI);
    	fprintf(stderr, "main() Express interest %d:", ++n);
		FPRINTF_CHARBUF(stderr, " ", name);

		// Build the interest template with discovered_children as exclusion,
		// and flag AnswerOriginKind to require app to answer rather than content store.
		create_interest_template(&templ, &discovered_children, true);
		if ((res = ccn_express_interest(ccn_rec, name, cl, templ)) <  0)		// May be greater than zero?
			fprintf(stderr, "Error from ccn_express_interest (res==%d)\n", res);
        fflush(stdout);
		ccn_run(ccn_rec, 100); /* stop if we run dry for .1 sec */
        ccn_run(ccn_pub, 100); /* stop if we run dry for .1 sec */
        ccn_charbuf_destroy(&name);
        ccn_charbuf_destroy(&templ);
    }
    fprintf(stdout, "\n%s\n", TEST_URI);
	for (list<string>::iterator it = discovered_children.begin();  it != discovered_children.end(); it++) {
		fprintf(stdout, "\t%s\n", (*it).c_str());
	}
    // Probably missing some cleanup
    ccn_charbuf_destroy(&root_prefix);
    ccn_destroy(&ccn_pub);
    ccn_destroy(&ccn_rec);
    fflush(stderr);
	return(0);
}



// packet_handler() for both discovery interests to find names
// and content objects returned back.  this is for demo purposes.
//
enum ccn_upcall_res
packet_handler(struct ccn_closure *selfp,
                 enum ccn_upcall_kind upcall_kind,
                 struct ccn_upcall_info *info)
{
	handler_data* h_data = (handler_data*) selfp->data; // Client data returned
	ccn_set_run_timeout(info->h, 0); // Return to client faster
    struct ccn_charbuf* interest_name;
	struct ccn_charbuf* content_name;
	struct ccn_indexbuf* name_comps;
    const unsigned char* content = NULL;
    size_t content_bytes = 0;
    int res;
    char* child;
    unsigned char *suffix_comp;

    switch(upcall_kind) {

	// NAME SEEKER UPCALL - HANDLES ContentObjects RETURNING TO DISCOVERY MECHANISM
	//
	// By being received in UPCALL_CONTENT, we know that signature was verified
    //
    case CCN_UPCALL_CONTENT:
    	// Received name in contentobject
    	content_name = ccn_charbuf_create();
    	ccn_charbuf_append(content_name,
    			&info->content_ccnb[info->pco->offset[CCN_PCO_B_Name]],
    			info->pco->offset[CCN_PCO_E_Name]-info->pco->offset[CCN_PCO_B_Name]);
    	FPRINTF_CHARBUF(stderr, "CCN_UPCALL_CONTENT: ", content_name);

    	// Content  (do we need to free() this?)
        ccn_ref_tagged_BLOB(CCN_DTAG_Content, info->content_ccnb,
							  info->pco->offset[CCN_PCO_B_Content],
							  info->pco->offset[CCN_PCO_E_Content],
							  &content, &content_bytes);

    	// Split our content_name into components
    	name_comps = ccn_indexbuf_create();
    	ccn_name_split(content_name, name_comps);

    	// Verify root prefix
        // In our case, if it matches the root, it is a discovery request
    	//
        res = ccn_compare_names((*(h_data->root_prefix))->buf, (*(h_data->root_prefix))->length,
    			&info->content_ccnb[info->pco->offset[CCN_PCO_B_Name]],
    			info->pco->offset[CCN_PCO_E_Name]-info->pco->offset[CCN_PCO_B_Name]
    			  -  (name_comps->buf[name_comps->n-1] - name_comps->buf[name_comps->n - 2]) - 1);  // remove last component
    	if (res != 0) {
    		fprintf(stderr, "- Didn't match parent prefix, ignoring.\n");
        	ccn_charbuf_destroy(&content_name);
    		return CCN_UPCALL_RESULT_OK;
    	}

    	// Verify number of suffix component
    	// For now, we only support one suffix after our request
    	//
    	if ((*(h_data->root_prefix_comps))->n - name_comps->n != -1) {
    		fprintf(stderr, "- More than one suffix component - not supported.\n");
        	ccn_charbuf_destroy(&content_name);
    		return CCN_UPCALL_RESULT_OK;
    	}

    	// Quick parse of the ccnb formatted child name (the suffix); it would be great if there
    	// were functions to do this that didn't require instantiating a decoder
    	// object.
    	// Assumes a zero terminated string (not a more generic byte array!)
    	// for name components and reads last component before digest.
    	// http://www.ccnx.org/releases/latest/doc/technical/BinaryEncoding.html
    	suffix_comp = content_name->buf + name_comps->buf[name_comps->n - 2];
    	++suffix_comp; // Move past the component boundary
    	for (; *suffix_comp < 128; suffix_comp++)  // Read until the terminating byte, which has the high order bit set
    		;
    	++suffix_comp; // move past it
    	child = (char*)  suffix_comp;
    	fprintf(stderr, "- Parsed child [%s] ", child);

    	if (find(h_data->discovered_children->begin(), h_data->discovered_children->end(), string(child)) ==  h_data->discovered_children->end()) {
        	fprintf(stderr, "and added to discovered_children. ");
    		h_data->discovered_children->push_back(string(child));
    	} else {
    		fprintf(stderr, "- already discovered this, skipping. ");
    	}
    	fprintf(stderr, "Content [%s]\n", content);
    	ccn_charbuf_destroy(&content_name);
        ccn_indexbuf_destroy(&name_comps);
        return (CCN_UPCALL_RESULT_OK);

    // NAME PUBLISHER UPCALL - DISCOVERY PROVIDER - PREFIX REGISTRANT SIDE, ANSWER INTERESTS EXPRESSED FOR root_prefix
    //
    case CCN_UPCALL_INTEREST:
    	interest_name = ccn_charbuf_create();
        ccn_name_init(interest_name);
        res = ccn_name_append_components(interest_name, info->interest_ccnb,
    			info->interest_comps->buf[0], info->interest_comps->buf[info->interest_comps->n - 1]);
        FPRINTF_CHARBUF(stderr, "CCN_UPCALL_INTEREST: ", interest_name);

        // In our case, if it matches the root, it is a discovery request
    	//
        res = ccn_compare_names((*(h_data->root_prefix))->buf, (*(h_data->root_prefix))->length,
    			&info->interest_ccnb[info->interest_comps->buf[0]],
    			info->interest_comps->buf[info->interest_comps->n] - info->interest_comps->buf[0]);
    	if (res != 0) {
    		fprintf(stderr, "- Didn't match interest for parent prefix\n");
        	ccn_charbuf_destroy(&interest_name);
    		return CCN_UPCALL_RESULT_OK;
    	}

    	// Iterate through our possible pre-built ContentObjects and answer with the first
    	// one that is not excluded.  This could be done with a hashtable of names, but it
    	// is remarkably painful to manually parse the exclude filter, so we call use
    	// ccn_content_matches_interest on our previously built ContentObjects, which
    	// hopefully is efficient.
    	//
    	for (vector<child_contentObject>::iterator it = h_data->device_content_objects->begin();  it != h_data->device_content_objects->end(); it++) {
    		//fprintf(stderr, "Checking child: %s\n", ((*it).suffix.c_str()));
    		int res = ccn_content_matches_interest( (*it).co.buf, (*it).co.length, false, NULL /* could cache PCO for speed */,
    				info->interest_ccnb, info->pi->offset[CCN_PI_E] /* ? */, info->pi);
    		if (res==1) {
            	if ((res = ccn_put(info->h, (*it).co.buf, (*it).co.length)) < 0)
            		fprintf(stderr, "- Error trying to ccn_put the content object: res==%d\n", res);
            	else
            		fprintf(stderr, "- Responded with content object for child: %s\n", ((*it).suffix.c_str()));
            	break;
    		} else {
    			// No match, which means everything has been excluded or some other flag
    			// prevents the match
    			// fprintf(stderr, "ccn_content_matches_interest returned res==%d\n", res);
    		}
    	}
    	ccn_charbuf_destroy(&interest_name);
    	return (CCN_UPCALL_RESULT_INTEREST_CONSUMED);

    case CCN_UPCALL_FINAL:
    	// A regular occurrence, let it go
    	//fprintf(stderr, "CCN_UPCALL_FINAL \n");
        return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_INTEREST_TIMED_OUT:
    	// We let these go by silently, and count them in the main loop
    	// fprintf(stderr, "CCN_UPCALL_INTEREST_TIMED_OUT ");
        return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_CONTENT_UNVERIFIED:
    	fprintf(stderr, "CCN_UPCALL_CONTENT_UNVERIFIED \n");
        return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_CONTENT_BAD:
    	fprintf(stderr, "CCN_UPCALL_CONTENT_BAD \n");
        return (CCN_UPCALL_RESULT_OK);
    case CCN_UPCALL_CONSUMED_INTEREST:
    	fprintf(stderr, "CCN_UPCALL_CONSUMED_INTEREST \n");
        return (CCN_UPCALL_RESULT_OK);
    }
    return (CCN_UPCALL_RESULT_ERR);
}
