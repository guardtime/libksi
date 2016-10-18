T0 - Basics
===========

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparation
---------------

The first thing by using the SDK, we need to create a KSI context variable
and initialize it. The context contains all the configurations and can be used
for debugging. The following example shows the initialization of a new #KSI_CTX
object.

~~~~~~~~~~{.c}

	#include <ksi/ksi.h>
	KSI_CTX *ksi = NULL; /* Must be feed at the end. */
	KSI_CTX_new(&ksi); /* Must be initialized only once per thread. */

~~~~~~~~~~

The next step would be to configure the context, as there are no default service
locations to send the signing request to. Let's assume the signing service address is
\c http://signservice.somehost:1234 and it is authenticated by \c user:key. We can configure
the signing service provider by calling #KSI_CTX_setAggregator.

~~~~~~~~~~{.c}

	KSI_CTX_setAggregator(ksi, "http://signingservice.somehost:1234", "user", "key");

~~~~~~~~~~

The verification process may on some cases access to the extender service. Let's assume the 
extending service address is \c http://extendservice.somehost:4321 and it is authenticated by
 \c user:key. We can configure the service provider by calling #KSI_CTX_setExtender.

~~~~~~~~~~{.c}

	KSI_CTX_setExtender(ksi, "http://signingservice.somehost:1234", "user", "key");

~~~~~~~~~~

To verify the responses from the service, we'll need to configure the publications
file location. Usually it is located as a binary file on a http server. Guardtime hosts
this file at http://verify.guardtime.com/ksi-publications.bin. The file is added using
#KSI_CTX_setPublicationUrl method.

~~~~~~~~~~{.c}

	KSI_CTX_setPublicationUrl(ksi, "http://publication.somehost/ksi-publications.bin");

~~~~~~~~~~

But how can we verify the the publications file? The publications file is signed with
PKI and the certificate must be issued by a known CA (by default the local truststore
is consulted for this). We need to add some constraints to the certificate to make sure
it is the correct one. To do so, we need to call KSI_CTX_setDefaultPubFileCertConstraints.
The constraints are an array of OID and expected value pairs.

~~~~~~~~~{.c}

	KSI_CertConstraint arr[] = {
	                { KSI_CERT_EMAIL, "publications@guardtime.com"},
	                { KSI_CERT_ORGANIZATION, "Guardtime" },
	                { NULL, NULL }
	};
	
	KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);

~~~~~~~~~

There are some OID keys predefined (#KSI_CERT_EMAIL, #KSI_CERT_ORGANIZATION, #KSI_CERT_COMMON_NAME, #KSI_CERT_COUNTRY) 
for convenience but is not limited to them. The following example is equivalent (but less readable) as
the previous one:

~~~~~~~~~~{.c}

	KSI_CertConstraint arr[] = {
	                { "1.2.840.113549.1.9.1", "publications@guardtime.com"},
	                { "2.5.4.10", "Guardtime" },
	                { NULL, NULL }
	};
	KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);

~~~~~~~~~~

The context is ready to be used.

2. Offline Publications File
----------------------------

If there is a need to load the publications file from the local file system, the file may be
loaded using #KSI_PublicationsFile_fromFile or #KSI_PublicationsFile_parse.
The second function is essentially the same as the parse function, but
takes a file name as an argument and parses the contents.

~~~~~~~~~~{.c}

	KSI_CTX *ksi = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	
	KSI_CTX_new(&ksi);	
	KSI_PublicationsFile_fromFile(ksi, KSI_PUBLICATIONS_FILE, &pubFile);
	KSI_CTX_setPublicationsFile(ksi, pubFile);
	
~~~~~~~~~~

The SDK performs verification on the publications file only if it is the one to load it from the
given publication URL. In this case the SDK assumes the user has verified the publication file (or
if not the caller has made a conscious decision.). To verify the publications file call #KSI_PublicationsFile_verify.

~~~~~~~~~~{.c}

	int res = KSI_PublicationsFile_verify(pubFile);
	if (res != KSI_OK) {
		fprintf(stderr, "Publications file not verified!\n");
	} else {
		printf("Publications file verified.\n");
	}
	
~~~~~~~~~~


2. Hashing
----------

Lets assume our data to be signed is stored in a variable called \c data and it's
length is stored in \c data_len.

As only the hash of the original document is signed, we need to create a #KSI_DataHash
object. This is usually done using the #KSI_DataHasher object where the data can be added to the
hash calculation in chunks. In our example, the data is already stored in a single
memory buffer and we can use the #KSI_DataHash_create function. We will use the 
#KSI_HASHALG_SHA2_256 algorithm.

~~~~~~~~~~{.c}

    KSI_DataHash *hsh = NULL; /* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, &hsh);

~~~~~~~~~~

3. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be created every time. It is
also important to point out that the context must be freed last.

~~~~~~~~~~{.c}

	KSI_DataHash_free(hsh);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
