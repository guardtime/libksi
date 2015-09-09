T4 - Publications File Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

Online Usage
------------
By default the SDK is configured to use the Guardtime provided public publications
file (located at http://verify.guardtime.com/ksi-publications.bin). This should be
enough for most of the cases.

If the Guardtime provided publications file mentioned in the previous paragraph is
not available (e.g firewall or company policy), you may set a different URL to the
publications file using #KSI_CTX_setPublicationUrl. If this referenced publications
file is not a Guardtime issued publications file, you may have to alter the verification
criteria (see Custom Publication File below).

~~~~~~~~~~{.c}
	KSI_CTX *ksi = NULL;
	
	KSI_CTX_new(&ksi);	
	KSI_CTX_setPublicationUrl(ksi, "http://someotherhost/ksi-publications.bin");
~~~~~~~~~~

Offline Usage
-------------
If there is a need to load the publications file from the local file system, the file may be
loaded using #KSI_CTX_setPublicationsFile. To create a publications file you may use #KSI_PublicationsFile_parse
or #KSI_PublicationsFile_fromFile. The second function is essentially the same as the parse function, but
takes a file name as an argument and parses the contents.

~~~~~~~~~~{.c}
	KSI_CTX *ksi = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	
	KSI_CTX_new(&ksi);	
	KSI_PublicationsFile_fromFile(ksi, "~/ksi-publications.bin", &pubFile);
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

Custom Publications File
------------------------
If you need to use a custom publications file, which is not issued by Guardtime you'll probably
need to change the criteria for verifying the certificate on the PKI signature of the publications file.
The easiest way to do so is by using #KSI_CTX_setDefaultPubFileCertConstraints. This function takes
the KSI context and an array of OID and expected value pairs as its arguments. The array of pairs must
be terminated by two NULL pointers. The array is copied internally witch means the array may be freed
after a successful call to this function.

~~~~~~~~~~{.c}
KSI_CertConstraint arr[] = {
                { KSI_CERT_EMAIL, "publications@guardtime.com"},
                { KSI_CERT_ORGANIZATION, "Guardtime" },
                { NULL, NULL }
};
KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
~~~~~~~~~~

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
