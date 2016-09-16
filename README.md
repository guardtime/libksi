# libksi #
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically 
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global 
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term 
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical 
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, 
see [https://guardtime.com](https://guardtime.com).

The libksi is a software development kit for developers who want to integrate KSI with their C/C++ based applications 
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending 
and verifying the signatures.

## Installation ##

To build the libksi, you need to have the following SW components installed:
1. A network provider
2. A cryptography provider

The following network providers are supported, choose one:
* Libcurl (recommended)
* Windows native WinINet
* Windows native WinHTTP

The following cryptography providers are supported, choose one:
* OpenSSL (recommended)
* Windows native CryptoAPI

For building under Windows you need the Windows SDK.

To use libksi in your C/C++ project, link it against the libksi binary and your chosen network and cryptography providers. 

If you do not want to build your own binaries, you can get the latest stable release from the Gaurdtime repository.
To set up the repository, save this repo file in your repositories directory (e.g. /etc/yum.repos.d/): 
[http://download.guardtime.com/ksi/configuration/guardtime.el6.repo](http://download.guardtime.com/ksi/configuration/guardtime.el6.repo)

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple example how to sign a document and verify the signature:
```C

	#include <ksi/ksi.h>
	/* Set up KSI context and aggregator for signing. */
	KSI_CTX *ksi = NULL;		/* Must be freed at the end. */
	KSI_CTX_new(&ksi);			/* Must be initialized only once per thread. */
	KSI_CTX_setAggregator(ksi, "http://signingservice.somehost:1234", "user", "key");

	/* Set up extender and publications file for verification. */
	KSI_PublicationsFile *pubFile = NULL;	/* Must be freed. */
	KSI_CTX_setExtender(ksi, "http://signingservice.somehost:1234", "user", "key");
	KSI_PublicationsFile_fromFile(ksi, "~/ksi-publications.bin", &pubFile);
	KSI_CTX_setPublicationsFile(ksi, pubFile);

	/* Calculate hash of document, sign the hash and verify the signature. */
	int res;
    KSI_DataHash *hsh = NULL;	/* Must be freed. */
	KSI_Signature *sig = NULL;	/* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, &hsh);
	KSI_createSignature(ksi, hsh, &sig);
	res = KSI_verifySignature(ksi, sig);

```
The API full reference is available here [http://guardtime.github.io/libksi/3.9](http://guardtime.github.io/libksi/3.9).

## License ##

See LICENSE file.
