# libksi #

Guardtime KSI Blockchain is an industrial scale blockchain platform that cryptographically
ensures data integrity and proves time of existence. Its signatures, based on hash chains, link data to global
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more,
see [https://guardtime.com](https://guardtime.com).

The `libksi` is a software development kit for developers who want to integrate KSI with their C/C++ based applications
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending
and verifying the signatures.

## Installation ##

### Latest Release from Guardtime Repository

In order to install the `libksi` packages directly from the Guardtime public repository, download and save the repository configuration and use appropriate system package manager. 


```
### On RHEL/CentOS ###

cd /etc/yum.repos.d

# In case of RHEL/CentOS 6
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el6.repo

# In case of RHEL/CentOS 7
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el7.repo

sudo yum install libksi


### On Debian/Ubuntu ###

# Add Guardtime pgp key.
sudo curl http://download.guardtime.com/ksi/GUARDTIME-GPG-KEY | sudo apt-key add -

# In case of Ubuntu 16 (Xenial)
sudo curl -o /etc/apt/sources.list.d/guardtime.list http://download.guardtime.com/ksi/configuration/guardtime.xenial.list

# In case of Debian 9 (Stretch)
sudo curl -o /etc/apt/sources.list.d/guardtime.list http://download.guardtime.com/ksi/configuration/guardtime.stretch.list

sudo apt update
apt-get install libksi
```

For OS X, see [https://github.com/guardtime/homebrew-ksi](https://github.com/guardtime/homebrew-ksi)

### From Source Code

To build the `libksi`, you need to have the following SW components installed:
1. A network provider
2. A cryptography provider

The following network providers are supported, choose one:
* `libcurl` (recommended)
* Windows native WinINet
* Windows native WinHTTP

The following cryptography providers are supported, choose one:
* OpenSSL (recommended)
* Windows native CryptoAPI

For building under Windows you need the Windows SDK.

To use `libksi` in your C/C++ project, link it against the `libksi` binary and your chosen network and cryptography providers.


## Known Limitations ##

* Curl

The `libcurl` latest version `7.29.0-42` used in CentOS/RHEL 7 is not signal-proof. If your application is using signals
in combination with `libksi` basic network service interface, network requests can fail. In this case `libksi` request
call will return `KSI_NETWORK_ERROR`.

* WinINet

WinINet maximum connections per server is limited to a value of 128. In case the asynchronous interface is used, it is
advised to set maximum parallel running request count (see `KSI_ASYNC_OPT_REQUEST_CACHE_SIZE`) to a value not greater
than 128. Otherwise, the requests could be timed out.

* Windows

Build combination of `DLL=dll` and `RTL=MT(d)` is not supported.

## Proxy Configuration ##

To use a proxy, you need to configure the proxy on your operating system according to the chosen network client.

* Curl

Set the system environment variable: `http_proxy=user:pass@server:port`

In the Windows control panel:

1) Find the 'System' page and select 'Advanced system settings'
2) Select 'Environment Variables...'
3) Select 'New...' to create a new system variable
4) Enter `http_proxy` in the name field and and proxy configuration (see above) in the value field.

In Linux add the system variable to `/etc/bashrc`:
~~~
	export http_proxy=user:pass@server:port
~~~

* WinHTTP

Windows command line:
~~~
	netsh winhttp set proxy server:port
~~~

Configuring authentication is not supported by the `netsh` utility.

* WinINet

In the Windows control panel:

1) Find the 'Internet Options' page and select the 'Connections' tab.
2) Select 'LAN settings' and enable proxy configuration by ticking the 'Use a proxy ..' checkbox
3) Enter the address and port of your proxy server in the corresponding fields.

Alternatively in the Windows registry, modify the 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings' key:

1) Set ProxyEnable to 1
2) Set ProxyServer to `server:port`

Configuring authentication is not supported by the Windows control panel and registry.

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple example how to sign a document and verify the signature:
```C


	#include <ksi/ksi.h>

	/* Return values of libksi function calls. */
	int res;

	/* Set up KSI context and aggregator for signing. */
	KSI_CTX *ksi = NULL;            /* Must be freed at the end. */
	KSI_CTX_new(&ksi);              /* Must be initialized only once per thread. */
	KSI_CTX_setAggregator(ksi, "http://signingservice.somehost:1234", "user", "key");

	/* Set up the extender. */
	KSI_CTX_setExtender(ksi, "http://signingservice.somehost:1234", "user", "key");

	/* Publications file object (only needed, when using a local file.) */
	KSI_PublicationsFile *pubFile = NULL;   /* Must be freed. */
            
	/* Read the publications file from a file. */
	KSI_PublicationsFile_fromFile(ksi, KSI_PUBLICATIONS_FILE, &pubFile);

	/* Publications file signing cert verification constraints. */
	KSI_CertConstraint certConstr[] = {
		{ KSI_CERT_EMAIL, "publications@guardtime.com"},
		{ NULL, NULL}
	};

	/* Set the verification criteria. */
	KSI_PublicationsFile_setCertConstraints(pubFile, certConstr);

	/* Verify the publications file. */
	res = KSI_PublicationsFile_verify(pubFile, ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify publications file. Exiting.\n");
		exit(1);
	}
	/* Set the publications file. */
	KSI_CTX_setPublicationsFile(ksi, pubFile);

	/* Calculate hash of document, sign the hash and verify the signature. */
	KSI_DataHash *hsh = NULL;       /* Must be freed. */
	KSI_Signature *sig = NULL;      /* Must be freed. */
	char *data = "Hello KSI!";
	size_t data_len = strlen(data);
	KSI_DataHash_create(ksi, data, data_len, KSI_HASHALG_SHA2_256, &hsh);
	KSI_createSignature(ksi, hsh, &sig);

	res = KSI_verifyDataHash(ksi, sig, hsh);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify the signature.\n");
	} else {
		printf("Verified!");
	}

```
The API full reference is available here [http://guardtime.github.io/libksi/](http://guardtime.github.io/libksi/).

## Contributing ##

See `CONTRIBUTING.md` file.

## License ##

See `license.txt` file.

## Dependencies ##

| Dependency        | Version                           | License type | Source                         | Notes |
| :---              | :---                              | :---         | :---                           |:---   |
| OpenSSL           | Latest stable for target platform | BSD          | https://www.openssl.org/       | This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).  This product includes software written by Tim Hudson (tjh@cryptsoft.com). |
| libcurl           | Latest stable for target platform | MIT/X        | https://github.com/bagder/curl |       |
| Windows CryptoAPI |                                   |              |                                | Can be used as alternative to OpenSSL. Build time option. |
| Windows WinINet   |                                   |              |                                | Can be used as alternative to libcurl. Build time option. |
| Windows WinHTTP   |                                   |              |                                | Can be used as alternative to libcurl. Build time option. |
| CuTest            | 1.5                               | Zlib         |                                | Required only for testing. |
| Nginx             | n/a                               | MIT          |                                | Modified version of code based on src/http/ngx_http_parse.c from NGINX embedded in KSI code base. |

## Compatibility ##

| OS / Platform                              | Compatibility                                |
| :---                                       | :---                                         |
| CentOS/RHEL 6 and 7, x86_64 architecture | Fully compatible and tested.                  |
| Debian, ...                                | Compatible but not tested on a regular basis. |
| OS X                                       | Compatible but not tested on a regular basis. |
| Windows 7, 8, 10                           | Compatible but not tested on a regular basis. |
