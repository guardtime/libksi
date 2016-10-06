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

## Proxy configuration ##

To use a proxy, you need to configure the proxy on your operating system according to the chosen network client.

* Curl

Set the system environment variable: http_proxy=user:pass@server:port  

In the Windows control panel:  

1) Find the 'System' page and select 'Advanced system settings'  
2) Select 'Environment Variables...'  
3) Select 'New...' to create a new system variable  
4) Enter http_proxy in the name field and and proxy configuration (see above) in the value field.  

In Linux add the system variable to /etc/bashrc:  
~~~
    export http_proxy=user:pass@server:port
~~~

* WinHTTP

Windows command line:
~~~
    netsh winhttp set proxy server:port
~~~

Configuring authentication is not supported by the netsh utility.

* WinINet

In the Windows control panel:

1) Find the 'Internet Options' page and select the 'Connections' tab.  
2) Select 'LAN settings' and enable proxy configuration by ticking the 'Use a proxy ..' checkbox  
3) Enter the address and port of your proxy server in the corresponding fields.  

Alternatively in the Windows registry, modify the 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings' key:

1) Set ProxyEnable to 1  
2) Set ProxyServer to server:port  

Configuring authentication is not supported by the Windows control panel and registry.

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
	KSI_PublicationsFile_fromFile(ksi, KSI_PUBLICATIONS_FILE, &pubFile);
	KSI_CTX_setPublicationsFile(ksi, pubFile);

	/* Calculate hash of document, sign the hash and verify the signature. */
	int res;
    KSI_DataHash *hsh = NULL;	/* Must be freed. */
	KSI_Signature *sig = NULL;	/* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, &hsh);
	KSI_createSignature(ksi, hsh, &sig);
	res = KSI_verifySignature(ksi, sig);

```
The API full reference is available here [http://guardtime.github.io/libksi/](http://guardtime.github.io/libksi/).

## License ##

See LICENSE file.

## Dependencies ##
| Dependency        | Version                           | License type | Source                         | Notes |
| :---              | :---                              | :---         | :---                           |:---   |
| OpenSSL           | Latest stable for target platform | BSD          | http://www.openssl.org/        | This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).  This product includes software written by Tim Hudson (tjh@cryptsoft.com). |
| libCurl           | Latest stable for target platform | MIT/X        | https://github.com/bagder/curl |       |
| Windows CryptoAPI |                                   |              |                                | Can be used as alternative to OpenSSL. Build time option. |
| Windows WinINet   |                                   |              |                                | Can be used as alternative to libCurl. Build time option. |
| Windows WinHTTP   |                                   |              |                                | Can be used as alternative to libCurl. Build time option. |
| CuTest            | 1.5                               | Zlib         |                                | Required only for testing. |
| Nginx             | n/a                               | MIT          |                                | Modified version of code based on src/http/ngx_http_parse.c from NGINX embedded in KSI code base. |

## Compatibility ##
| OS / Platform                              | Compatibility                                |
| :---                                       | :---                                         | 
| CentOS / RHEL 6 and 7, x86_64 architecture | Fully compatible and tested.                  |
| Debian, ...                                | Compatible but not tested on a regular basis. |
| OS X                                       | Compatible but not tested on a regular basis. |
| Windows 7, 8, 10                           | Compatible but not tested on a regular basis. Build combination of DLL=dll and RTL=MT(d) not supported. |
