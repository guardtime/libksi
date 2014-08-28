#include "internal.h"

#if KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_CRYPTOAPI

#include <string.h>
#include <limits.h>

#include <windows.h>
#include <Wincrypt.h>

/* Hide the following line to deactivate. */
#define MAGIC_EMAIL "publications@guardtime.com"

void printError(DWORD dw) 
{ 
    // Retrieve the system error message for the last-error code
    LPVOID lpMsgBuf;
    
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

	fprintf(stderr, "MS Error:(%X) %s",  HRESULT_FROM_WIN32(dw), lpMsgBuf);

    LocalFree(lpMsgBuf);
    return; 
}

static int KSI_PKITruststore_global_initCount = 0;

struct KSI_PKITruststore_st {
	KSI_CTX *ctx;
	HCERTSTORE store;
};

struct KSI_PKICertificate_st {
	KSI_CTX *ctx;
	PCCERT_CONTEXT x509;
};

struct KSI_PKISignature_st {
	KSI_CTX *ctx;
	CRYPT_INTEGER_BLOB pkcs7;
};

static int cryptopapiGlobal_init(void) {
	if (KSI_PKITruststore_global_initCount++ > 0) {
		/* Nothing to do */
	} else {
		;//OpenSSL_add_all_digests();
	}

	return KSI_OK;
}

static void cryptopapiGlobal_cleanup(void) {
	if (--KSI_PKITruststore_global_initCount > 0) {
		/* Nothing to do */
	} else {
		;//EVP_cleanup();
	}
}

static int KSI_MD2hashAlg(ALG_ID hash_alg) {
	if (hash_alg == CALG_SHA_256)
		return KSI_HASHALG_SHA2_256;
	else if (hash_alg == CALG_SHA1)
		return KSI_HASHALG_SHA1;
	else if (hash_alg == CALG_SHA_384)
		return KSI_HASHALG_SHA2_384;
	else if (hash_alg == CALG_SHA_512)
		return KSI_HASHALG_SHA2_512;
	else
		return -1;
}


/*TODO: Check CertClose error handling*/
void KSI_PKITruststore_free(KSI_PKITruststore *trust) {
	if (trust != NULL) {
		if (trust->store != NULL){
			if(!CertCloseStore(trust->store, CERT_CLOSE_STORE_CHECK_FLAG)){
				printError(GetLastError());
				fprintf(stderr, "CryptoAPI: Unable to free PKI Truststore.\nFor Developer: Some Certificates may be still in use / not released. Consider using 'CERT_CLOSE_STORE_FORCE_FLAG'\n");
				}
		}
		KSI_free(trust);
	}
}

int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;

	KSI_PKICertificate *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);
	
	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKICertificate_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*cert = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

	
cleanup:

	KSI_nofree(raw);

	KSI_PKICertificate_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_toTlv(KSI_PKICertificate *cert, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(cert->ctx, &err);

	res = KSI_TLV_new(cert->ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKICertificate_serialize(cert, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}
/*TODO implement*/
int KSI_PKITruststore_addLookupDir(KSI_PKITruststore *trust, const char *path) {
	return KSI_OK;
}
/*TODO implement*/
int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path) {
	/*KSI_ERR err;
	HCERTSTORE tmp_FileTrustStore;
	
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, path != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);
	*/
	/*Open new store */
	/*tmp_FileTrustStore = CertOpenStore(CERT_STORE_PROV_FILENAME_A, 0, NULL, 0, path);
	if (tmp_FileTrustStore == NULL) {
		DWORD error = GetLastError();
		printf("New Cert Store open error %i", error);
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}*/

	/*Not updates with priority 0*/
	/*if (!CertAddStoreToCollection(trust->store, tmp_FileTrustStore, 0, 0)) {
		DWORD error = GetLastError();
		printf("New Cert Store appending error %i", error);
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}*/

	//tmp_FileTrustStore = NULL;
	
	//KSI_SUCCESS(&err);

//cleanup:

//	if(tmp_FileTrustStore) CertCloseStore(tmp_FileTrustStore, CERT_CLOSE_STORE_CHECK_FLAG);
//	return KSI_RETURN(&err);
	return KSI_OK;
}
/*+ TODO: At CertOpenSystemStore change "ROOT" to CA*/
int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **trust) {
	KSI_ERR err;
	KSI_PKITruststore *tmp = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_CTX_registerGlobals(ctx, cryptopapiGlobal_init, cryptopapiGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	tmp = KSI_new(KSI_PKITruststore);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->store = NULL;

	/*Open cert store as system store*/
	tmp->store = CertOpenSystemStore ((HCRYPTPROV_LEGACY)NULL, "ROOT");
	if (tmp->store == NULL) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to open PKI certificate store");
		goto cleanup;
	}

	*trust = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);
	
cleanup:

	KSI_PKITruststore_free(tmp);

	return KSI_RETURN(&err);
}

void KSI_PKICertificate_free(KSI_PKICertificate *cert) {
	if (cert != NULL) {
		if (cert->x509 != NULL) CertFreeCertificateContext(cert->x509);
		KSI_free(cert);
	}
}

void KSI_PKISignature_free(KSI_PKISignature *sig) {
	if (sig != NULL) {
		if (sig->pkcs7.pbData != NULL) KSI_free(sig->pkcs7.pbData);
		KSI_free(sig);
	}
}

int KSI_PKISignature_serialize(KSI_PKISignature *sig, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	unsigned char *tmp = NULL;
		
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	tmp = KSI_malloc(sig->pkcs7.cbData);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	
	memcpy(tmp, sig->pkcs7.pbData, sig->pkcs7.cbData);

	*raw = tmp;
	*raw_len = (unsigned)sig->pkcs7.cbData;

	tmp = NULL;

	KSI_SUCCESS(&err);
	
cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;

	KSI_PKISignature *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "CryptoAPI: PKI Signature from TLV");
	
	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);
	
	KSI_LOG_debug(ctx, "CryptoAPI: PKI Signature from TLV. Done");
	
cleanup:

	KSI_nofree(raw);

	KSI_PKISignature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_toTlv(KSI_PKISignature *sig, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	KSI_LOG_debug(sig->ctx, "CryptoAPI: PKI Signature to TLV");
	
	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_serialize(sig, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

	KSI_LOG_debug(sig->ctx, "CryptoAPI: PKI Signature to TLV. Done");
	
cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, unsigned raw_len, KSI_PKISignature **signature) {
	KSI_ERR err;
	KSI_PKISignature *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "CryptoAPI: PKI Signature new");
	
	tmp = KSI_new(KSI_PKISignature);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->pkcs7.pbData = NULL;
	tmp->pkcs7.cbData = 0;

	if (raw_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Length is greater than INT_MAX");
		goto cleanup;
	}

	tmp->pkcs7.pbData = KSI_malloc(raw_len);
	tmp->pkcs7.cbData = raw_len;
	
	memcpy(tmp->pkcs7.pbData, raw, raw_len);

	*signature = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

	KSI_LOG_debug(ctx, "CryptoAPI: PKI Signature new. Done");
	
cleanup:

	KSI_PKISignature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, size_t der_len, KSI_PKICertificate **cert) {
	KSI_ERR err;
	PCERT_CONTEXT x509;
	KSI_PKICertificate *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, der != NULL) goto cleanup;
	KSI_PRE(&err, der_len > 0) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (der_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Length is more than MAX_INT");
		goto cleanup;
	}
	
	/*TODO check pCreatePara (last argument)*/
	x509 = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, (const BYTE*)der, der_len);
	if (x509 == NULL) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to create PKI certificate");
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKICertificate);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->x509 = x509;
	x509 = NULL;

	*cert = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

	
cleanup:

	if (x509 != NULL) CertFreeCertificateContext(x509);
	KSI_PKICertificate_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	unsigned char *tmp_serialized = NULL;
	DWORD len = 0;

	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(cert->ctx, &err);

	if (!CertSerializeCertificateStoreElement(cert->x509, 0, NULL, &len)) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get serialized PKI certificate data length");
		goto cleanup;
	}

	tmp_serialized = KSI_malloc(len);
	if (tmp_serialized == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if(!CertSerializeCertificateStoreElement(cert->x509, 0, (BYTE*)tmp_serialized, &len)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to serialize PKI certificate");
		goto cleanup;
	}

	*raw = tmp_serialized;
	*raw_len = (unsigned)len;

	tmp_serialized = NULL;
	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp_serialized);

	return KSI_RETURN(&err);
}

static void printCertInfo(PCCERT_CONTEXT cert){
	char strMail[256];
	char strData[256];
	char strIssuerName[256];
	
	if(cert == NULL){
		printf("Certificate is nullptr\n");
		return;
	}
	
	CertGetNameString(cert, CERT_NAME_EMAIL_TYPE, 0, NULL, strMail, sizeof(strMail));
	CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, strData, sizeof(strData));
	CertGetNameString(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE , CERT_NAME_ISSUER_FLAG, 0,strIssuerName, sizeof(strIssuerName));
	printf("Cert: '%s' Mail '%s' Issuer '%s'\n", strData,strMail, strIssuerName);
	
	return;
	}

static void printCertsInStore(HCERTSTORE certStore){
	PCCERT_CONTEXT certFound = NULL;
	DWORD i =0;
	
	do{
		certFound = CertEnumCertificatesInStore(certStore,certFound);
		
		
		if(certFound != NULL){
			printf("  >>%2i)",i++);
			printCertInfo(certFound);
			
		}
		else{
			printf("  >>No more certs to print.\n");
		}
	
	}
	while(certFound != NULL);
	
	}

/*cert obj must be freed*/
static int extractCertificate(const KSI_PKISignature *signature, PCCERT_CONTEXT *cert) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	HCERTSTORE certStore;
	PCCERT_CONTEXT signing_cert = NULL;
	DWORD certCount=0;
	
	
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	ctx = signature->ctx;
	KSI_BEGIN(ctx, &err);
	
	/*Get Signature certificates as a certificate store*/
	certStore = CryptGetMessageCertificates(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, (HCRYPTPROV_LEGACY)NULL, 0, signature->pkcs7.pbData, signature->pkcs7.cbData);
	if(certStore == NULL){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable extract PKI signatures certificate");
		goto cleanup;
	 }
	
	/*Counting certificates*/
	/*TODO: Is there really no better way ???*/
	do{
		signing_cert = CertEnumCertificatesInStore(certStore,signing_cert);
		if(signing_cert != NULL){
			certCount++;
		}
	}
	while(signing_cert != NULL);
	
	if(certCount !=1){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "PKI signature cert count is not 1");
		goto cleanup;
	}
	
	/*If there was 1 certificate, extract that*/
	signing_cert = CertEnumCertificatesInStore(certStore,NULL);
	
	/*The copy of the object is NOT created. Just its reference value is incremented*/
	signing_cert = CertDuplicateCertificateContext(signing_cert);
	
	*cert = signing_cert;
	signing_cert = NULL;
	
	
	res = KSI_OK;
	
cleanup:

	if(signing_cert) CertFreeCertificateContext(signing_cert);
	if(certStore) CertCloseStore(certStore, CERT_CLOSE_STORE_CHECK_FLAG);

	return res;
}

static int KSI_PKITruststore_verifySignatureCertificate(const KSI_PKITruststore *pki, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	PCCERT_CONTEXT subjectCert = NULL;
	char tmp[256];
	CERT_ENHKEY_USAGE enhkeyUsage;
	CERT_USAGE_MATCH certUsage;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	CERT_CHAIN_POLICY_PARA policyPara;
	CERT_CHAIN_POLICY_STATUS policyStatus;

	
	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	ctx = pki->ctx;
	KSI_BEGIN(ctx, &err);

	
	res = extractCertificate(signature, &subjectCert);
	KSI_CATCH(&err, res) goto cleanup;

#ifdef MAGIC_EMAIL
	if(CertGetNameString(subjectCert, CERT_NAME_EMAIL_TYPE, 0, NULL, tmp, sizeof(tmp))==1){
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get subjects name from PKI certificate");
		goto cleanup;
	}
	
	KSI_LOG_debug(ctx, "CryptoAPI: Subjects E-mail: %s", tmp);

	if (strcmp(tmp, MAGIC_EMAIL) != 0) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Wrong subject name");
		goto cleanup;
	}
#endif

	/* Get the certificate chain of our certificate. */
	enhkeyUsage.cUsageIdentifier = 0;
	enhkeyUsage.rgpszUsageIdentifier = NULL;
	certUsage.dwType = USAGE_MATCH_TYPE_AND;
	certUsage.Usage = enhkeyUsage;
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage = certUsage;

	/*Build Certificate Chain from top to root certificate*/
	if (!CertGetCertificateChain(NULL, subjectCert, NULL, pki->store, &chainPara, 0, NULL, &pChainContext)) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get PKI certificate chain");
		goto cleanup;
	}

	if (pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "PKI certificate chain trust error");
		goto cleanup;
	}

	/* Verify certificate chain. */
	policyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
	policyPara.dwFlags = 0;
	policyPara.pvExtraPolicyPara = NULL;

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE,pChainContext, &policyPara, &policyStatus)) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "PKI certificate chain policy verification error");
		goto cleanup;
	}

	if (policyStatus.dwError) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
		goto cleanup;
	}
	
	KSI_SUCCESS(&err);

cleanup:

	if(subjectCert) CertFreeCertificateContext(subjectCert);
	if(pChainContext) CertFreeCertificateChain(pChainContext);

	return KSI_RETURN(&err);
}

static void printPublicKey(const HCRYPTKEY hKey){
	DWORD dwBlobLen;
	BYTE* pbKeyBlob;
	DWORD count = 0;
	DWORD colCount=0;
	
	if(hKey == 0){
		printf("Error: key is nullptr. \n");
	}
	
	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0,NULL,&dwBlobLen)){
		printError(GetLastError());
		printf("Error computing BLOB length.\n");
		return;
		}

	
	
	pbKeyBlob = (BYTE*)malloc(dwBlobLen);
	if(pbKeyBlob == NULL){
		printf("Out of memory. \n");
		return;
	}

	if(!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0,pbKeyBlob,&dwBlobLen)){
		printError(GetLastError());
		printf("Error exporting key.\n");
		return;
	}

   printf("Printing Key BLOB for verification: \n");
   for(count=0; count < dwBlobLen; count ++){
		printf("%02x",pbKeyBlob[count]);
		colCount++;
		if(colCount == 64){
			printf("\n");
			colCount=0;
		}
	}
   printf("\n");
   return;
}

int KSI_PKITruststore_verifySignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	PCCERT_CONTEXT subjectCert = NULL;
	CRYPT_VERIFY_MESSAGE_PARA msgPara;

	
	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	ctx = pki->ctx;
	KSI_BEGIN(ctx, &err);

	
	if (data_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Data too long (more than MAX_INT).");
		goto cleanup;
	}

	/*Get the subjects certificate*/
	res = extractCertificate(signature, &subjectCert);
	if(res != KSI_OK){
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable extract subject PKI certificate");
		goto cleanup;		
		}
	
	KSI_LOG_debug(ctx, "CryptoAPI: Subjects PKI Certificate info:");
	printCertInfo(subjectCert);

	msgPara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    msgPara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    msgPara.hCryptProv = 0;
    msgPara.pfnGetSignerCertificate = NULL;
    msgPara.pvGetArg = NULL;
	
	if (!CryptVerifyDetachedMessageSignature(&msgPara,0,signature->pkcs7.pbData,signature->pkcs7.cbData,1,&data,&data_len,NULL)){
		printError(GetLastError()); 
		KSI_LOG_debug(ctx, "CryptoAPI: Verification of PKI signature failed");
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Verification of PKI signature failed");
		goto cleanup;
		}
	
	res = KSI_PKITruststore_verifySignatureCertificate(pki, signature);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_debug(ctx, "PKI signature verified successfully.");
	
	KSI_SUCCESS(&err);

cleanup:

	if(subjectCert) CertFreeCertificateContext(subjectCert);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_verifyRawSignature(KSI_CTX *ctx, const unsigned char *data, unsigned data_len, const char *algoOid, const unsigned char *signature, unsigned signature_len, const KSI_PKICertificate *certificate) {
	KSI_ERR err;
	PCCRYPT_OID_INFO pOID_INFO = NULL;
	ALG_ID algorithm=0;
	HCRYPTPROV hCryptProv = 0;
    PCCERT_CONTEXT subjectCert = NULL;
	HCRYPTKEY publicKey = 0;
	DWORD i=0;
	BYTE *little_endian_pkcs1= NULL;
	DWORD pkcs1_len = 0;
	HCRYPTHASH hash = 0;
	
	
	KSI_PRE(&err, data != NULL && data_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL && signature_len > 0) goto cleanup;
	KSI_PRE(&err, signature_len < UINT_MAX) goto cleanup;
	KSI_PRE(&err, algoOid != NULL) goto cleanup;
	KSI_PRE(&err, certificate != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	
	
	/*TODO: fix algorithm identification*/
	/*Get signatures ALG_ID*/
	//algorithm = CertOIDToAlgId(algoOid);
	pOID_INFO = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)algoOid, 0);
	algorithm = pOID_INFO->Algid;
	algorithm = CALG_SHA_256;
	printf(">>ALG_ID %i %i \n%s\n%s\n%s \n", algorithm, CALG_SHA_256, algoOid, certificate->x509->pCertInfo->SignatureAlgorithm.pszObjId, CertAlgIdToOID(CALG_SHA1));
	if (algorithm == 0) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}
	
	// Get the CSP context
	if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		printError(GetLastError());
		KSI_LOG_debug(ctx, "CryptoAPI: Unable to get cryptographic provider");
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get cryptographic provider");
		goto cleanup;
	}
	
	// Get the public key from the issuer certificate
	subjectCert = certificate->x509;
	if(!CryptImportPublicKeyInfo(hCryptProv, X509_ASN_ENCODING,&subjectCert->pCertInfo->SubjectPublicKeyInfo,&publicKey)){
		printError(GetLastError());
		KSI_LOG_debug(ctx, "CryptoAPI: Failed to read public key");
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Failed to read PKI public key");
		goto cleanup;
	}
	
	/*Convert big-endian to little-endian PKCS#1 signature*/
	pkcs1_len = signature_len;
	little_endian_pkcs1 = (BYTE*)KSI_malloc(pkcs1_len);
	
	for(i=0; i<pkcs1_len; i++){
		little_endian_pkcs1[pkcs1_len-1-i] = signature[i];
	}
	
	// Create the hash object and hash input data.
	if(!CryptCreateHash(hCryptProv, algorithm, 0, 0, &hash)){
		printError(GetLastError());
		KSI_LOG_debug(ctx, "CryptoAPI: Unable to create hasher");
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to create hasher");
		goto cleanup;
		}
	
	if(!CryptHashData(hash, (BYTE*)data, data_len,0)){
		printError(GetLastError());
		KSI_LOG_debug(ctx, "CryptoAPI: Unable to hash data");
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to hash data");
		goto cleanup;
		}

	/*Verify the signature. The format MUST be PKCS#1*/
	if(!CryptVerifySignature(hash, (BYTE*)little_endian_pkcs1, pkcs1_len, publicKey, NULL, 0)){
		printError(GetLastError());
		KSI_LOG_debug(ctx, "CryptoAPI: Verification of PKI signature failed");
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Verification of PKI signature failed");
		goto cleanup;
		}

	KSI_LOG_debug(certificate->ctx, "PKI signature verified successfully.");

	KSI_SUCCESS(&err);

cleanup:

	if(hCryptProv) CryptReleaseContext(hCryptProv, 0);
	if(hash) CryptDestroyHash(hash);

	return KSI_RETURN(&err);
}

#endif

