#include "internal.h"

#if KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_CRYPTOAPI || 1

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
	KSI_LOG_debug(trust->ctx, "Not implemented");
	return KSI_OK;
}

int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path) {
	KSI_ERR err;
	HCERTSTORE tmp_FileTrustStore;
	
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, path != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);
	
	/*Open new store */
	tmp_FileTrustStore = CertOpenStore(CERT_STORE_PROV_FILENAME_A, 0, NULL, 0, path);
	if (tmp_FileTrustStore == NULL) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	/*Not updates with priority 0*/
	if (!CertAddStoreToCollection(trust->store, tmp_FileTrustStore, 0, 0)) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	tmp_FileTrustStore = NULL;
	
	KSI_SUCCESS(&err);

cleanup:

	if(tmp_FileTrustStore) CertCloseStore(tmp_FileTrustStore, CERT_CLOSE_STORE_CHECK_FLAG);
	return KSI_RETURN(&err);
	return KSI_OK;
}
/*+ TODO: At CertOpenSystemStore change "ROOT" to CA*/
int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **trust) {
	KSI_ERR err;
	KSI_PKITruststore *tmp = NULL;
	HCERTSTORE collectionStore = NULL;
	HCERTSTORE systemStore = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_CTX_registerGlobals(ctx, cryptopapiGlobal_init, cryptopapiGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	/*Open certificate store as collection of other stores*/
	collectionStore = CertOpenStore(CERT_STORE_PROV_COLLECTION, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, NULL, 0, NULL);
	if (collectionStore == NULL) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	/*Open cert store as system store*/
	systemStore = CertOpenSystemStore ((HCRYPTPROV_LEGACY)NULL, "ROOT");
	if (systemStore == NULL) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}
	
	/*Add system store to collection store. Priority determines where the store is located on the chain of other stores.*/
	/*if(!CertAddStoreToCollection(collectionStore, systemStore, 0, 0)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to add PKI systems certificate store to collection store");
		goto cleanup;
	}*/
	
	tmp = KSI_new(KSI_PKITruststore);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->store = NULL;

	tmp->store = collectionStore;
	
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

	
	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);
	
	
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

	
	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_serialize(sig, &raw, &raw_len);
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

int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, unsigned raw_len, KSI_PKISignature **signature) {
	KSI_ERR err;
	KSI_PKISignature *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	
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
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
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
	
	if(certStore == NULL){
		printf("Cert store is nullptr\n");
		return;
	}
	
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

static void printCertChain(const PCCERT_CHAIN_CONTEXT pChainContext){
	DWORD i=0;
	DWORD j=0;
	
	if(pChainContext == NULL){
		printf("Certificate chain is nullptr");
		return;
	}
	
	printf("Certificate chains (%i)", pChainContext->cChain);
	for(i=0; i< pChainContext->cChain; i++){
		printf("\n Chain (%i)::\n", pChainContext->rgpChain[i]->cElement);
		for(j=0; j<pChainContext->rgpChain[i]->cElement; j++){
			PCERT_CHAIN_ELEMENT element = pChainContext->rgpChain[i]->rgpElement[j];
			printf("\t %i) ", j);
			if((element->TrustStatus.dwInfoStatus)&CERT_TRUST_IS_SELF_SIGNED)
				printf("*ROOT* ");
			printCertInfo(element->pCertContext);
		}
			
	}
}

static const char* getCertificateChainErrorStr(PCCERT_CHAIN_CONTEXT pChainContext){
	if(pChainContext == NULL)
		return "Certificate chain is nullptr";
	
	switch(pChainContext->TrustStatus.dwErrorStatus){
		case CERT_TRUST_NO_ERROR: return "No error found for this certificate or chain.";
		case CERT_TRUST_IS_NOT_TIME_VALID:return "This certificate or one of the certificates in the certificate chain is not time valid.";
		case CERT_TRUST_IS_REVOKED:return "Trust for this certificate or one of the certificates in the certificate chain has been revoked.";
		case CERT_TRUST_IS_NOT_SIGNATURE_VALID: return "The certificate or one of the certificates in the certificate chain does not have a valid signature.";
		case CERT_TRUST_IS_NOT_VALID_FOR_USAGE:return "The certificate or certificate chain is not valid for its proposed usage.";
		case CERT_TRUST_IS_UNTRUSTED_ROOT: return "The certificate or certificate chain is based on an untrusted root.";
		case CERT_TRUST_REVOCATION_STATUS_UNKNOWN: return "The revocation status of the certificate or one of the certificates in the certificate chain is unknown.";
		case CERT_TRUST_IS_CYCLIC: return "One of the certificates in the chain was issued by a certification authority that the original certificate had certified.";
		case CERT_TRUST_INVALID_EXTENSION: return "One of the certificates has an extension that is not valid.";
		case CERT_TRUST_INVALID_POLICY_CONSTRAINTS: return "The certificate or one of the certificates in the certificate chain has a policy constraints extension, and one of the issued certificates has a disallowed policy mapping extension or does not have a required issuance policies extension.";
		case CERT_TRUST_INVALID_BASIC_CONSTRAINTS: return "The certificate or one of the certificates in the certificate chain has a basic constraints extension, and either the certificate cannot be used to issue other certificates, or the chain path length has been exceeded.";
		case CERT_TRUST_INVALID_NAME_CONSTRAINTS: return "The certificate or one of the certificates in the certificate chain has a name constraints extension that is not valid.";
		case CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT: return "The certificate or one of the certificates in the certificate chain has a name constraints extension that contains unsupported fields.";
		case CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT: return "The certificate or one of the certificates in the certificate chain has a name constraints extension and a name constraint is missing for one of the name choices in the end certificate.";
		case CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT: return "The certificate or one of the certificates in the certificate chain has a name constraints extension, and there is not a permitted name constraint for one of the name choices in the end certificate.";
		case CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT: return "The certificate or one of the certificates in the certificate chain has a name constraints extension, and one of the name choices in the end certificate is explicitly excluded.";
		case CERT_TRUST_IS_OFFLINE_REVOCATION: return "The revocation status of the certificate or one of the certificates in the certificate chain is either offline or stale.";
		case CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY: return "The end certificate does not have any resultant issuance policies, and one of the issuing certification authority certificates has a policy constraints extension requiring it.";
		case CERT_TRUST_IS_EXPLICIT_DISTRUST: return "The certificate is explicitly distrusted.";
		case CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT: return "The certificate does not support a critical extension.";
		default: return "Unknown certificate chain error";
	}
}

/*cert obj must be freed*/
static int extractSigningCertificate(const KSI_PKISignature *signature, PCCERT_CONTEXT *cert) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	HCERTSTORE certStore;
	DWORD signerCount = 0;
	PCERT_INFO pSignerCertInfo = NULL;
	HCRYPTMSG signaturMSG = NULL;
	PCCERT_CONTEXT signing_cert = NULL;
	BYTE *dataRecieved = NULL;
	DWORD dataLen = 0;
	
	
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	ctx = signature->ctx;
	KSI_BEGIN(ctx, &err);
	
	/*Get Signature certificates as a certificate store*/
	certStore = CryptGetMessageCertificates(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, (HCRYPTPROV_LEGACY)NULL, 0, signature->pkcs7.pbData, signature->pkcs7.cbData);
	if(certStore == NULL){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	 }
	
	/*Counting signing certificates*/
	signerCount = CryptGetMessageSignerCount(PKCS_7_ASN_ENCODING, signature->pkcs7.pbData, signature->pkcs7.cbData);
	if(signerCount == -1){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	/*Is there exactly 1 signing cert?*/
	if(signerCount !=1){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "PKI signature cert count is not 1");
		goto cleanup;
	}
	
	/*Open signature for decoding*/
	signaturMSG = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0,0, NULL, NULL);
	if(signaturMSG == NULL){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	if(!CryptMsgUpdate(signaturMSG, signature->pkcs7.pbData, signature->pkcs7.cbData, TRUE)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	/*Get signatures signing cert id*/
	if(!CryptMsgGetParam (signaturMSG, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &dataLen)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	dataRecieved = KSI_malloc(dataLen);
	if(dataRecieved == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	
	if(!CryptMsgGetParam (signaturMSG, CMSG_SIGNER_CERT_INFO_PARAM, 0, dataRecieved, &dataLen)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	pSignerCertInfo = (PCERT_INFO)dataRecieved;

	/*Get signing cert*/
	signing_cert = CertGetSubjectCertificateFromStore(certStore, X509_ASN_ENCODING, pSignerCertInfo);
	if(signing_cert == NULL){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get signer certificate");
		goto cleanup;
	}
	
	/*The copy of the object is NOT created. Just its reference value is incremented*/
	signing_cert = CertDuplicateCertificateContext(signing_cert);
	
	*cert = signing_cert;
	signing_cert = NULL;
	
	
	KSI_SUCCESS(&err);
	
cleanup:

	if(signing_cert) CertFreeCertificateContext(signing_cert);
	if(certStore) CertCloseStore(certStore, CERT_CLOSE_STORE_CHECK_FLAG);
	if(signaturMSG) CryptMsgClose(signaturMSG);
	KSI_free(dataRecieved);

	return KSI_RETURN(&err);
}

static int KSI_PKITruststore_verifyCertificate(const KSI_PKITruststore *pki, const PCCERT_CONTEXT cert){
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	CERT_ENHKEY_USAGE enhkeyUsage;
	CERT_USAGE_MATCH certUsage;
	CERT_CHAIN_PARA chainPara;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;
	CERT_CHAIN_POLICY_PARA policyPara;
	CERT_CHAIN_POLICY_STATUS policyStatus;

	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	ctx = pki->ctx;
	KSI_BEGIN(ctx, &err);
	
	/* Get the certificate chain of our certificate. */
	enhkeyUsage.cUsageIdentifier = 0;
	enhkeyUsage.rgpszUsageIdentifier = NULL;
	certUsage.dwType = USAGE_MATCH_TYPE_AND;
	certUsage.Usage = enhkeyUsage;
	chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	chainPara.RequestedUsage = certUsage;
	
	/*use CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL for no updates*/	
	/*Build Certificate Chain from top to root certificate*/
	if (!CertGetCertificateChain(NULL, cert, NULL, pki->store, &chainPara, 0, NULL, &pChainContext)) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get PKI certificate chain");
		goto cleanup;
	}

	printCertChain(pChainContext);
	
	if (pChainContext->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR) {
		KSI_LOG_debug(ctx, "%s", getCertificateChainErrorStr(pChainContext));
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, getCertificateChainErrorStr(pChainContext));
		goto cleanup;
	}
	
	/* Verify certificate chain. */
	policyPara.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);
	policyPara.dwFlags = 0;
	policyPara.pvExtraPolicyPara = 0;

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE,pChainContext, &policyPara, &policyStatus)) {
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	if (policyStatus.dwError) {
		KSI_LOG_debug(ctx, "PKI chain policy error %X", policyStatus.dwError);
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
		goto cleanup;
	}
	
	KSI_SUCCESS(&err);
	
cleanup:
	
	if(pChainContext) CertFreeCertificateChain(pChainContext);
	
	return KSI_RETURN(&err);
}

static int KSI_PKITruststore_verifySignatureCertificate(const KSI_PKITruststore *pki, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	PCCERT_CONTEXT subjectCert = NULL;
	char tmp[256];
	
	
	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	ctx = pki->ctx;
	KSI_BEGIN(ctx, &err);

	res = extractSigningCertificate(signature, &subjectCert);
	KSI_CATCH(&err, res) goto cleanup;

	printCertInfo(subjectCert);
	
	
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

	res = KSI_PKITruststore_verifyCertificate(pki, subjectCert);
	KSI_CATCH(&err, res);
	
	KSI_SUCCESS(&err);

cleanup:

	if(subjectCert) CertFreeCertificateContext(subjectCert);

	return KSI_RETURN(&err);
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
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Data too long (more than MAX_INT)");
		goto cleanup;
	}

	/*Verify signature and signed data. Certificate is extracted from signature*/
	msgPara.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    msgPara.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    msgPara.hCryptProv = 0;
    msgPara.pfnGetSignerCertificate = NULL;
    msgPara.pvGetArg = NULL;
	
	if (!CryptVerifyDetachedMessageSignature(&msgPara,0,signature->pkcs7.pbData,signature->pkcs7.cbData,1,&data,&data_len,&subjectCert)){
		printError(GetLastError()); 
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Verification of PKI signature failed");
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "CryptoAPI: Subjects PKI Certificate info:");
	printCertInfo(subjectCert);
	
	res = KSI_PKITruststore_verifyCertificate(pki, subjectCert);
	KSI_CATCH(&err, res) goto cleanup;
	
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
	int res;
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
	algorithm = CertOIDToAlgId(algoOid);
	pOID_INFO = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)algoOid, 0);
	printError(GetLastError());
	algorithm = pOID_INFO->Algid;
	printf(">>ALG_ID %x %x \n%s\n%s\n%s \n", algorithm, CALG_SHA_256, algoOid, certificate->x509->pCertInfo->SignatureAlgorithm.pszObjId, CertAlgIdToOID(CALG_SHA1));
	algorithm = CALG_SHA_256;
	if (algorithm == 0) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}
	
	// Get the CSP context
	if(!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get cryptographic provider");
		goto cleanup;
	}
	
	// Get the public key from the issuer certificate
	subjectCert = certificate->x509;
	if(!CryptImportPublicKeyInfo(hCryptProv, X509_ASN_ENCODING,&subjectCert->pCertInfo->SubjectPublicKeyInfo,&publicKey)){
		printError(GetLastError());
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
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to create hasher");
		goto cleanup;
	}
	
	if(!CryptHashData(hash, (BYTE*)data, data_len,0)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to hash data");
		goto cleanup;
	}

	/*Verify the signature. The format MUST be PKCS#1*/
	if(!CryptVerifySignature(hash, (BYTE*)little_endian_pkcs1, pkcs1_len, publicKey, NULL, 0)){
		printError(GetLastError());
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
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

