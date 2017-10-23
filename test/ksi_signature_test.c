/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <string.h>

#include <ksi/signature.h>
#include <ksi/tlv.h>

#include "all_tests.h"

#include "../src/ksi/impl/ctx_impl.h"
#include "../src/ksi/impl/net_impl.h"
#include "../src/ksi/impl/signature_impl.h"

extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"


static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

static void testLoadSignatureFromFile(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifySignatureNew(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature online.", res == KSI_OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testVerifySignatureWithPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);

	CuAssert(tc, "Unable to verify signature with publication.", res == KSI_OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifyLegacySignatureAndDoc(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"

	int res;
	char doc[] = "This is a test data file.\x0d\x0a";
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifyLegacyExtendedSignatureAndDoc(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-legacy-sig-2014-06-extended.gtts.ksig"

	int res;
	char doc[] = "This is a test data file.\x0d\x0a";
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testExtractInputHashLegacySignature(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"

	int res;
	char doc[] = "This is a test data file.\x0d\x0a";
	KSI_Signature *sig = NULL;
	KSI_DataHash *sig_input_hash = NULL;
	KSI_DataHash *doc_hash = NULL;
	KSI_DataHasher *hsr = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_getHashAlgorithmByName("sha-256"), &hsr);
	CuAssert(tc, "Unable to open hasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, doc, strlen(doc));
	CuAssert(tc, "Unable to hash document.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &doc_hash);
	CuAssert(tc, "Unable to hash document.", res == KSI_OK && doc_hash != NULL);


	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getDocumentHash(sig, &sig_input_hash);
	CuAssert(tc, "Unable to get signatures input hash.", res == KSI_OK);
	CuAssert(tc, "Signature input hash does not equal documents hash!", KSI_DataHash_equals(sig_input_hash, doc_hash));

	KSI_Signature_free(sig);
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(doc_hash);

#undef TEST_SIGNATURE_FILE
}

static void testRFC3161WrongChainIndex(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-legacy-sig-2015-01-chainIndex.gtts"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && sig == NULL);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRFC3161WrongAggreTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-legacy-sig-2015-01-aggretime.gtts"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && sig == NULL);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRFC3161WrongInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-legacy-sig-2015-01-inHash.gtts"

	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && sig == NULL);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifySignatureWithUserPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	const char pubStr[] = "AAAAAA-CTOQBY-AAMJYH-XZPM6T-UO6U6V-2WJMHQ-EJMVXR-JEAGID-2OY7P5-XFFKYI-QIF2LG-YOV7SO";
	const char pubStr_bad[] = "AAAAAA-CT5VGY-AAPUCF-L3EKCC-NRSX56-AXIDFL-VZJQK4-WDCPOE-3KIWGB-XGPPM3-O5BIMW-REOVR4";
	KSI_PublicationData *pubData = NULL;
	KSI_PublicationData *pubData_bad = NULL;
	KSI_VerificationContext verifier;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_VerificationContext_init(&verifier, ctx);

	res = KSI_PublicationData_fromBase32(ctx, pubStr, &pubData);
	CuAssert(tc, "Unable to parse publication string.", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_fromBase32(ctx, pubStr_bad, &pubData_bad);
	CuAssert(tc, "Unable to parse publication string.", res == KSI_OK && pubData_bad != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verifier.signature = sig;

	/* The positive case. */
	verifier.userPublication = pubData;
	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &verifier, &result);
	CuAssert(tc, "Unable to verify signature with publication due to an error.", res == KSI_OK);
	CuAssert(tc, "The verification should have been successful.", result->resultCode == KSI_VER_RES_OK);
	KSI_PolicyVerificationResult_free(result);
	result = NULL;

	/* The negative case. */
	verifier.userPublication = pubData_bad;
	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &verifier, &result);
	CuAssert(tc, "Unable to verify signature with publication due to an error.", res == KSI_OK);
	CuAssert(tc, "The verification should not have been successful.", result->resultCode != KSI_VER_RES_OK);


	KSI_PublicationData_free(pubData);
	KSI_PublicationData_free(pubData_bad);
	KSI_Signature_free(sig);
	KSI_VerificationContext_clean(&verifier);
	KSI_PolicyVerificationResult_free(result);

#undef TEST_SIGNATURE_FILE
}

static void testVerifySignatureExtendedToHead(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-head.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-head-extend_response.tlv"
	int res;
	KSI_Signature *sig = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_VerificationContext verifier;

	KSI_ERR_clearErrors(ctx);

	KSI_VerificationContext_init(&verifier, ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Signature should have either a calendar auth record or publication", res == KSI_OK && sig != NULL);

	/* Set the extend response. */
	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	verifier.signature = sig;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &verifier, &result);
	CuAssert(tc, "Unable to verify signature due to an error.", res == KSI_OK);
	CuAssert(tc, "Signature should verify.", result->resultCode == KSI_VER_RES_OK);

	KSI_VerificationContext_clean(&verifier);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}


static void testSignatureSigningTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_uint64_t utc = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	CuAssert(tc, "Unable to get signing time from signature", res == KSI_OK && sigTime != NULL);

	utc = KSI_Integer_getUInt64(sigTime);

	CuAssert(tc, "Unexpected signature signing time.", utc == 1398866256);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testSignatureSigningTimeNoCalendarChain(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-only_aggr.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_uint64_t utc = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature containing only aggregation chains from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	CuAssert(tc, "Unable to get signing time from signature containing only aggregation chains.", res == KSI_OK && sigTime != NULL);

	utc = KSI_Integer_getUInt64(sigTime);

	CuAssert(tc, "Unexpected signature signing time.", utc == 1398866256);

	KSI_Signature_free(sig);
#undef TEST_SIGNATURE_FILE
}

static void testSerializeSignature(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;

	unsigned char in[0x1ffff];
	size_t in_len = 0;

	unsigned char *out = NULL;
	size_t out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &out, &out_len);
	CuAssert(tc, "Failed to serialize signature", res == KSI_OK);
	CuAssert(tc, "Serialized signature length mismatch", in_len == out_len);
	CuAssert(tc, "Serialized signature content mismatch", !memcmp(in, out, in_len));

	KSI_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifyDocument(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;

	unsigned char in[0x1ffff];
	size_t in_len = 0;

	char doc[] = "LAPTOP";

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifyDocumentHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;

	unsigned char in[0x1ffff];
	size_t in_len = 0;

	char doc[] = "LAPTOP";
	KSI_DataHash *hsh = NULL;

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_PolicyVerificationResult *result = NULL;
	KSI_VerificationContext verifier;

	KSI_ERR_clearErrors(ctx);

	KSI_VerificationContext_init(&verifier, ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	/* Chech correct document. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	verifier.signature = sig;
	verifier.documentHash = hsh;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &verifier, &result);
	CuAssert(tc, "Verification failed with an error.", res == KSI_OK);
	CuAssert(tc, "Verification should have been successful.", result->resultCode == KSI_VER_RES_OK);

	KSI_PolicyVerificationResult_free(result);
	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Chech wrong document. */
	res = KSI_DataHash_create(ctx, doc, sizeof(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	verifier.documentHash = hsh;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &verifier, &result);
	CuAssert(tc, "Verification failed with an error.", res == KSI_OK);
	CuAssert(tc, "Verification should not have been successful.", result->resultCode != KSI_VER_RES_OK);

	KSI_DataHash_free(hsh);
	KSI_PolicyVerificationResult_free(result);
	result = NULL;
	hsh = NULL;

	/* Check correct document with wrong hash algorithm. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_512, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	verifier.documentHash = hsh;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &verifier, &result);
	CuAssert(tc, "Verification failed with an error.", res == KSI_OK);
	CuAssert(tc, "Verification should not have been successful.", result->resultCode != KSI_VER_RES_OK);

	KSI_DataHash_free(hsh);
	KSI_VerificationContext_clean(&verifier);
	KSI_PolicyVerificationResult_free(result);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testSignerIdentity(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-08-01.1.ksig"

	int res;
	const char id_expected[] = "GT :: testA :: 36-test";
	KSI_Signature *sig = NULL;
	char *id_actual = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSignerIdentity(sig, &id_actual);
	CuAssert(tc, "Unable to get signer identity from signature.", res == KSI_OK && id_actual != NULL);

	CuAssert(tc, "Unexpected signer identity", !strncmp(id_expected, id_actual, strlen(id_expected)));

	KSI_Signature_free(sig);
	KSI_free(id_actual);

#undef TEST_SIGNATURE_FILE
}

static void testSignerIdentityMetaData(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2015-09-13_21-34-00.ksig"

	int res;
	const char id_expected[] = "GT :: GT :: release test :: anon http";
	KSI_Signature *sig = NULL;
	char *id_actual = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSignerIdentity(sig, &id_actual);
	CuAssert(tc, "Unable to get signer identity from signature.", res == KSI_OK && id_actual != NULL);
	CuAssert(tc, "Unexpected signer identity", !strncmp(id_expected, id_actual, strlen(id_expected)));

	KSI_Signature_free(sig);
	KSI_free(id_actual);

#undef TEST_SIGNATURE_FILE
}

static void testAggregationHashChainIdentity(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-08-01.1.ksig"

	int res;
	const char *expected[] = {"GT","testA","36-test"};
	KSI_Signature *sig = NULL;
	KSI_HashChainLinkIdentity *identity = NULL;
	KSI_HashChainLinkIdentityList *identityList = NULL;
	size_t i;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getAggregationHashChainIdentity(sig, &identityList);
	CuAssert(tc, "Unable to get identity list from signature.", res == KSI_OK && identityList != NULL);

	CuAssert(tc, "Identity list size mismatch.", KSI_HashChainLinkIdentityList_length(identityList) == (sizeof(expected) / sizeof(char*)));

	for (i = 0; i < KSI_HashChainLinkIdentityList_length(identityList); i++) {
		KSI_Utf8String *clientId = NULL;
		KSI_Utf8String *machineId = NULL;
		KSI_Integer *sequenceNr = NULL;
		KSI_Integer *requestTime = NULL;
		KSI_HashChainLinkIdentityType type;

		res = KSI_HashChainLinkIdentityList_elementAt(identityList, i, &identity);
		CuAssert(tc, "Unable to get identity from identity list.", res == KSI_OK && identity != NULL);

		res = KSI_HashChainLinkIdentity_getType(identity, &type);
		CuAssert(tc, "Unable to get client id from identity list.", res == KSI_OK);
		CuAssert(tc, "Identity type mismatch.", type == KSI_IDENTITY_TYPE_LEGACY_ID);

		res = KSI_HashChainLinkIdentity_getClientId(identity, &clientId);
		CuAssert(tc, "Unable to get client id from identity list.", res == KSI_OK && clientId != NULL);

		CuAssert(tc, "Unexpected client id.", !strncmp(expected[i], KSI_Utf8String_cstr(clientId), strlen(expected[i])));

		res = KSI_HashChainLinkIdentity_getMachineId(identity, &machineId);
		CuAssert(tc, "Machine id is not present.", res == KSI_OK && machineId == NULL);

		res = KSI_HashChainLinkIdentity_getSequenceNr(identity, &sequenceNr);
		CuAssert(tc, "Sequence number is not present.", res == KSI_OK && sequenceNr == NULL);

		res = KSI_HashChainLinkIdentity_getRequestTime(identity, &requestTime);
		CuAssert(tc, "Request time is not present.", res == KSI_OK && requestTime == NULL);
	}

	KSI_Signature_free(sig);
	KSI_HashChainLinkIdentityList_free(identityList);

#undef TEST_SIGNATURE_FILE
}

static void testAggregationHashChainIdentityWithMetaData(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2015-09-13_21-34-00.ksig"

	int res;
	struct {
		int type;
		char *clientId;
		char *machineId;
		uint64_t sequenceNr;
		uint64_t requestTime;
	} expected[] = {
		{KSI_IDENTITY_TYPE_LEGACY_ID,	"GT",				NULL, 0, 0},
		{KSI_IDENTITY_TYPE_LEGACY_ID,	"GT",				NULL, 0, 0},
		{KSI_IDENTITY_TYPE_LEGACY_ID,	"release test",		NULL, 0, 0},
		{KSI_IDENTITY_TYPE_METADATA,	"anon http",		NULL, 0, 0x051fa5314579d7}
	};
	KSI_Signature *sig = NULL;
	KSI_HashChainLinkIdentity *identity = NULL;
	KSI_HashChainLinkIdentityList *identityList = NULL;
	size_t i;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getAggregationHashChainIdentity(sig, &identityList);
	CuAssert(tc, "Unable to get identity list from signature.", res == KSI_OK && identityList != NULL);

	CuAssert(tc, "Identity list size mismatch.", KSI_HashChainLinkIdentityList_length(identityList) == (sizeof(expected) / sizeof(expected[0])));

	for (i = 0; i < KSI_HashChainLinkIdentityList_length(identityList); i++) {
		KSI_HashChainLinkIdentityType type;
		KSI_Utf8String *clientId = NULL;

		res = KSI_HashChainLinkIdentityList_elementAt(identityList, i, &identity);
		CuAssert(tc, "Unable to get identity from identity list.", res == KSI_OK && identity != NULL);


		res = KSI_HashChainLinkIdentity_getClientId(identity, &clientId);
		CuAssert(tc, "Unable to get client id from identity list.", res == KSI_OK && clientId != NULL);
		CuAssert(tc, "Unexpected client id.", !strncmp(expected[i].clientId, KSI_Utf8String_cstr(clientId), strlen(expected[i].clientId)));

		res = KSI_HashChainLinkIdentity_getType(identity, &type);
		CuAssert(tc, "Unable to get type from identity list.", res == KSI_OK);
		CuAssert(tc, "Identity type mismatch.", type == expected[i].type);

		if (type == KSI_IDENTITY_TYPE_METADATA) {
			KSI_Utf8String *machineId = NULL;
			KSI_Integer *sequenceNr = NULL;
			KSI_Integer *requestTime = NULL;

			res = KSI_HashChainLinkIdentity_getMachineId(identity, &machineId);
			CuAssert(tc, "Unexpected machine id.", res == KSI_OK && machineId == NULL);

			res = KSI_HashChainLinkIdentity_getSequenceNr(identity, &sequenceNr);
			CuAssert(tc, "Unable to get sequence number from identity list.", res == KSI_OK && sequenceNr != NULL);
			CuAssert(tc, "Unexpected sequence number.", KSI_Integer_getUInt64(sequenceNr) == expected[i].sequenceNr);

			res = KSI_HashChainLinkIdentity_getRequestTime(identity, &requestTime);
			CuAssert(tc, "Unable to get request time from identity list.", res == KSI_OK && requestTime != NULL);
			CuAssert(tc, "Unexpected request time.", KSI_Integer_getUInt64(requestTime) == expected[i].requestTime);
		}
	}

	KSI_Signature_free(sig);
	KSI_HashChainLinkIdentityList_free(identityList);

#undef TEST_SIGNATURE_FILE
}

static void testSignatureWith2Anchors(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-two-anchors.ksig"

	KSI_Signature *sig = NULL;
	int res;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Reading a signature with more than one trust anchor should result in format error.", res == KSI_INVALID_FORMAT && sig == NULL);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testVerifyCalendarChainAlgoChange(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/cal_algo_switch.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/cal_algo_switch-extend_resposne.tlv"

	int res;
	unsigned char in[0x1ffff];
	size_t in_len = 0;

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_PolicyVerificationResult *result = NULL;
	KSI_VerificationContext verifier;

	KSI_ERR_clearErrors(ctx);

	KSI_VerificationContext_init(&verifier, ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	verifier.signature = sig;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &verifier, &result);
	CuAssert(tc, "Verification failed due to an error.", res == KSI_OK);
	CuAssert(tc, "The signature should have been verified successfully.", result->resultCode == KSI_VER_RES_OK);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_clean(&verifier);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testCreateAggregationAuthRec(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationAuthRec *auhtRec = NULL;

	res = KSI_AggregationAuthRec_new(ctx, &auhtRec);
	CuAssert(tc, "Unable to create aggregation authentication record", res == KSI_OK && auhtRec != NULL);

	KSI_AggregationAuthRec_free(auhtRec);
}

static void testSignatureGetPublicationInfo(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Utf8StringList *pubRef = NULL;
	KSI_Utf8StringList *pubRepUrl = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubDate = NULL;
	size_t i;
	KSI_Utf8StringList *infoPubRef = NULL;
	KSI_Utf8StringList *infoPubRepUrl = NULL;
	KSI_Utf8String *infoPubStr = NULL;
	KSI_DataHash *infoPubHsh = NULL;
	time_t infoPubDate;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationInfo(sig, &infoPubHsh, &infoPubStr, &infoPubDate, &infoPubRef, &infoPubRepUrl);
	CuAssert(tc, "Unable to get signature publication info.", res == KSI_OK);

#if DUMP_RESULT
	{
		char buf[256];
		struct tm tm;

		KSI_LOG_debug(ctx, "Publication string: %s", KSI_Utf8String_cstr(infoPubStr));
		gmtime_r(&infoPubDate, &tm);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
		KSI_LOG_debug(ctx, "Publication date:   %s (Unix epoc time %d)", buf, infoPubDate);
		KSI_LOG_debug(ctx, "Publication hash:   %s", KSI_DataHash_toString(infoPubHsh, buf, sizeof(buf)));
		KSI_LOG_debug(ctx, "Publication refs:   %d", KSI_Utf8StringList_length(infoPubRef));
		for (i = 0; i < KSI_Utf8StringList_length(infoPubRef); i++) {
			KSI_Utf8String *el = NULL;
			res = KSI_Utf8StringList_elementAt(infoPubRef, i, &el);
			KSI_LOG_debug(ctx, "  %d: %s", i, KSI_Utf8String_cstr(el));
		}
		KSI_LOG_debug(ctx, "Publication URLs:   %d", KSI_Utf8StringList_length(infoPubRepUrl));
		for (i = 0; i < KSI_Utf8StringList_length(infoPubRepUrl); i++) {
			KSI_Utf8String *el = NULL;
			KSI_Utf8StringList_elementAt(infoPubRepUrl, i, &el);
			KSI_LOG_debug(ctx, "  %d: %s", i, KSI_Utf8String_cstr(el));
		}
	}
#endif

	res = KSI_Signature_getPublicationRecord(sig, &pubRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRef);
	CuAssert(tc, "Unable to read signature publication references.", res == KSI_OK && pubRef != NULL);

	CuAssert(tc, "Publication reference number mismatch.", KSI_Utf8StringList_length(infoPubRef) == KSI_Utf8StringList_length(pubRef));

	for (i = 0; i < KSI_Utf8StringList_length(pubRef); i++) {
		KSI_Utf8String *ref = NULL;
		KSI_Utf8String *infRef = NULL;

		res = KSI_Utf8StringList_elementAt(pubRef, i, &ref);
		CuAssert(tc, "Unable to read publication reference.", res == KSI_OK && ref != NULL);

		res = KSI_Utf8StringList_elementAt(infoPubRef, i, &infRef);
		CuAssert(tc, "Unable to read publication reference.", res == KSI_OK && ref != NULL);

		CuAssert(tc, "Publication reference mismatch.", strcmp(KSI_Utf8String_cstr(infRef), KSI_Utf8String_cstr(ref)) == 0);
	}

	res = KSI_PublicationRecord_getRepositoryUriList(pubRec, &pubRepUrl);
	CuAssert(tc, "Signature publication repository URLs are not availale.", res == KSI_OK && pubRepUrl == NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_getImprint(pubData, &pubHsh);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && pubHsh != NULL);

	CuAssert(tc, "Published hash mismatch.", KSI_DataHash_equals(pubHsh, infoPubHsh) != 0);

	KSI_PublicationData_getTime(pubData, &pubDate);
	CuAssert(tc, "Unable to read signature publication time.", res == KSI_OK && pubDate != NULL);
	CuAssert(tc, "Publication date mismatch.", KSI_Integer_equalsUInt(pubDate, infoPubDate) != 0);

	/* Release resources */
	KSI_DataHash_free(infoPubHsh);
	KSI_Utf8String_free(infoPubStr);
	KSI_Utf8StringList_free(infoPubRef);
	KSI_Utf8StringList_free(infoPubRepUrl);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testSignatureGetPublicationInfo_verifyNullPointer(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Utf8StringList *pubRef = NULL;
	KSI_Utf8StringList *pubRepUrl = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubDate = NULL;
	size_t i;
	KSI_Utf8StringList *infoPubRef = NULL;
	KSI_Utf8StringList *infoPubRepUrl = NULL;
	KSI_Utf8String *infoPubStr = NULL;
	KSI_DataHash *infoPubHsh = NULL;
	time_t infoPubDate;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationInfo(sig, &infoPubHsh, NULL, NULL, NULL, NULL);
	CuAssert(tc, "Unable to get signature publication info publication hash.", res == KSI_OK && infoPubHsh != NULL);

	res = KSI_Signature_getPublicationInfo(sig, NULL, &infoPubStr, NULL, NULL, NULL);
	CuAssert(tc, "Unable to get signature publication info publication string.", res == KSI_OK && infoPubStr != NULL);

	res = KSI_Signature_getPublicationInfo(sig, NULL, NULL, &infoPubDate, NULL, NULL);
	CuAssert(tc, "Unable to get signature publication info publication date.", res == KSI_OK);

	res = KSI_Signature_getPublicationInfo(sig, NULL, NULL, NULL, &infoPubRef, NULL);
	CuAssert(tc, "Unable to get signature publication info publication refs.", res == KSI_OK && infoPubRef != NULL);

	res = KSI_Signature_getPublicationInfo(sig, NULL, NULL, NULL, NULL, &infoPubRepUrl);
	CuAssert(tc, "Unable to get signature publication info repository URLs.", res == KSI_OK && infoPubRepUrl != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &pubRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRef);
	CuAssert(tc, "Unable to read signature publication references.", res == KSI_OK && pubRef != NULL);

	CuAssert(tc, "Publication reference number mismatch.", KSI_Utf8StringList_length(infoPubRef) == KSI_Utf8StringList_length(pubRef));

	for (i = 0; i < KSI_Utf8StringList_length(pubRef); i++) {
		KSI_Utf8String *ref = NULL;
		KSI_Utf8String *infRef = NULL;

		res = KSI_Utf8StringList_elementAt(pubRef, i, &ref);
		CuAssert(tc, "Unable to read publication reference.", res == KSI_OK && ref != NULL);

		res = KSI_Utf8StringList_elementAt(infoPubRef, i, &infRef);
		CuAssert(tc, "Unable to read publication reference.", res == KSI_OK && ref != NULL);

		CuAssert(tc, "Publication reference mismatch.", strcmp(KSI_Utf8String_cstr(infRef), KSI_Utf8String_cstr(ref)) == 0);
	}

	res = KSI_PublicationRecord_getRepositoryUriList(pubRec, &pubRepUrl);
	CuAssert(tc, "Signature publication repository URLs are not availale.", res == KSI_OK && pubRepUrl == NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_getImprint(pubData, &pubHsh);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && pubHsh != NULL);

	CuAssert(tc, "Published hash mismatch.", KSI_DataHash_equals(pubHsh, infoPubHsh) != 0);

	KSI_PublicationData_getTime(pubData, &pubDate);
	CuAssert(tc, "Unable to read signature publication time.", res == KSI_OK && pubDate != NULL);
	CuAssert(tc, "Publication date mismatch.", KSI_Integer_equalsUInt(pubDate, infoPubDate) != 0);

	/* Release resources */
	KSI_DataHash_free(infoPubHsh);
	KSI_Utf8String_free(infoPubStr);
	KSI_Utf8StringList_free(infoPubRef);
	KSI_Utf8StringList_free(infoPubRepUrl);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testCreateHasher(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	const char data[] = "LAPTOP";

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_createDataHasher(sig, &hsr);
	CuAssert(tc, "Unable to create data hasher from signature.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, data, strlen(data));
	CuAssert(tc, "Unable to add data to the hasher.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "######", hsh);
	CuAssert(tc, "Unable to close the data hasher", res == KSI_OK && hsh != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Data hash verification should not fail.", res == KSI_OK);

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testSigning_docAlgorithmDeprecated(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_createZero(ctx, KSI_HASHALG_SHA1, &hsh);
	CuAssert(tc, "Unable to create data hash object.", res == KSI_OK && hsh != NULL);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Unable to sign the hash", res == KSI_UNTRUSTED_HASH_ALGORITHM && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
}

CuSuite* KSITest_Signature_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testLoadSignatureFromFile);
	SUITE_ADD_TEST(suite, testSignatureSigningTime);
	SUITE_ADD_TEST(suite, testSignatureSigningTimeNoCalendarChain);
	SUITE_ADD_TEST(suite, testSerializeSignature);
	SUITE_ADD_TEST(suite, testVerifyDocument);
	SUITE_ADD_TEST(suite, testVerifyDocumentHash);
	SUITE_ADD_TEST(suite, testVerifySignatureNew);
	SUITE_ADD_TEST(suite, testVerifySignatureWithPublication);
	SUITE_ADD_TEST(suite, testVerifySignatureWithUserPublication);
	SUITE_ADD_TEST(suite, testVerifySignatureExtendedToHead);
	SUITE_ADD_TEST(suite, testVerifyLegacySignatureAndDoc);
	SUITE_ADD_TEST(suite, testVerifyLegacyExtendedSignatureAndDoc);
	SUITE_ADD_TEST(suite, testRFC3161WrongChainIndex);
	SUITE_ADD_TEST(suite, testRFC3161WrongAggreTime);
	SUITE_ADD_TEST(suite, testRFC3161WrongInputHash);
	SUITE_ADD_TEST(suite, testSignerIdentity);
	SUITE_ADD_TEST(suite, testSignerIdentityMetaData);
	SUITE_ADD_TEST(suite, testAggregationHashChainIdentity);
	SUITE_ADD_TEST(suite, testAggregationHashChainIdentityWithMetaData);
	SUITE_ADD_TEST(suite, testSignatureWith2Anchors);
	SUITE_ADD_TEST(suite, testVerifyCalendarChainAlgoChange);
	SUITE_ADD_TEST(suite, testExtractInputHashLegacySignature);
	SUITE_ADD_TEST(suite, testCreateAggregationAuthRec);
	SUITE_ADD_TEST(suite, testSignatureGetPublicationInfo);
	SUITE_ADD_TEST(suite, testSignatureGetPublicationInfo_verifyNullPointer);
	SUITE_ADD_TEST(suite, testCreateHasher);
	SUITE_ADD_TEST(suite, testSigning_docAlgorithmDeprecated);

	return suite;
}
