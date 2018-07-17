/*
 * Copyright 2013-2018 Guardtime, Inc.
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


#include "cutest/CuTest.h"
#include "all_tests.h"

#include <ksi/tlv.h>

extern KSI_CTX *ctx;

static void TestLogInfo(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_info(ctx, "Logging info with null ctx");
	CuAssert(tc, "Logging should be successful with info level and context.", res == KSI_OK);
}

static void TestLogDebug(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_debug(ctx, "Logging Debug with ctx");
	CuAssert(tc, "Logging should be successful with debug level and context.", res == KSI_OK);
}

static void TestLogNotice(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_notice(ctx, "Logging notice with ctx");
	CuAssert(tc, "Logging should be successful with notice level and context.", res == KSI_OK);
}

static void TestLogWarn(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_warn(ctx, "Logging warn with ctx");
	CuAssert(tc, "Logging should be successful with warm level and context.", res == KSI_OK);
}

static void TestLogError(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_error(ctx, "Logging error with ctx");
	CuAssert(tc, "Logging should be successful with error level and context.", res == KSI_OK);
}

static void TestLogInfoAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_info(NULL, "Logging info with null ctx");
	CuAssert(tc, "Logging should be successful with info level and null context.", res == KSI_OK);
}

static void TestLogDebugAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_debug(NULL, "Logging Debug with null ctx");
	CuAssert(tc, "Logging should be successful with debug level and null context.", res == KSI_OK);
}

static void TestLogNoticeAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_notice(NULL, "Logging notice with null ctx");
	CuAssert(tc, "Logging should be successful with notice level and null context.", res == KSI_OK);
}

static void TestLogWarnAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_warn(NULL, "Logging warn with null ctx");
	CuAssert(tc, "Logging should be successful with info warm level and null context.", res == KSI_OK);
}

static void TestLogErrorAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_error(NULL, "Logging error with null ctx");
	CuAssert(tc, "Logging should be successful with error level and null context.", res == KSI_OK);
}

static void TestLogBlobWithInfoLevel(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_logBlob(ctx, KSI_LOG_INFO, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should be successful with info level.", res == KSI_OK);
}

static void TestLogBlobWithDebugLevel(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should be successful with debug level.", res == KSI_OK);
}

static void TestLogBlobWithNoticeLevel(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_logBlob(ctx, KSI_LOG_NOTICE, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should be successful with notice level.", res == KSI_OK);
}

static void TestLogBlobWithWarnLevel(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_logBlob(ctx, KSI_LOG_WARN, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should be successful with warn level.", res == KSI_OK);
}

static void TestLogBlobWithErrorLevel(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	KSI_ERR_clearErrors(ctx);

	res = KSI_LOG_logBlob(ctx, KSI_LOG_ERROR, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should be successful with error level.", res == KSI_OK);
}

static void TestLogBlobWithInfoLevelAndCtxNull(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	res = KSI_LOG_logBlob(NULL, KSI_LOG_INFO, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should not be successful with info level and ctx null.", res == KSI_INVALID_ARGUMENT);
}

static void TestLogBlobWithDebugLevelAndCtxNull(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	res = KSI_LOG_logBlob(NULL, KSI_LOG_DEBUG, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should not be successful with debug level and ctx null.", res == KSI_INVALID_ARGUMENT);
}

static void TestLogBlobWithNoticeLevelAndCtxNull(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	res = KSI_LOG_logBlob(NULL, KSI_LOG_NOTICE, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should not be successful with notice level and ctx null.", res == KSI_INVALID_ARGUMENT);
}

static void TestLogBlobWithWarnLevelAndCtxNull(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	res = KSI_LOG_logBlob(NULL, KSI_LOG_WARN, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should not be successful with warn level and ctx null.", res == KSI_INVALID_ARGUMENT);
}

static void TestLogBlobWithErrorLevelAndCtxNull(CuTest *tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	res = KSI_LOG_logBlob(NULL, KSI_LOG_ERROR, raw, "Blob: ", sizeof(raw));
	CuAssert(tc, "Blob logging should not be successful with error level and ctx null.", res == KSI_INVALID_ARGUMENT);
}

static void TestLogTlvInfoLevel(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(ctx, KSI_LOG_INFO, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvDebugLevel(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvNoticeLevel(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(ctx, KSI_LOG_NOTICE, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWarnLevel(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(ctx, KSI_LOG_WARN, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvErrorLevel(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(ctx, KSI_LOG_ERROR, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWithInfoLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(NULL, KSI_LOG_INFO, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful with null ctx.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWithDebugLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(NULL, KSI_LOG_DEBUG, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful with null ctx.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWithNoticeLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(NULL, KSI_LOG_NOTICE, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful with null ctx.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWithWarnLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(NULL, KSI_LOG_WARN, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful with null ctx.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogTlvWithErrorLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_LOG_logTlv(NULL, KSI_LOG_ERROR, "TLV: ", tlv);
	CuAssert(tc, "TLV logging should be successful with null ctx.", res == KSI_OK);

	KSI_TLV_free(tlv);
}

static void TestLogDataHashWithInfoLevel(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(ctx, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with info level.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithDebugLevel(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(ctx, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with debug level.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithNoticeLevel(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(ctx, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with notice level.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithWarnLevel(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(ctx, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with warn level.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithErrorLevel(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(ctx, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with error level.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithInfoLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(NULL, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(NULL, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with info level and ctx null.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithDebugLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(NULL, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(NULL, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with debug level and ctx null.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithNoticeLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(NULL, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(NULL, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with notice level and ctx null.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithWarnLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(NULL, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(NULL, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with warn level and ctx null.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogDataHashWithErrorLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(NULL, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	res = KSI_LOG_logDataHash(NULL, KSI_LOG_INFO, "Hash", hsh);
	CuAssert(tc, "DataHash logging should be successful with error level and ctx null.", res == KSI_OK);

	KSI_DataHash_free(hsh);
}

static void TestLogCtxErrorWithInfoLevel(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 101, 0, NULL, 0, "Info level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_INFO);
	CuAssert(tc, "CTX Error logging should be successful with info level.", res == KSI_OK);
}

static void TestLogCtxErrorWithDebugLevel(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 202, 0, NULL, 0, "Debug level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_DEBUG);
	CuAssert(tc, "CTX Error logging should be successful with debug level.", res == KSI_OK);
}

static void TestLogCtxErrorWithNoticeLevel(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 303, 0, NULL, 0, "Notice level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_NOTICE);
	CuAssert(tc, "CTX Error logging should be successful with notice level.", res == KSI_OK);
}

static void TestLogCtxErrorWithWarnLevel(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 404, 0, NULL, 0, "Warn level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_WARN);
	CuAssert(tc, "CTX Error logging should be successful with warn level.", res == KSI_OK);
}

static void TestLogCtxErrorWithErrorLevel(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 505, 0, NULL, 0, "Error level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_ERROR);
	CuAssert(tc, "CTX Error logging should be successful with error level.", res == KSI_OK);
}

static void TestLogCtxErrorWithInfoLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 101, 0, NULL, 0, "Info level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_INFO);
	CuAssert(tc, "CTX Error logging should be successful with info level.", res == KSI_OK);
}

static void TestLogCtxErrorWithDebugLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 202, 0, NULL, 0, "Debug level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_DEBUG);
	CuAssert(tc, "CTX Error logging should be successful with debug level.", res == KSI_OK);
}

static void TestLogCtxErrorWithNoticeLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 303, 0, NULL, 0, "Notice level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_NOTICE);
	CuAssert(tc, "CTX Error logging should be successful with notice level.", res == KSI_OK);
}

static void TestLogCtxErrorWithWarnLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 404, 0, NULL, 0, "Warn level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_WARN);
	CuAssert(tc, "CTX Error logging should be successful with warn level.", res == KSI_OK);
}

static void TestLogCtxErrorWithErrorLevelAndCtxNull(CuTest *tc) {
	int res;
	KSI_ERR_clearErrors(ctx);

	KSI_ERR_push(ctx, 505, 0, NULL, 0, "Error level");
	res = KSI_LOG_logCtxError(ctx, KSI_LOG_ERROR);
	CuAssert(tc, "CTX Error logging should be successful with error level.", res == KSI_OK);
}

CuSuite* KSITest_Log_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestLogInfo);
	SUITE_ADD_TEST(suite, TestLogDebug);
	SUITE_ADD_TEST(suite, TestLogNotice);
	SUITE_ADD_TEST(suite, TestLogWarn);
	SUITE_ADD_TEST(suite, TestLogError);
	SUITE_ADD_TEST(suite, TestLogInfoAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDebugAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogNoticeAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogWarnAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogErrorAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogBlobWithInfoLevel);
	SUITE_ADD_TEST(suite, TestLogBlobWithDebugLevel);
	SUITE_ADD_TEST(suite, TestLogBlobWithNoticeLevel);
	SUITE_ADD_TEST(suite, TestLogBlobWithWarnLevel);
	SUITE_ADD_TEST(suite, TestLogBlobWithErrorLevel);
	SUITE_ADD_TEST(suite, TestLogBlobWithInfoLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogBlobWithDebugLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogBlobWithNoticeLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogBlobWithWarnLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogBlobWithErrorLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogTlvInfoLevel);
	SUITE_ADD_TEST(suite, TestLogTlvDebugLevel);
	SUITE_ADD_TEST(suite, TestLogTlvNoticeLevel);
	SUITE_ADD_TEST(suite, TestLogTlvWarnLevel);
	SUITE_ADD_TEST(suite, TestLogTlvErrorLevel);
	SUITE_ADD_TEST(suite, TestLogTlvWithInfoLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogTlvWithDebugLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogTlvWithNoticeLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogTlvWithWarnLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogTlvWithErrorLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDataHashWithInfoLevel);
	SUITE_ADD_TEST(suite, TestLogDataHashWithDebugLevel);
	SUITE_ADD_TEST(suite, TestLogDataHashWithNoticeLevel);
	SUITE_ADD_TEST(suite, TestLogDataHashWithWarnLevel);
	SUITE_ADD_TEST(suite, TestLogDataHashWithErrorLevel);
	SUITE_ADD_TEST(suite, TestLogDataHashWithInfoLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDataHashWithDebugLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDataHashWithNoticeLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDataHashWithWarnLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogDataHashWithErrorLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithInfoLevel);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithDebugLevel);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithNoticeLevel);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithWarnLevel);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithErrorLevel);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithInfoLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithDebugLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithNoticeLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithWarnLevelAndCtxNull);
	SUITE_ADD_TEST(suite, TestLogCtxErrorWithErrorLevelAndCtxNull);

	return suite;
}
