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

#include <stdio.h>
#include <string.h>

#include <ksi/ksi.h>
#include <ksi/net_http.h>
#include <ksi/compatibility.h>

#define REQUESTS 10

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res = KSI_UNKNOWN_ERROR;

	KSI_DataHash *hsh = NULL;
	KSI_RequestHandle *handle[REQUESTS];
	KSI_NetworkClient *http = NULL;

	FILE *logFile = NULL;

	size_t i;

	KSI_DataHasher *hsr = NULL;

	struct {
		size_t ok;
		size_t nok;
	} stat;

	stat.ok = 0;
	stat.nok = 0;


	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};


	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	logFile = fopen("multi_curl.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Check publications file url. */
	res = KSI_CTX_setPublicationUrl(ksi, "http://verify.guardtime.com/ksi-publications.bin");
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

	res = KSI_HttpClient_new(ksi, &http);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create http client.\n");
		goto cleanup;
	}

	res = KSI_HttpClient_setAggregator(http, "http://ksigw.test.guardtime.com:3332", "anon", "anon");
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set aggregator url.\n");
		goto cleanup;
	}

	KSI_HttpClient_setReadTimeoutSeconds(http, 10);
	KSI_HttpClient_setConnectTimeoutSeconds(http, 10);

	for (i = 0; i < REQUESTS; i++) {
		char buf[100];
		size_t len;
		KSI_AggregationReq *req = NULL;

		len = KSI_snprintf(buf, sizeof(buf), "Hello %d", i);
		res = KSI_DataHash_create(ksi, buf, len, KSI_getHashAlgorithmByName("default"), &hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to create hash.");
			goto cleanup;
		}

		res = KSI_AggregationReq_new(ksi, &req);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to create request.");
			goto cleanup;
		}

		res = KSI_AggregationReq_setRequestHash(req, hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to set request hash.");
			goto cleanup;
		}

		res = KSI_NetworkClient_sendSignRequest(http, req, &handle[i]);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to send aggregation request.");
			goto cleanup;
		}

		KSI_AggregationReq_free(req);
	}

	res = KSI_NetworkClient_performAll(http, handle, REQUESTS);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to perform requests.");
		goto cleanup;
	}

	for (i = 0; i < REQUESTS; i++) {
		KSI_AggregationResp *resp = NULL;
		res = KSI_RequestHandle_getAggregationResponse(handle[i], &resp);
		if (res != KSI_OK) {
			const KSI_RequestHandleStatus *st = NULL;
			res = KSI_RequestHandle_getResponseStatus(handle[i], &st);
			if (res == KSI_OK) {
				printf("Status code = %ld: %s\n", st->code, st->errm);
			}

			KSI_ERR_statusDump(ksi, stdout);
			stat.nok++;
		} else {
			stat.ok ++;
		}

		KSI_AggregationResp_free(resp);
	}

	printf("Requests:\n"
			"  Successful: %llu\n"
			"      Failed: %llu\n"
			"       TOTAL: %llu\n", (unsigned long long)stat.ok, (unsigned long long)stat.nok, (unsigned long long)(stat.ok + stat.nok));

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_CTX_free(ksi);

	return res;

}
