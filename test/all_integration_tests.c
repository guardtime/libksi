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

#include<stdio.h>
#include<string.h>
#include<ctype.h>
#include<stdlib.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include "support_tests.h"
#include "ksi/compatibility.h"
#include <ctype.h>

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx = NULL;

static CuSuite* initSuite(void) {
	CuSuite *suite = CuSuiteNew();

	addSuite(suite, AggreIntegrationTests_getSuite);
	addSuite(suite, ExtIntegrationTests_getSuite);

	return suite;
}

static int RunAllTests() {
	int failCount;
	int res;
	CuSuite* suite = initSuite();
	FILE *logFile = NULL;

	/* Create the context. */
	res = KSI_CTX_new(&ctx);
	if (ctx == NULL || res != KSI_OK){
		fprintf(stderr, "Error: Unable to init KSI context (%s)!\n", KSI_getErrorString(res));
		exit(EXIT_FAILURE);
	}

	res = KSI_CTX_setPublicationUrl(ctx, conf.publications_file_url);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file URL.\n");
		exit(EXIT_FAILURE);
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, conf.testPubFileCertConstraints);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file verification constraints.\n");
		exit(EXIT_FAILURE);
	}

	logFile = fopen("integration_test.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		exit(EXIT_FAILURE);
	}

	KSI_CTX_setLoggerCallback(ctx, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ctx, KSI_LOG_DEBUG);

	KSI_CTX_setAggregator(ctx, conf.aggregator_url, conf.aggregator_user, conf.aggregator_pass);
	KSI_CTX_setExtender(ctx, conf.extender_url, conf.extender_user, conf.extender_pass);

	CuSuiteRun(suite);

	printStats(suite, "==== INTEGRATION TEST RESULTS ====");

	writeXmlReport(suite, UNIT_TEST_OUTPUT_XML);

	failCount = suite->failCount;

	CuSuiteDelete(suite);

	if (logFile != NULL) {
		fclose(logFile);
	}

	KSI_CTX_free(ctx);

	return failCount;
}

#define CONF_cpy(name, param, value) \
	if (conf->name[0] == '\0' && strcmp(param, #name) == 0) {\
		KSI_strncpy(conf->name, value, CONF_FIELD_SIZE);\
	}\

static char *string_getBetweenWhitespace(char *strn) {
	char *beginning = strn;
	char *end = NULL;
	unsigned strn_len;

	if (strn == NULL) return NULL;
	strn_len = strlen(strn);
	if (strn_len == 0) return strn;
	end = strn + strn_len - 1;

	/*Replace trailing whitespace with string end characters*/
	while(end != strn && isspace(*end)) {
		*end = '\0';
		end--;
	}

	while(*beginning != '\0' && isspace(*beginning)) beginning++;
	return beginning;
	}

static void conf_append(CONF *conf, const char *param, const char *value) {
	char tmp[CONF_FIELD_SIZE];
	char *equal = NULL;
	char *OID = NULL;
	char *oid_value = NULL;


	CONF_cpy(extender_url, param, value);
	CONF_cpy(extender_pass, param, value);
	CONF_cpy(extender_user, param, value);

	CONF_cpy(aggregator_url, param, value);
	CONF_cpy(aggregator_pass, param, value);
	CONF_cpy(aggregator_user, param, value);

	CONF_cpy(publications_file_url, param, value);

	CONF_cpy(tcp_url, param, value);
	CONF_cpy(tcp_user, param, value);
	CONF_cpy(tcp_pass, param, value);

	if (strcmp(param, "publications_file_cnstr") == 0) {
		if (conf->constraints >= CONF_MAX_CONSTRAINTS) {
			fprintf(stderr, "Error: Publications file constraint count too large. Max is %i\n", CONF_MAX_CONSTRAINTS);
			exit(EXIT_FAILURE);
		}
		KSI_strncpy(tmp, value, sizeof(tmp));
		/*Entry in conf file must contain '='*/
		equal = strchr(tmp, '=');
		if(equal == NULL) {
			fprintf(stderr, "Error: Publications file constraint must have format <oid>=<value>, but is '%s'!\n", value);
			exit(EXIT_FAILURE);
		} else {
			*equal = '\0';
			OID = string_getBetweenWhitespace(tmp);
			oid_value = string_getBetweenWhitespace(equal + 1);

			if(strlen(OID) == 0) {
				fprintf(stderr, "Error: Publications file constraint OID must not be empty string!\n");
				fprintf(stderr, "Error: Invalid entry '%s'\n", value);
				exit(EXIT_FAILURE);
			}

			if(strlen(oid_value) == 0) {
				fprintf(stderr, "Error: Publications file constraint value must not be empty string!\n");
				fprintf(stderr, "Error: Invalid entry '%s'\n", value);
				exit(EXIT_FAILURE);
			}
			KSI_strncpy(conf->oid[conf->constraints], OID, CONF_FIELD_SIZE);
			KSI_strncpy(conf->val[conf->constraints], oid_value, CONF_FIELD_SIZE);

			conf->testPubFileCertConstraints[conf->constraints].oid = conf->oid[conf->constraints];
			conf->testPubFileCertConstraints[conf->constraints].val = conf->val[conf->constraints];
			conf->constraints++;
		}

	}
}

static void conf_clear(CONF *conf) {
	unsigned int i;

	conf->aggregator_url[0] = '\0';
	conf->aggregator_pass[0] = '\0';
	conf->aggregator_user[0] = '\0';
	conf->extender_url[0] = '\0';
	conf->extender_pass[0] = '\0';
	conf->extender_user[0] = '\0';
	conf->publications_file_url[0] = '\0';
	conf->publications_file_cnstr[0] = '\0';
	conf->tcp_url[0] = '\0';
	conf->tcp_pass[0] = '\0';
	conf->tcp_user[0] = '\0';

	conf->constraints = 0;
	for (i = 0; i < CONF_MAX_CONSTRAINTS + 1; i++) {
		conf->testPubFileCertConstraints[i].oid = NULL;
		conf->testPubFileCertConstraints[i].val = NULL;
		if (i < CONF_MAX_CONSTRAINTS) {
			conf->oid[i][0] = '\0';
			conf->val[i][0] = '\0';
		}
	}
}

#define CONF_CONTROL(_conf, _param, _res) \
	if(_conf -> _param [0] == '\0') {\
		fprintf(stderr, "Error: parameter '%s' in conf file must have valeue.\n", #_param);\
		_res = 1; \
	}

static int conf_control(CONF *conf) {
	int res = 0;
	CONF_CONTROL(conf, aggregator_url, res);
	CONF_CONTROL(conf, aggregator_pass, res);
	CONF_CONTROL(conf, aggregator_user, res);
	CONF_CONTROL(conf, extender_url, res);
	CONF_CONTROL(conf, extender_pass, res);
	CONF_CONTROL(conf, extender_user, res);
	CONF_CONTROL(conf, publications_file_url, res);
	CONF_CONTROL(conf, tcp_url, res);
	CONF_CONTROL(conf, tcp_pass, res);
	CONF_CONTROL(conf, tcp_user, res);

	if (conf->constraints == 0) {
		fprintf(stderr, "Error: At least 1 publications file certificate constraint must be defined in conf file.\n");
		res = 1;
	}
	/*Return 1 if conf contains errors*/
	return res;
}

/*Returns 0 if successful, 1 otherwise.*/
static int conf_load(const char *confFile, CONF *conf) {
	int res = 0;
	FILE *file = NULL;
	char tmp[2048];
	char *line = NULL;
	char *ln = NULL;
	char *equal = NULL;
	char *param = NULL;
	char *value = NULL;

	file = fopen(confFile, "r");
	if(file == NULL) {
		fprintf(stderr, "Error: Unable to open conf. file '%s'.\n", confFile);
		res = 1;
		goto cleanup;
	}

	/*Initialize configuration object*/
	conf_clear(conf);

	while(fgets(tmp, sizeof(tmp), file)){
		if ((ln = strchr(tmp, 0x0D)) != NULL) *ln = 0;
		else if ((ln = strchr(tmp, 0x0A)) != NULL) *ln = 0;
		else continue;

		/*Remove whitespace character. If invalid line, continue!*/
		line = string_getBetweenWhitespace(tmp);
		if (line == NULL || line[0] == '\0' || line[0] == '#') continue;

		/*Entry in conf file must contain =*/
		equal = strchr(line, '=');
		if(equal == NULL) {
			/*Its a unknown line, continue!*/
			continue;
		} else {
			*equal = '\0';
			param = string_getBetweenWhitespace(line);
			value = string_getBetweenWhitespace(equal + 1);
			conf_append(conf, param, value);
		}
	}

	res = conf_control(conf);

cleanup:

	return res;
}


/**
 * Configuration object for integration tests.
 */
CONF conf;


int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage:\n %s <path to test root>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	initFullResourcePath(argv[1]);

	if (conf_load(getFullResourcePath("integrationtest.conf"), &conf)) {
		exit(EXIT_FAILURE);
	}


	return RunAllTests();
}
