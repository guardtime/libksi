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

#include "test_conf.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <ksi/compatibility.h>


#define CONF_str_cpy(name, param, value) \
	if (conf->name[0] == '\0' && strcmp(param, #name) == 0) {\
		KSI_strncpy(conf->name, value, CONF_FIELD_SIZE);\
	}

#define CONF_int_set(name, param, value) \
	if (conf->name == 0 && strcmp(param, #name) == 0) {\
		conf->name = atoi(value); \
	}

static char *string_getBetweenWhitespace(char *strn) {
	char *beginning = strn;
	char *end = NULL;
	size_t strn_len;

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

static void conf_append(KSITest_Conf *conf, const char *param, const char *value) {
	char tmp[CONF_FIELD_SIZE];
	char *equal = NULL;
	char *OID = NULL;
	char *oid_value = NULL;


	CONF_str_cpy(extender.host, param, value);
	CONF_str_cpy(extender.pass, param, value);
	CONF_str_cpy(extender.user, param, value);

	CONF_int_set(extender.port, param, value);

	CONF_str_cpy(aggregator.host, param, value);
	CONF_str_cpy(aggregator.pass, param, value);
	CONF_str_cpy(aggregator.user, param, value);

	CONF_int_set(aggregator.port, param, value);

	CONF_str_cpy(publications_file_url, param, value);

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

static void conf_clear(KSITest_Conf *conf) {
	unsigned int i;

	conf->aggregator.host[0] = '\0';
	conf->aggregator.port = 0;
	conf->aggregator.pass[0] = '\0';
	conf->aggregator.user[0] = '\0';

	conf->extender.host[0] = '\0';
	conf->extender.port = 0;
	conf->extender.pass[0] = '\0';
	conf->extender.user[0] = '\0';

	conf->publications_file_url[0] = '\0';
	conf->publications_file_cnstr[0] = '\0';

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

#define CONF_CONTROL_STR(_conf, _param, _res) \
	if(_conf -> _param [0] == '\0') {\
		fprintf(stderr, "Error: parameter '%s' in conf file must have value.\n", #_param);\
		_res = 1; \
	}

#define CONF_CONTROL_INT(_conf, _param, _res) \
	if(_conf -> _param == 0) {\
		fprintf(stderr, "Error: parameter '%s' in conf file must have value (not 0).\n", #_param);\
		_res = 1; \
	}

static int conf_control(KSITest_Conf *conf) {
	int res = 0;

	CONF_CONTROL_STR(conf, aggregator.host, res);
	CONF_CONTROL_STR(conf, aggregator.pass, res);
	CONF_CONTROL_STR(conf, aggregator.user, res);
	CONF_CONTROL_INT(conf, aggregator.port, res);

	CONF_CONTROL_STR(conf, extender.host, res);
	CONF_CONTROL_STR(conf, extender.pass, res);
	CONF_CONTROL_STR(conf, extender.user, res);
	CONF_CONTROL_INT(conf, extender.port, res);

	CONF_CONTROL_STR(conf, publications_file_url, res);

	if (conf->constraints == 0) {
		fprintf(stderr, "Error: At least 1 publications file certificate constraint must be defined in conf file.\n");
		res = 1;
	}
	/*Return 1 if conf contains errors*/
	return res;
}

int KSITest_Conf_load(const char *confFile, KSITest_Conf *conf) {
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
