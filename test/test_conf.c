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

#include "test_conf.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <ksi/compatibility.h>

#define isParam(name, param) (strcmp(param, name) == 0)

#define CONF_str_cpy(name, param, value) \
	if (conf->name[0] == '\0' && isParam(param, #name)) {\
		KSI_strncpy(conf->name, value, CONF_FIELD_SIZE);\
	}

#define CONF_arr_str_cpy(name, pos, max, param, value) \
	if (pos >= max) {\
		fprintf(stderr, "Error: Parameter '%s' count too large. Max is %i.\n", #name, max); \
		exit(EXIT_FAILURE);\
	}\
	if (conf->name[pos][0] == '\0' && isParam(param, #name)) {\
		KSI_strncpy(conf->name[pos], value, CONF_FIELD_SIZE);\
	}

#define CONF_int_set(name, param, value) \
	if (conf->name == 0 && isParam(param, #name)) {\
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

	/* Replace trailing whitespace with string end characters. */
	while(end != strn && isspace(*end)) {
		*end = '\0';
		end--;
	}

	while(*beginning != '\0' && isspace(*beginning)) beginning++;
	return beginning;
}

static void parseConstraint(KSITest_PubfileConf *conf, unsigned at, const char *value) {
	char *equal = NULL;

	/* Entry in conf file must contain '='. */
	equal = strchr(conf->cnstr[at], '=');
	if(equal == NULL) {
		fprintf(stderr, "Error: Publications file constraint must have format <oid>=<value>, but is '%s'!\n", value);
		exit(EXIT_FAILURE);
	} else {
		char *oid = NULL;
		char *val = NULL;

		*equal = '\0';
		oid = string_getBetweenWhitespace(conf->cnstr[at]);
		val = string_getBetweenWhitespace(equal + 1);

		if (strlen(oid) == 0) {
			fprintf(stderr, "Error: Publications file constraint OID must not be empty string!\n");
			fprintf(stderr, "Error: Invalid entry '%s'.\n", value);
			exit(EXIT_FAILURE);
		}

		if (strlen(val) == 0) {
			fprintf(stderr, "Error: Publications file constraint value must not be empty string!\n");
			fprintf(stderr, "Error: Invalid entry '%s'.\n", value);
			exit(EXIT_FAILURE);
		}

		conf->certConstraints[at].oid = oid;
		conf->certConstraints[at].val = val;
	}
}

static void conf_append(KSITest_Conf *conf, const char *param, const char *value) {

	/* Parse extender configuration. */
	CONF_str_cpy(extender.host, param, value);
	CONF_int_set(extender.port, param, value);
	CONF_str_cpy(extender.pass, param, value);
	CONF_str_cpy(extender.user, param, value);
	CONF_str_cpy(extender.hmac, param, value);

	/* HA Service conf. */
	CONF_str_cpy(ha.extender[0].host, param, value);
	CONF_int_set(ha.extender[0].port, param, value);
	CONF_str_cpy(ha.extender[0].pass, param, value);
	CONF_str_cpy(ha.extender[0].user, param, value);
	CONF_str_cpy(ha.extender[0].hmac, param, value);

	CONF_str_cpy(ha.extender[1].host, param, value);
	CONF_int_set(ha.extender[1].port, param, value);
	CONF_str_cpy(ha.extender[1].pass, param, value);
	CONF_str_cpy(ha.extender[1].user, param, value);
	CONF_str_cpy(ha.extender[1].hmac, param, value);

	CONF_str_cpy(ha.extender[2].host, param, value);
	CONF_int_set(ha.extender[2].port, param, value);
	CONF_str_cpy(ha.extender[2].pass, param, value);
	CONF_str_cpy(ha.extender[2].user, param, value);
	CONF_str_cpy(ha.extender[2].hmac, param, value);



	/* Parse aggregator configuration. */
	CONF_str_cpy(aggregator.host, param, value);
	CONF_int_set(aggregator.port, param, value);
	CONF_str_cpy(aggregator.pass, param, value);
	CONF_str_cpy(aggregator.user, param, value);
	CONF_str_cpy(aggregator.hmac, param, value);

	/* HA Service conf. */
	CONF_str_cpy(ha.aggregator[0].host, param, value);
	CONF_int_set(ha.aggregator[0].port, param, value);
	CONF_str_cpy(ha.aggregator[0].pass, param, value);
	CONF_str_cpy(ha.aggregator[0].user, param, value);
	CONF_str_cpy(ha.aggregator[0].hmac, param, value);

	CONF_str_cpy(ha.aggregator[1].host, param, value);
	CONF_int_set(ha.aggregator[1].port, param, value);
	CONF_str_cpy(ha.aggregator[1].pass, param, value);
	CONF_str_cpy(ha.aggregator[1].user, param, value);
	CONF_str_cpy(ha.aggregator[1].hmac, param, value);

	CONF_str_cpy(ha.aggregator[2].host, param, value);
	CONF_int_set(ha.aggregator[2].port, param, value);
	CONF_str_cpy(ha.aggregator[2].pass, param, value);
	CONF_str_cpy(ha.aggregator[2].user, param, value);
	CONF_str_cpy(ha.aggregator[2].hmac, param, value);



	/* Parse publications file configuration. */
	CONF_str_cpy(pubfile.url, param, value);
	CONF_arr_str_cpy(pubfile.cnstr, conf->pubfile.cnstrCount, CONF_MAX_CONSTRAINTS, param, value);

	CONF_int_set(async.timeout.sleep, param, value);
	CONF_int_set(async.timeout.cumulative, param, value);

	if (isParam(param, "pubfile.cnstr") && conf->pubfile.cnstr[conf->pubfile.cnstrCount] != NULL) {
		parseConstraint(&conf->pubfile, conf->pubfile.cnstrCount, value);
		conf->pubfile.cnstrCount++;
	}
}

static void conf_clear(KSITest_Conf *conf) {
	memset(conf, 0, sizeof(KSITest_Conf));
}

#define CONF_CONTROL_STR(_conf, _param, _res) \
	if(_conf -> _param [0] == '\0') {\
		fprintf(stderr, "Error: parameter '%s' in conf file must have value.\n", #_param);\
		_res = 1; \
	}

#define CONF_CONTROL_INT(_conf, _param, _res, _ctrl_val) \
	if(_conf -> _param == (_ctrl_val)) {\
		fprintf(stderr, "Error: parameter '%s' in conf file must have value (not %d).\n", #_param, (_ctrl_val));\
		_res = 1; \
	}

#define CONF_CONTROL_CNT(_conf, _param, _res, _ctrl_cnt, msg) \
	if(_conf -> _param == (_ctrl_cnt)) {\
		fprintf(stderr, msg);\
		_res = 1; \
	}

static int conf_control(KSITest_Conf *conf) {
	int res = 0;

	CONF_CONTROL_STR(conf, aggregator.host, res);
	CONF_CONTROL_STR(conf, aggregator.pass, res);
	CONF_CONTROL_STR(conf, aggregator.user, res);
	CONF_CONTROL_INT(conf, aggregator.port, res, 0);
	/* Optional values:
	 * - aggregator.hmac
	 * - ha.aggregator[].*
	 */

	CONF_CONTROL_STR(conf, extender.host, res);
	CONF_CONTROL_STR(conf, extender.pass, res);
	CONF_CONTROL_STR(conf, extender.user, res);
	CONF_CONTROL_INT(conf, extender.port, res, 0);
	/* Optional values:
	 * - extender.hmac
	 * - ha.extender[].*
	 */

	CONF_CONTROL_STR(conf, pubfile.url, res);
	CONF_CONTROL_CNT(conf, pubfile.cnstrCount, res, 0, "Error: At least 1 publications file certificate constraint must be defined in conf file.\n");

	/* Optional values: */
	/*
	CONF_CONTROL_INT(conf, async.timeout.sleep, res, 0);
	CONF_CONTROL_INT(conf, async.timeout.cumulative, res, 0);
	*/

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

	/* Initialize configuration object. */
	conf_clear(conf);

	while(fgets(tmp, sizeof(tmp), file)){
		if ((ln = strchr(tmp, 0x0D)) != NULL) *ln = 0;
		else if ((ln = strchr(tmp, 0x0A)) != NULL) *ln = 0;
		else continue;

		/* Remove whitespace character. If invalid line, continue! */
		line = string_getBetweenWhitespace(tmp);
		if (line == NULL || line[0] == '\0' || line[0] == '#') continue;

		/* Entry in conf file must contain '='. */
		equal = strchr(line, '=');
		if(equal == NULL) {
			/* Its a unknown line, continue! */
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
