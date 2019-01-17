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

#include "net_ha.h"

#include <string.h>

#include "net.h"
#include "net_async.h"
#include "tlv.h"
#include "impl/ctx_impl.h"
#include "impl/net_async_impl.h"


#define MAX(x, y) (((x) > (y)) ? (x) : (y))

typedef struct KSI_HighAvailabilityRequest_st KSI_HighAvailabilityRequest;


static void KSI_HighAvailabilityRequest_free(KSI_HighAvailabilityRequest *o) {
	if (o != NULL && --o->ref == 0) {
		KSI_AsyncHandle_free(o->asyncHandle);

		KSI_free(o);
	}
}

static int KSI_HighAvailabilityRequest_new(KSI_CTX *ctx, KSI_AsyncHandle *asyncHandle, KSI_HighAvailabilityRequest **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityRequest *tmp = NULL;

	if (ctx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_HighAvailabilityRequest);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;

	tmp->asyncHandle = asyncHandle;
	tmp->expectedRespCount = 0;
	tmp->hasReq = false;
	tmp->hasCnf = false;

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_HighAvailabilityRequest_free(tmp);
	return res;
}

static KSI_IMPLEMENT_REF(KSI_HighAvailabilityRequest)

static int KSI_HighAvailabilityService_addRequest(KSI_HighAvailabilityService *has, KSI_AsyncHandle *handle){
	int res = KSI_UNKNOWN_ERROR;
	int addRes = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_AsyncHandle *tmp = NULL;
	KSI_AsyncHandle *hndlRef = NULL;
	bool added = false;
	KSI_HighAvailabilityRequest *haRequest = NULL;

	if (has == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	/* The HA request object acts as a wrapper to the original async request. */
	res = KSI_HighAvailabilityRequest_new(has->ctx, (hndlRef = KSI_AsyncHandle_ref(handle)), &haRequest);
	if (res != KSI_OK) {
		KSI_AsyncHandle_free(hndlRef);
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	if (handle->aggrReq != NULL) {
		KSI_DataHash *reqHash = NULL;
		KSI_Config *reqConf = NULL;

		res = KSI_AggregationReq_getRequestHash(handle->aggrReq, &reqHash);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		haRequest->hasReq = (reqHash != NULL);

		res = KSI_AggregationReq_getConfig(handle->aggrReq, &reqConf);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		haRequest->hasCnf = (reqConf != NULL);
	}

	if (handle->extReq != NULL) {
		KSI_Integer *reqTime = NULL;
		KSI_Config *reqConf = NULL;

		res = KSI_ExtendReq_getAggregationTime(handle->extReq, &reqTime);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		haRequest->hasReq = (reqTime != NULL);

		res = KSI_ExtendReq_getConfig(handle->extReq, &reqConf);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		haRequest->hasCnf = (reqConf != NULL);
	}

	for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
		KSI_AsyncService *as = NULL;
		KSI_HighAvailabilityRequest *haReqRef = NULL;

		/* Create a new async handle to be passed to the subservice. */
		res = KSI_AbstractAsyncHandle_new(has->ctx, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		/* Clone the original request and copy additional request data. */
		if (handle->aggrReq != NULL) {
			res = KSI_AggregationReq_clone(handle->aggrReq, &tmp->aggrReq);
			if (res != KSI_OK) {
				KSI_pushError(has->ctx, res, NULL);
				goto cleanup;
			}
		}
		if (handle->extReq != NULL) {
			res = KSI_ExtendReq_clone(handle->extReq, &tmp->extReq);
			if (res != KSI_OK) {
				KSI_pushError(has->ctx, res, NULL);
				goto cleanup;
			}
			/* Not necessary, but copy anyway. */
			tmp->signature = handle->signature;
			tmp->pubRec = handle->pubRec;
		}

		res = KSI_AsyncHandle_setRequestCtx(tmp,
				(void *)(haReqRef = KSI_HighAvailabilityRequest_ref(haRequest)),
				(void (*)(void*))KSI_HighAvailabilityRequest_free);
		if (res != KSI_OK) {
			KSI_HighAvailabilityRequest_free(haReqRef);
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		/* Add the newly created async handle to the subservice request queue. */
		KSI_ERR_clearErrors(has->ctx);
		addRes = KSI_AsyncService_addRequest(as, tmp);
		if (addRes != KSI_OK) {
			KSI_pushError(has->ctx, addRes, NULL);
			KSI_LOG_debug(has->ctx, "Request rejected by sub-service %d.", (int)i);
			KSI_LOG_logCtxError(has->ctx, KSI_LOG_DEBUG);

			KSI_AsyncHandle_free(tmp);
			tmp = NULL;
			/* Try to add the original request to the next async service. */
			continue;
		}
		/* The request handle was succesfully added to the async service. */
		haRequest->expectedRespCount++;
		tmp = NULL;
		added = true;
	}
	/* If all clients have failed to accept the request, then fail with the returned error. */
	if (added == false) {
		KSI_LOG_debug(has->ctx, "Request rejected by all sub-service.");
		res = addRes;
		goto cleanup;
	}
	handle->state = KSI_ASYNC_STATE_WAITING_FOR_RESPONSE;

	res = KSI_OK;
cleanup:
	/* In case of an error do not take ownership of the original handle. */
	if (res == KSI_OK) KSI_AsyncHandle_free(handle);
	KSI_HighAvailabilityRequest_free(haRequest);
	KSI_AsyncHandle_free(tmp);
	return res;
}

#define KSI_HA_CONF_MAX_LEVEL 20
#define KSI_HA_CONF_MIN_PERIOD_MS 100
#define KSI_HA_CONF_MAX_PERIOD_MS (20 * 1000)
#define KSI_HA_CONF_MAX_REQUESTS 16000
#define KSI_HA_CONF_CALENDAR_BEGIN 1136073600

static bool isMaxLevelValid(KSI_uint64_t val) {
	/* Values under 1 and over 20 are discarded. */
	return (val > 0 || val <= KSI_HA_CONF_MAX_LEVEL);
}

static bool isAggrAlgoValid(KSI_uint64_t val) {
	/* Unknown values are discarded. */
	return !!KSI_isHashAlgorithmTrusted((KSI_HashAlgorithm)val);
}

static bool isAggrPeriodValid(KSI_uint64_t val) {
	/* Values under 0.1 and over 20 seconds are discarded. */
	return (val > KSI_HA_CONF_MIN_PERIOD_MS || val <= KSI_HA_CONF_MAX_PERIOD_MS);
}

static bool isMaxRequestsValid(KSI_uint64_t val) {
	/* Values under 1 and over 16000 are discarded. */
	return (val > 0 || val <= KSI_HA_CONF_MAX_REQUESTS);
}

static bool isCalendarTimeValid(KSI_uint64_t val) {
	/* Values before year 2006 are discarded. */
	return (val >= KSI_HA_CONF_CALENDAR_BEGIN);
}

static int KSI_Config_consolidateMaxLevel(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getMaxLevel(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getMaxLevel(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (respVal == NULL || KSI_Integer_getUInt64(respVal) == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	if (isMaxLevelValid(KSI_Integer_getUInt64(respVal)) != true) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The max level value is not in the valid range (%llu).",
				(unsigned long long)KSI_Integer_getUInt64(respVal));
		res = KSI_OK;
		goto cleanup;
	}

	/* The largest value should be taken. */
	if (KSI_Integer_compare(haVal, respVal) < 0) {
		res = KSI_Config_setMaxLevel(haCfg, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);

		res = KSI_Config_setMaxLevel(respCfg, NULL);
		if (res != KSI_OK) goto cleanup;

		*updated = true;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateAggrAlgo(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getAggrAlgo(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getAggrAlgo(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	/* Any non-null is preferred to null. */
	if (respVal == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	if (isAggrAlgoValid(KSI_Integer_getUInt64(respVal)) == false) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The aggregation algorithm value is not valid (%s).",
				KSI_getHashAlgorithmName((KSI_HashAlgorithm)KSI_Integer_getUInt64(respVal)));
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_Config_setAggrAlgo(haCfg, respVal);
	if (res != KSI_OK) goto cleanup;
	KSI_Integer_free(haVal);

	res = KSI_Config_setAggrAlgo(respCfg, NULL);
	if (res != KSI_OK) goto cleanup;

	*updated = true;

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateAggrPeriod(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getAggrPeriod(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getAggrPeriod(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (respVal == NULL || KSI_Integer_getUInt64(respVal) == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	if (isAggrPeriodValid(KSI_Integer_getUInt64(respVal)) != true) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The aggregation period value is not in the valid range (%llu).",
				(unsigned long long)KSI_Integer_getUInt64(respVal));
		res = KSI_OK;
		goto cleanup;
	}

	/* The smallest value should be taken. */
	if (KSI_Integer_getUInt64(haVal) == 0 || KSI_Integer_compare(haVal, respVal) > 0) {
		res = KSI_Config_setAggrPeriod(haCfg, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);

		res = KSI_Config_setAggrPeriod(respCfg, NULL);
		if (res != KSI_OK) goto cleanup;

		*updated = true;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateMaxRequests(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getMaxRequests(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getMaxRequests(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (respVal == NULL || KSI_Integer_getUInt64(respVal) == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	if (isMaxRequestsValid(KSI_Integer_getUInt64(respVal)) != true) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The max requests count is not in the valid range (%llu).",
				(unsigned long long)KSI_Integer_getUInt64(respVal));
		res = KSI_OK;
		goto cleanup;
	}

	/* The largest value should be taken. */
	if (KSI_Integer_compare(haVal, respVal) < 0) {
		res = KSI_Config_setMaxRequests(haCfg, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);

		res = KSI_Config_setMaxRequests(respCfg, NULL);
		if (res != KSI_OK) goto cleanup;

		*updated = true;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateCalendarFirstTime(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getCalendarFirstTime(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getCalendarFirstTime(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (respVal == NULL || KSI_Integer_getUInt64(respVal) == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	if (isCalendarTimeValid(KSI_Integer_getUInt64(respVal)) != true) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The calendar first time is not in the valid range (%llu).",
				(unsigned long long)KSI_Integer_getUInt64(respVal));
		res = KSI_OK;
		goto cleanup;
	}

	/* The earliest value should be taken. */
	if (KSI_Integer_getUInt64(haVal) == 0 || KSI_Integer_compare(haVal, respVal) > 0) {
		res = KSI_Config_setCalendarFirstTime(haCfg, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);

		res = KSI_Config_setCalendarFirstTime(respCfg, NULL);
		if (res != KSI_OK) goto cleanup;

		*updated = true;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateCalendarLastTime(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;
	KSI_Integer *haValFirst = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getCalendarLastTime(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getCalendarLastTime(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (respVal == NULL || KSI_Integer_getUInt64(respVal) == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_Config_getCalendarFirstTime(haCfg, &haValFirst);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_compare(haValFirst, respVal) > 0 && isCalendarTimeValid(KSI_Integer_getUInt64(respVal)) != true) {
		KSI_LOG_info(KSI_Config_getCtx(haCfg), "The calendar last time is not in the valid range (%llu).",
				(unsigned long long)KSI_Integer_getUInt64(respVal));
		res = KSI_OK;
		goto cleanup;
	}

	/* The latest value should be taken. */
	if (KSI_Integer_compare(haVal, respVal) < 0) {
		res = KSI_Config_setCalendarLastTime(haCfg, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);

		res = KSI_Config_setCalendarLastTime(respCfg, NULL);
		if (res != KSI_OK) goto cleanup;

		*updated = true;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_Config_consolidateParentUri(KSI_Config *haCfg, KSI_Config *respCfg, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Utf8StringList *haVal = NULL;
	KSI_Utf8StringList *respVal = NULL;

	if (haCfg == NULL || respCfg == NULL || updated == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Config_getParentUri(haCfg, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getParentUri(respCfg, &respVal);
	if (res != KSI_OK) goto cleanup;

	/* Any non-null is preferred to null. */
	if (respVal == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_Config_setParentUri(haCfg, respVal);
	if (res != KSI_OK) goto cleanup;
	KSI_Utf8StringList_free(haVal);

	res = KSI_Config_setParentUri(respCfg, NULL);
	if (res != KSI_OK) goto cleanup;

	*updated = true;

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_consolidateConfig(KSI_HighAvailabilityService *has, KSI_Config *config, bool *updated) {
	int res = KSI_UNKNOWN_ERROR;
	bool changed = false;

	if (has == NULL || config == NULL || updated  == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (has->consolidatedConfig == NULL) {
		res = KSI_Config_new(has->ctx, &has->consolidatedConfig);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_Config_consolidateMaxLevel(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateAggrAlgo(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateAggrPeriod(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateMaxRequests(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateCalendarFirstTime(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateCalendarLastTime(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_Config_consolidateParentUri(has->consolidatedConfig, config, &changed);
	if (res != KSI_OK) goto cleanup;
	*updated |= changed;

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_getPendingCount(KSI_HighAvailabilityService *has, size_t *count) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i = 0;
	size_t pending = 0;

	if (has == NULL || count == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
		KSI_AsyncService *as = NULL;
		size_t srvPending = 0;

		res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AsyncService_getPendingCount(as, &srvPending);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		pending = MAX(pending, srvPending);
	}
	*count = pending;

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_getReceivedCount(KSI_HighAvailabilityService *has, size_t *count) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i = 0;
	size_t received = 0;

	if (has == NULL || count == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
		KSI_AsyncService *as = NULL;
		size_t srvReceived = 0;

		res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AsyncService_getReceivedCount(as, &srvReceived);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		received = MAX(received, srvReceived);
	}
	*count = received + KSI_AsyncHandleList_length(has->respQueue);

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_reportErrorNotice(KSI_HighAvailabilityService *has,
		KSI_AsyncHandle *reqHndl, size_t origin,
		int err, long errExt, KSI_Utf8String *errMsg) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *noticeHandle = NULL;
	KSI_AsyncHandle *ref = NULL;

	if (has == NULL || reqHndl == NULL || err == KSI_OK) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	res = KSI_AbstractAsyncHandle_new(has->ctx, &noticeHandle);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}
	noticeHandle->state = KSI_ASYNC_STATE_ERROR_NOTICE;
	noticeHandle->err = err;
	noticeHandle->errExt = errExt;
	noticeHandle->errMsg = KSI_Utf8String_ref(errMsg);

	noticeHandle->parentId = origin;

	res = KSI_AsyncHandle_setRequestCtx(noticeHandle,
			(void*)(ref = KSI_AsyncHandle_ref(reqHndl)), (void (*)(void*))KSI_AsyncHandle_free);
	if (res != KSI_OK) {
		KSI_AsyncHandle_free(ref);
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AsyncHandleList_append(has->respQueue, noticeHandle);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}
	noticeHandle = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncHandle_free(noticeHandle);

	return res;
}

static int handleConfigResponse(KSI_HighAvailabilityService *has, KSI_AsyncService *from,
		KSI_AsyncHandle *respHndl,	KSI_Config_Callback confCallback) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityRequest *haRequest = NULL;
	KSI_Config *pushConf = NULL;
	bool updated = false;

	if (has == NULL || respHndl == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	res = KSI_AsyncHandle_getRequestCtx(respHndl, (const void **)&haRequest);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}
	if (haRequest != NULL) {
		KSI_AsyncHandle *reqHndl = NULL;
		int reqState = KSI_ASYNC_STATE_UNDEFINED;

		haRequest->expectedRespCount--;
		reqHndl = haRequest->asyncHandle;

		res = KSI_AsyncHandle_getState(reqHndl, &reqState);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		/* Clear error response, if it has been received from any subservice. */
		if (haRequest->hasReq == false && reqState == KSI_ASYNC_STATE_ERROR) {
			/* First report an error notice. */
			res = KSI_HighAvailabilityService_reportErrorNotice(has, reqHndl, reqHndl->parentId,
					reqHndl->err, reqHndl->errExt, reqHndl->errMsg);
			if (res != KSI_OK) {
				KSI_pushError(has->ctx, res, NULL);
				goto cleanup;
			}
			/* Clear the error from the handle. */
			reqHndl->err = KSI_OK;
			reqHndl->errExt = 0L;
			KSI_Utf8String_free(reqHndl->errMsg);
			reqHndl->errMsg = NULL;
		}
	}

	res = KSI_AsyncHandle_getConfig(respHndl, &pushConf);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	/* Check if user config consolidation callback is configured. */
	if (has->confConsolidateCallback != NULL) {
		size_t id = 0;
		void *userp = NULL;

		res = KSI_AsyncService_getOption(from, KSI_ASYNC_PRIVOPT_ENDPOINT_ID, &id);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AsyncService_getOption(from, KSI_ASYNC_OPT_CALLBACK_USERDATA, &userp);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		res = has->confConsolidateCallback(has->ctx, id, userp, has->consolidatedConfig, pushConf);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, "HA config consolidate callback returned error.");
			goto cleanup;
		}
	} else {
		res = KSI_HighAvailabilityService_consolidateConfig(has, pushConf, &updated);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		if (updated == false) goto cleanup;
	}

	if (confCallback) {
		res = confCallback(has->ctx, has->consolidatedConfig);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, "KSI conf callback returned error.");
			goto cleanup;
		}
	} else {
		KSI_AsyncHandle *hndlRef = NULL;

		/* Renew the config. */
		respHndl->respCtx_free(respHndl->respCtx);
		respHndl->respCtx = (void*)KSI_Config_ref(has->consolidatedConfig);
		respHndl->respCtx_free = (void (*)(void*))KSI_Config_free;

		res = KSI_AsyncHandleList_append(has->respQueue, (hndlRef = KSI_AsyncHandle_ref(respHndl)));
		if (res != KSI_OK) {
			KSI_AsyncHandle_free(hndlRef);
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int handleReqResponse(KSI_HighAvailabilityService *has, KSI_AsyncHandle *respHndl) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityRequest *haRequest = NULL;
	KSI_AsyncHandle *reqHndl = NULL;
	int reqState = KSI_ASYNC_STATE_UNDEFINED;

	if (has == NULL || respHndl == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	res = KSI_AsyncHandle_getRequestCtx(respHndl, (const void **)&haRequest);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}
	if (haRequest == NULL) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}
	haRequest->expectedRespCount--;
	reqHndl = haRequest->asyncHandle;

	res = KSI_AsyncHandle_getState(reqHndl, &reqState);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	/* Report currently set error. */
	if (reqState == KSI_ASYNC_STATE_ERROR) {
		res = KSI_HighAvailabilityService_reportErrorNotice(has, reqHndl, reqHndl->parentId,
				reqHndl->err, reqHndl->errExt, reqHndl->errMsg);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Update request handle. */
	if (reqState == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE || reqState == KSI_ASYNC_STATE_ERROR) {
		KSI_AsyncHandle *hndlRef = NULL;

		/* Clear error response, if it has been received from any subservice. */
		if (reqState == KSI_ASYNC_STATE_ERROR) {
			reqHndl->err = KSI_OK;
			reqHndl->errExt = 0L;
			KSI_Utf8String_free(reqHndl->errMsg);
			reqHndl->errMsg = NULL;
		}

		/* Update handle state. */
		reqHndl->state = KSI_ASYNC_STATE_RESPONSE_RECEIVED;

		/* Update transfer times. */
		reqHndl->rcvTime = respHndl->rcvTime;
		reqHndl->reqTime = respHndl->reqTime;
		reqHndl->sndTime = respHndl->sndTime;

		/* Set response context. */
		reqHndl->respCtx = respHndl->respCtx;
		respHndl->respCtx = NULL;
		reqHndl->respCtx_free = respHndl->respCtx_free;
		respHndl->respCtx_free = NULL;

		reqHndl->parentId = respHndl->parentId;

		res = KSI_AsyncHandleList_append(has->respQueue, (hndlRef = KSI_AsyncHandle_ref(reqHndl)));
		if (res != KSI_OK) {
			KSI_AsyncHandle_free(hndlRef);
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int handleErrorResponse(KSI_HighAvailabilityService *has, KSI_AsyncHandle *respHndl) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityRequest *haRequest = NULL;
	KSI_AsyncHandle *reqHndl = NULL;
	int reqState = KSI_ASYNC_STATE_UNDEFINED;

	if (has == NULL || respHndl == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	res = KSI_AsyncHandle_getRequestCtx(respHndl, (const void **)&haRequest);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}
	if (haRequest == NULL) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}
	haRequest->expectedRespCount--;
	reqHndl = haRequest->asyncHandle;

	res = KSI_AsyncHandle_getState(reqHndl, &reqState);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	/* Only set the error in case there have been no responses received yet. Otherwise report error notice. */
	if (reqState == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
		reqState = KSI_ASYNC_STATE_ERROR;

		reqHndl->state = reqState;
		reqHndl->err = respHndl->err;
		reqHndl->errExt = respHndl->errExt;
		reqHndl->errMsg = KSI_Utf8String_ref(respHndl->errMsg);
		reqHndl->parentId = respHndl->parentId;
	} else {
		res = KSI_HighAvailabilityService_reportErrorNotice(has, reqHndl, respHndl->parentId,
				respHndl->err, respHndl->errExt, respHndl->errMsg);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* In case all of the relevant subservices have returned an error,
	 * move the request to the response queue. */
	if (reqState == KSI_ASYNC_STATE_ERROR && haRequest->expectedRespCount == 0) {
		KSI_AsyncHandle *hndlRef = NULL;

		res = KSI_AsyncHandleList_append(has->respQueue, (hndlRef = KSI_AsyncHandle_ref(reqHndl)));
		if (res != KSI_OK) {
			KSI_AsyncHandle_free(hndlRef);
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int responseHandler(KSI_HighAvailabilityService *has, KSI_Config_Callback confCallback) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *respHndl = NULL;
	size_t i = 0;

	if (has == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
		KSI_AsyncService *as = NULL;
		int respState = KSI_ASYNC_STATE_UNDEFINED;

		res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		KSI_ERR_clearErrors(has->ctx);

		respHndl = NULL;
		res = KSI_AsyncService_run(as, &respHndl, NULL);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		if (respHndl == NULL) continue;

		res = KSI_AsyncHandle_getState(respHndl, &respState);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}

		switch (respState) {
			case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED:
				handleConfigResponse(has, as, respHndl, confCallback);
				break;

			case KSI_ASYNC_STATE_RESPONSE_RECEIVED:
				handleReqResponse(has, respHndl);
				break;

			case KSI_ASYNC_STATE_ERROR:
				handleErrorResponse(has, respHndl);
				break;

			default:
				/* Do nothing! */
				break;
		}

		KSI_AsyncHandle_free(respHndl);
		respHndl = NULL;
	}

	res = KSI_OK;
cleanup:
	KSI_AsyncHandle_free(respHndl);
	return res;
}

static int KSI_HighAvailabilityService_aggrRespHandler(KSI_HighAvailabilityService *has) {
	return responseHandler(has, (has->confCallback != NULL ? has->confCallback :
			(KSI_Config_Callback)has->ctx->options[KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK]));
}

static int KSI_HighAvailabilityService_extRespHandler(KSI_HighAvailabilityService *has) {
	return responseHandler(has, (has->confCallback != NULL ? has->confCallback :
			(KSI_Config_Callback)has->ctx->options[KSI_OPT_EXT_CONF_RECEIVED_CALLBACK]));
}

static int KSI_HighAvailabilityService_run(KSI_HighAvailabilityService *has,
		int (*respHandler)(KSI_HighAvailabilityService *), KSI_AsyncHandle **handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;

	if (has == NULL || respHandler == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	res = respHandler(has);
	if (res != KSI_OK) {
		KSI_pushError(has->ctx, res, NULL);
		goto cleanup;
	}

	if (handle != NULL && KSI_AsyncHandleList_length(has->respQueue) > 0) {
		res = KSI_AsyncHandleList_remove(has->respQueue, 0, handle);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
	}
	if (waiting != NULL) {
		size_t pending = 0;
		size_t received = 0;
		res = KSI_HighAvailabilityService_getPendingCount(has, &pending);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_HighAvailabilityService_getReceivedCount(has, &received);
		if (res != KSI_OK) {
			KSI_pushError(has->ctx, res, NULL);
			goto cleanup;
		}
		*waiting = pending + received;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_setOption(KSI_HighAvailabilityService *has, const int option, void *value) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i = 0;

	if (has == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	switch (option) {
		/* Conf callback has to be handled internally by HA service itself. */
		case KSI_ASYNC_OPT_PUSH_CONF_CALLBACK:
			has->confCallback = (KSI_Config_Callback)value;
			break;
		case KSI_ASYNC_OPT_CONF_CONSOLIDATE_CALLBACK:
			has->confConsolidateCallback = (KSI_AsyncServiceCallback_configConsolidate)value;
			break;

		case KSI_ASYNC_OPT_HA_SUBSERVICE_LIST:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;

		/* All other options route to the subservices. */
		default:
			for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
				KSI_AsyncService *as = NULL;

				res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
				if (res != KSI_OK) {
					KSI_pushError(has->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_AsyncService_setOption(as, option, value);
				if (res != KSI_OK) {
					KSI_pushError(has->ctx, res, NULL);
					goto cleanup;
				}
			}
			break;
	}


	res = KSI_OK;
cleanup:
	return res;
}

static int KSI_HighAvailabilityService_getOption(const KSI_HighAvailabilityService *has, const int option, void *value) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i = 0;
	size_t tmp = 0;

	if (has == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(has->ctx);

	if (KSI_AsyncServiceList_length(has->services) == 0) {
		KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	switch (option) {
		case KSI_ASYNC_OPT_PUSH_CONF_CALLBACK:
			tmp = (size_t)has->confCallback;
			break;
		case KSI_ASYNC_OPT_CONF_CONSOLIDATE_CALLBACK:
			tmp = (size_t)has->confConsolidateCallback;
			break;

		case KSI_ASYNC_OPT_HA_SUBSERVICE_LIST:
			tmp = (size_t)has->services;
			break;

		default:
			for (i = 0; i < KSI_AsyncServiceList_length(has->services); i++) {
				KSI_AsyncService *as = NULL;
				size_t srvOpt = 0;

				res = KSI_AsyncServiceList_elementAt(has->services, i, &as);
				if (res != KSI_OK) {
					KSI_pushError(has->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_AsyncService_getOption(as, option, (void *)&srvOpt);
				if (res != KSI_OK) {
					KSI_pushError(has->ctx, res, NULL);
					goto cleanup;
				}

				/* Just in case verify that the subservices share the same option value. */
				if (i > 0 && tmp != srvOpt) {
					/* Only happens if the setting the option has failed. */
					KSI_pushError(has->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
					goto cleanup;
				}
				tmp = srvOpt;
			}
			break;
	}
	*(size_t*)value = tmp;

	res = KSI_OK;
cleanup:
	return res;
}

static void KSI_HighAvailabilityService_free(KSI_HighAvailabilityService *service) {
	if (service != NULL) {
		KSI_AsyncServiceList_free(service->services);
		KSI_AsyncHandleList_free(service->respQueue);
		KSI_Config_free(service->consolidatedConfig);

		KSI_free(service);
	}
}

static int KSI_AbstractHighAvailabilityService_new(KSI_CTX *ctx, KSI_HighAvailabilityService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityService *tmp = NULL;

	if (ctx == NULL || service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_HighAvailabilityService);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->services = NULL;
	tmp->respQueue = NULL;
	tmp->consolidatedConfig = NULL;
	tmp->confCallback = NULL;
	tmp->confConsolidateCallback = NULL;

	tmp->subservice_new = NULL;

	res = KSI_AsyncServiceList_new(&tmp->services);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AsyncHandleList_new(&tmp->respQueue);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Config_new(ctx, &tmp->consolidatedConfig);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_HighAvailabilityService_free(tmp);
	return res;
}

static int KSI_HighAvailabilityService_addEndpoint(KSI_AsyncService *service, const char *uri, const char *loginId, const char *key) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityService *has = NULL;
	KSI_AsyncService *tmp = NULL;

	if (service == NULL || uri == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(service->ctx);

	has = (KSI_HighAvailabilityService *)service->impl;
	if (has == NULL) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	if (KSI_AsyncServiceList_length(has->services) >= has->ctx->options[KSI_OPT_HA_SAFEGUARD]) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "Exceed maximum nof HA subservices.");
		goto cleanup;
	}

	res = has->subservice_new(service->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AsyncService_setEndpoint(tmp, uri, loginId, key);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	/* Disable callbacks. Will be handled by the HA service itself. */
	res = KSI_AsyncService_setOption(tmp, KSI_ASYNC_PRIVOPT_INVOKE_CONF_RECEIVED_CALLBACK, (void*)false);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AsyncServiceList_append(has->services, tmp);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);

	return res;
}

static int KSI_HighAvailabilityService_setEndpoint(KSI_AsyncService *service, const char *uri, const char *loginId, const char *key) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HighAvailabilityService *has = NULL;

	if (service == NULL || uri == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(service->ctx);

	has = (KSI_HighAvailabilityService *)service->impl;
	if (has == NULL) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "High availability service is not properly initialized.");
		goto cleanup;
	}

	/* Reset subservices. */
	while (KSI_AsyncServiceList_length(has->services)) {
		KSI_AsyncServiceList_remove(has->services, KSI_AsyncServiceList_length(has->services) - 1, NULL);
	}
	KSI_Config_free(has->consolidatedConfig);
	has->consolidatedConfig = NULL;

	/* Reset response queue. */
	while (KSI_AsyncServiceList_length(has->respQueue)) {
		KSI_AsyncServiceList_remove(has->respQueue, KSI_AsyncServiceList_length(has->respQueue) - 1, NULL);
	}

	res = KSI_HighAvailabilityService_addEndpoint(service, uri, loginId, key);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SigningHighAvailabilityService_new(KSI_CTX *ctx, KSI_AsyncService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;
	KSI_HighAvailabilityService *ha = NULL;

	if (ctx == NULL || service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	res = KSI_AbstractAsyncService_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AbstractHighAvailabilityService_new(ctx, (KSI_HighAvailabilityService **)&ha);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	ha->subservice_new = KSI_SigningAsyncService_new;

	tmp->impl_free = (void (*)(void *))KSI_HighAvailabilityService_free;
	tmp->impl = ha;
	ha = NULL;

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))KSI_HighAvailabilityService_addRequest;
	tmp->responseHandler = (int (*)(void *))KSI_HighAvailabilityService_aggrRespHandler;
	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *))KSI_HighAvailabilityService_run;

	tmp->getPendingCount = (int (*)(void *, size_t *))KSI_HighAvailabilityService_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))KSI_HighAvailabilityService_getReceivedCount;

	tmp->setOption = (int (*)(void *, int, void *))KSI_HighAvailabilityService_setOption;
	tmp->getOption = (int (*)(void *, int, void *))KSI_HighAvailabilityService_getOption;

	tmp->setEndpoint = (int (*)(void *, const char *, const char *, const char *))KSI_HighAvailabilityService_setEndpoint;
	tmp->addEndpoint = (int (*)(void *, const char *, const char *, const char *))KSI_HighAvailabilityService_addEndpoint;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_HighAvailabilityService_free(ha);
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_ExtendingHighAvailabilityService_new(KSI_CTX *ctx, KSI_AsyncService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;
	KSI_HighAvailabilityService *ha = NULL;

	if (ctx == NULL || service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	res = KSI_AbstractAsyncService_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AbstractHighAvailabilityService_new(ctx, (KSI_HighAvailabilityService **)&ha);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	ha->subservice_new = KSI_ExtendingAsyncService_new;

	tmp->impl_free = (void (*)(void *))KSI_HighAvailabilityService_free;
	tmp->impl = ha;
	ha = NULL;

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))KSI_HighAvailabilityService_addRequest;
	tmp->responseHandler = (int (*)(void *))KSI_HighAvailabilityService_extRespHandler;
	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *))KSI_HighAvailabilityService_run;

	tmp->getPendingCount = (int (*)(void *, size_t *))KSI_HighAvailabilityService_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))KSI_HighAvailabilityService_getReceivedCount;

	tmp->setOption = (int (*)(void *, int, void *))KSI_HighAvailabilityService_setOption;
	tmp->getOption = (int (*)(void *, int, void *))KSI_HighAvailabilityService_getOption;

	tmp->setEndpoint = (int (*)(void *, const char *, const char *, const char *))KSI_HighAvailabilityService_setEndpoint;
	tmp->addEndpoint = (int (*)(void *, const char *, const char *, const char *))KSI_HighAvailabilityService_addEndpoint;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_HighAvailabilityService_free(ha);
	KSI_AsyncService_free(tmp);
	return res;
}

