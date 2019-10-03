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
#include <stdio.h>
#include <limits.h>

#include "ksi.h"
#include "compatibility.h"

#ifdef _WIN32
size_t KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	size_t ret = 0;
	int tmp;
	if (buf == NULL || n > INT_MAX || n == 0 || format == NULL) goto cleanup;
	/* NOTE: If there is empty space in buf, it will be filled with 0x00 or 0xfe. */
	tmp = vsnprintf_s(buf, n, _TRUNCATE, format, va);
	if (tmp < 0) {
		ret = n - 1;
		goto cleanup;
	}
	ret = (size_t) tmp;

cleanup:

	return ret;
}
#else
size_t KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	size_t ret = 0;
	if (buf == NULL || n > INT_MAX || n == 0 || format == NULL) goto cleanup;
	ret = vsnprintf(buf, n, format, va);
	if (ret >= n) {
		ret = n - 1;
		goto cleanup;
	}

cleanup:

	return ret;
}
#endif

size_t KSI_snprintf(char *buf, size_t n, const char *format, ... ){
	size_t ret;
	va_list va;
	va_start(va, format);
	ret = KSI_vsnprintf(buf, n, format, va);
	va_end(va);
	return ret;
}

char *KSI_strncpy (char *destination, const char *source, size_t n){
	char *ret = NULL;
	if (destination == NULL || source == NULL || n == 0) {
		goto cleanup;
	}
	ret = strncpy(destination, source, n - 1);
	destination[n - 1] = 0;

cleanup:

	return ret;
}

int KSI_strdup(const char *from, char **to) {
	int res = KSI_UNKNOWN_ERROR;
	size_t len;
	char *tmp = NULL;

	if (from == NULL || to == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	len = strlen(from) + 1;

	tmp = KSI_malloc(len);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	KSI_strncpy(tmp, from, len);

	*to = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int is_leap_year(int year) {
	if (year % 4 > 0) return 0;
	if (year % 100 > 0) return 1;
	if (year % 400 > 0) return 0;
	return 1;
}

static int days_in_month(int month, int is_leap_year) {
	switch (month) {
		case 1: return 31;
		case 2: if (is_leap_year) return 29; else return 28;
		case 3: return 31;
		case 4: return 30;
		case 5: return 31;
		case 6: return 30;
		case 7: return 31;
		case 8: return 31;
		case 9: return 30;
		case 10: return 31;
		case 11: return 30;
		case 12: return 31;
		default: return -1;
	}
}

time_t KSI_CalendarTimeToUnixTime(struct tm *time) {
	/* Durations in seconds. */
	const int MIN = 60;
	const int HOUR = 60 * MIN;
	const int DAY = 24 * HOUR;
	const int YEAR = 365 * DAY;

	time_t tmp = 0;
	int year = 0;
	int month = 0;
	int i = 0;

	if (time == NULL) return -1;

	year = 1900 + time->tm_year;
	if (year < 1970) return -1; /* We only return non-negative values. */
	if (sizeof(time_t) == 4) {
		if ((time_t) -1 < 0) {
			if (year >= 2038) return -1; /* We have 32-bit signed time_t. */
		} else {
			if (year >= 2106) return -1; /* We have 32-bit unsigned time_t. */
		}
	} else {
		if (year >= 3000) return -1; /* We have 64-bit time_t, but allowing more is just insane. */
	}
	for (i = 1970; i < year; ++i) {
		tmp += YEAR;
		if (is_leap_year(i)) tmp += DAY;
	}

	month = 1 + time->tm_mon;
	if (month < 1) return -1;
	if (month > 12) return -1;
	for (i = 1; i < month; ++i) {
		int days = days_in_month(i, is_leap_year(year));
		if (days < 0) return -1;
		tmp += days * DAY;
	}

	if (time->tm_mday < 1) return -1;
	if (time->tm_mday > days_in_month(month, is_leap_year(year))) return -1;
	tmp += (time->tm_mday - 1) * DAY;

	if (time->tm_hour < 0) return -1;
	if (time->tm_hour > 23) return -1;
	tmp += time->tm_hour * HOUR;

	if (time->tm_min < 0) return -1;
	if (time->tm_min > 59) return -1;
	tmp += time->tm_min * MIN;

	if (time->tm_sec < 0) return -1;
	if (time->tm_sec > 59) return -1;
	tmp += time->tm_sec;

	return tmp;
}

int KSI_strcasecmp(const char *s1, const char *s2) {
	if (s1 == NULL || s2 == NULL) return KSI_INVALID_ARGUMENT;

	#ifdef _WIN32
		return _stricmp(s1, s2);
	#else
		return strcasecmp(s1, s2);
	#endif
}
