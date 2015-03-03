/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include "compatibility.h"
#include <string.h>
#include <stdio.h>
#include <limits.h>

/*TODO: Is it possible to avoid pointless buffer filling?*/
int KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	int ret=0;
	if (n==0 || buf == NULL || format == NULL || n > INT_MAX) return -1;
#ifdef _WIN32
	/*NOTE: If there is empty space in buf, it will be filled with 0x00 or 0xfe*/
	ret = vsnprintf_s(buf, n, _TRUNCATE, format, va);
	if (ret == -1) return (int)n-1; 
#else
	ret = vsnprintf(buf, n, format, va);
	if (ret >= n) return n-1;
#endif
	
	return ret;
}

int KSI_snprintf(char *buf, size_t n, const char *format, ... ){
	int ret;
	va_list va;
	va_start(va, format);
	ret = KSI_vsnprintf(buf, n, format, va);
	va_end(va);
	return ret;
}

char *KSI_strncpy (char *destination, const char *source, size_t n){
	char *ret;
	if (n==0 || destination == NULL || source == NULL) return NULL;
	destination[n-1] = 0;
	ret = strncpy(destination, source, n-1);
	return ret;
}
