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
