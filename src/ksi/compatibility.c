#include "compatibility.h"
#include <string.h>
#include <stdio.h>

int KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va){
	int ret;
	if (n==0 || buf == NULL || format == NULL) return -1;
	
#ifdef _WIN32
	ret = vsnprintf_s(buf, n, _TRUNCATE, format, va);
	//truncation 
	if (ret == -1) return n-1; 
#else
	ret = vsnprintf(buf, n, format, va);
	if(ret >= n) return n-1;
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
