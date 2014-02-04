#include <stdlib.h>

#include "ksi_internal.h"

void *KSI_malloc(size_t size) {
	return malloc(size);
}

void *KSI_calloc(size_t num, size_t size) {
	return calloc(num, size);
}

void *KSI_realloc(void *ptr, size_t size) {
	return realloc(ptr, size);
}

void KSI_free(void *ptr) {
	free(ptr);
}
