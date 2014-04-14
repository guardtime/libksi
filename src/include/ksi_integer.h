#ifndef KSI_INTEGER_H_
#define KSI_INTEGER_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	#define KSI_uint64_t uint64_t

	void KSI_Integer_free(KSI_Integer *kint);
	int KSI_Integer_getSize(KSI_Integer *kint, int *size);
	KSI_uint64_t KSI_Integer_getUInt64(KSI_Integer *kint);
	int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **kint);
	int KSI_Integer_equals(KSI_Integer *a, KSI_Integer *b);
	int KSI_Integer_equalsUInt(KSI_Integer *o, KSI_uint64_t i);

#ifdef __cplusplus
}
#endif

#endif /* KSI_INTEGER_H_ */
