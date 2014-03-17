#include "ksi_internal.h"
#include "ksi_hash.h"
#include "ksi_tlv_easy.h"

static int createRequestTlv(KSI_CTX *ctx, uint64_t aggr_time, KSI_TLV **reqTlv) {
	int res;
	KSI_TLV *tlv = NULL;

	KSI_TLV_BEGIN(ctx, 0x0301, 0, 0)
		KSI_TLV_NESTED_BEGIN(0x0301, 0, 0)
			KSI_TLV_NESTED_UINT(0x02, 0, 0, aggr_time)
		KSI_TLV_NESTED_END
	KSI_TLV_END(res, tlv);

	if (res != KSI_OK) goto cleanup;

	*reqTlv = tlv;

cleanup:

	return res;
}
