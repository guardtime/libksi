#ifndef TLV_ELEMENT_H_
#define TLV_ELEMENT_H_

#include "ksi.h"
#include "fast_tlv.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KSI_TlvElement_st KSI_TlvElement;

	KSI_DEFINE_LIST(KSI_TlvElement);
	KSI_DEFINE_REF(KSI_TlvElement);

	struct KSI_TlvElement_st {
		KSI_FTLV ftlv;
		unsigned char *ptr;
		int ptr_own;

		KSI_LIST(KSI_TlvElement) *subList;

		size_t ref;
	};
	int KSI_TlvElement_new(KSI_TlvElement **out);
	void KSI_TlvElement_free(KSI_TlvElement *t);

	void KSI_TlvElement_print(KSI_TlvElement *element, int level);

	int KSI_TlvElement_serialize(KSI_TlvElement *element, unsigned char *buf, size_t buf_size, size_t *len, int opt);
	int KSI_TlvElement_getUtf8String(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Utf8String **out);
	int KSI_TlvElement_getOctetString(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_OctetString **out);
	int KSI_TlvElement_getInteger(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Integer **out);

	int KSI_TlvElement_setUtf8String(KSI_TlvElement *parent, unsigned tag, KSI_Utf8String *s);
	int KSI_TlvElement_setInteger(KSI_TlvElement *parent, unsigned tag, KSI_Integer *s);

#ifdef __cplusplus
}
#endif

#endif /* TLV_ELEMENT_H_ */
