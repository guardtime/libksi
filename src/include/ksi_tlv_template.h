#include <stdlib.h>
#include "ksi_common.h"

#ifndef KSI_TLV_TEMPLATE_H_
#define KSI_TLV_TEMPLATE_H_

#ifdef __cplusplus
extern "C" {
#endif
	typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

	typedef int (*getter_t)(const void *, void **);
	typedef int (*setter_t)(void *, void *);
	typedef int (*cb_decode_t)(KSI_CTX *ctx, const KSI_TLV *, void *, const KSI_TlvTemplate *);

	typedef int (*cb_encode_t)(KSI_CTX *ctx, KSI_TLV *, const void *, const KSI_TlvTemplate *);
	struct KSI_TlvTemplate_st {
		int type;
		int tag;
		int isNonCritical;
		int isForward;
		/* Getter and setter for the internal value. */
		getter_t getValue;
		setter_t setValue;

		/* Constructor and destructor for the internal value. */
		int (*construct)(KSI_CTX *, void **);
		void (*destruct)(void *);



		const KSI_TlvTemplate *subTemplate;
		/* List functions */
		int (*listAppend)(void *, void *);
		/* Can this element be added multiple times (usefull with collections). */
		int multiple;
		int (*listNew)(KSI_CTX *, void **);
		void (*listFree)(void *);
		int (*listLength)(const void *);
		int (*listElementAt)(const void *, int, void **);

		/* Callbacks */
		cb_encode_t callbackEncode;
		cb_decode_t callbackDecode;

		int (*fromTlv)(KSI_TLV *tlv, void **);
		int (*toTlv)(void *, int, int, int, KSI_TLV **tlv);
	};

#define KSI_TLV_TEMPLATE(name) name##_template
#define KSI_IMPORT_TLV_TEMPLATE(name) extern const KSI_TlvTemplate KSI_TLV_TEMPLATE(name)[];

	#define KSI_TLV_TEMPLATE_OBJECT					1
	#define KSI_TLV_TEMPLATE_COMPOSITE				5
	#define KSI_TLV_TEMPLATE_SEEK_POS				6
	#define KSI_TLV_TEMPLATE_CALLBACK				7
	#define KSI_TLV_TEMPLATE_NATIVE_INT				8
	#define KSI_TLV_TEMPLATE_LIST					9

	#define KSI_TLV_FULL_TEMPLATE_DEF(typ, tg, nc, fw, gttr, sttr, constr, destr, subTmpl, list_append, mul, list_new, list_free, list_len, list_elAt, cbEnc, cbDec, fromTlv, toTlv) 								\
				{ typ, tg, nc, fw, (getter_t)gttr, (setter_t)sttr, 																																					\
				(int (*)(KSI_CTX *, void **)) constr, (void (*)(void *)) destr, subTmpl, 																															\
				(int (*)(void *, void *))list_append, mul, (int (*)(KSI_CTX *, void **)) list_new, (void (*)(void *)) list_free, (int (*)(const void *)) list_len, (int (*)(const void *, int, void **))list_elAt, 		\
				(cb_encode_t)cbEnc, (cb_decode_t)cbDec, 																																							\
				(int (*)(KSI_TLV *, void **)) fromTlv, (int (*)(void *, int, int, int, KSI_TLV **))toTlv},																											\

	#define KSI_TLV_PRIMITIVE_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter) KSI_TLV_FULL_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)


	#define KSI_DEFINE_TLV_TEMPLATE(name)	const KSI_TlvTemplate name##_template[] = {

	#define KSI_TLV_OBJECT(tag, nc, fw, getter, setter, fromTlv, toTlv) 					KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_OBJECT, tag, nc, fw, getter, setter, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, fromTlv, toTlv)
	#define KSI_TLV_UTF8_STRING(tag, nc, fw, getter, setter) 								KSI_TLV_OBJECT(tag, nc, fw, getter, setter, KSI_Utf8String_fromTlv, KSI_Utf8String_toTlv)
	#define KSI_TLV_INTEGER(tag, nc, fw, getter, setter) 									KSI_TLV_OBJECT(tag, nc, fw, getter, setter, KSI_Integer_fromTlv, KSI_Integer_toTlv)
	#define KSI_TLV_OCTET_STRING(tag, nc, fw, getter, setter) 								KSI_TLV_OBJECT(tag, nc, fw, getter, setter, KSI_OctetString_fromTlv, KSI_OctetString_toTlv)
	#define KSI_TLV_IMPRINT(tag, nc, fw, getter, setter) 									KSI_TLV_OBJECT(tag, nc, fw, getter, setter, KSI_DataHash_fromTlv, KSI_DataHash_toTlv)

	#define KSI_TLV_NATIVE_INT(tag, isNonCritical, isForward, getter, setter) 				KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_NATIVE_INT, tag, isNonCritical, isForward, getter, setter)

	#define KSI_TLV_OCTET_STRING_LIST(tag, isNonCritical, isForward, getter, setter) 		KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_OBJECT, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, KSI_OctetStringList_append, 1, KSI_OctetStringList_new, KSI_OctetStringList_free, KSI_OctetStringList_length, KSI_OctetStringList_elementAt, NULL, NULL, KSI_OctetSring_fromTlv, KSI_OctetString_toTlv)
	#define KSI_TLV_UTF8_STRING_LIST(tag, isNonCritical, isForward, getter, setter) 		KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_OBJECT, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, KSI_Utf8StringList_append, 1, KSI_Utf8StringList_new, KSI_Utf8StringList_free, KSI_Utf8StringList_length, KSI_Utf8StringList_elementAt, NULL, NULL, KSI_Utf8String_fromTlv, KSI_Utf8String_toTlv)


	#define KSI_TLV_COMPOSITE(tag, isNonCritical, isForward, getter, setter, sub)			KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_COMPOSITE, tag, isNonCritical, isForward, getter, setter, sub##_new, sub##_free, sub##_template, NULL, 0,  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
	#define KSI_TLV_COMPOSITE_LIST(tag, isNonCritical, isForward, getter, setter, sub) 		KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_COMPOSITE, tag, isNonCritical, isForward, getter, setter, sub##_new, sub##_free, sub##_template, sub##List_append, 1, sub##List_new, sub##List_free, sub##List_length, sub##List_elementAt, NULL, NULL, NULL, NULL)

	#define KSI_TLV_SEEK_POS(tag, setter)													KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_SEEK_POS, tag, 0, 0, NULL, setter)

	#define KSI_TLV_CALLBACK(tag, isNonCritical, isForward, getter, setter, encode, decode)	KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_CALLBACK, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 1, NULL, NULL, NULL, NULL, encode, decode, NULL, NULL)
	#define KSI_END_TLV_TEMPLATE { -1, 0, 0, 0, NULL, NULL}};


	/**
	 * Given a TLV object, template and a initialized target payload, this function evaluates the payload objects
	 * with the data from the TLV.
	 *
	 * \param[in]		ctx			KSI context.
	 * \param[in, out]	payload		Preinitialized empty object to be evaluated with the TLV values.
	 * \param[in]		tlv			TLV value which has the structure represented in \c template.
	 * \param[in]		template	Template of the TLV expected structure.
	 * \param[in, out]	reminder	List of TLV's that did not match the template on the first level. Can be NULL, in which case
	 * 								an error code is returned if an unknown non-critical TLV is encountered.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_TlvTemplate_extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder);

	/**
	 *
	 */
	int KSI_TlvTemplate_extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder, int (*generator)(void *, KSI_TLV **));

	/**
	 *
	 */
	int KSI_TlvTemplate_construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *template);
	int KSI_TlvTemplate_deepCopy(KSI_CTX *ctx, const void *from, const KSI_TlvTemplate *baseTemplate, void *to);

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_TEMPLATE_H_ */
