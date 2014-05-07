#include <stdlib.h>
#include "ksi_common.h"

#ifndef KSI_TLV_TEMPLATE_H_
#define KSI_TLV_TEMPLATE_H_

#ifdef __cplusplus
extern "C" {
#endif
	typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

	typedef int (*getter_t)(const void *, const void **);
	typedef int (*setter_t)(void *, void *);
	typedef int (*cb_decode_t)(KSI_CTX *ctx, KSI_TLV *, void *, getter_t, setter_t);

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
		int (*elementAppend)(void *, void *);
		/* Can this element be added multiple times (usefull with collections). */
		int multiple;
		int (*elementConstruct)(KSI_CTX *, void **);
		void (*elementDestruct)(void *);

		/* Callbacks */
		cb_encode_t callbackEncode;
		cb_decode_t callbackDecode;
	};

#define KSI_TLV_TEMPLATE(name) name##_template
#define KSI_IMPORT_TLV_TEMPLATE(name) extern const KSI_TlvTemplate KSI_TLV_TEMPLATE(name)[];

	#define KSI_TLV_TEMPLATE_INTEGER 				1
	#define KSI_TLV_TEMPLATE_OCTET_STRING 			2
	#define KSI_TLV_TEMPLATE_UTF8_STRING 			3
	#define KSI_TLV_TEMPLATE_IMPRINT 				4
	#define KSI_TLV_TEMPLATE_COMPOSITE				5
	#define KSI_TLV_TEMPLATE_LIST					6
	#define KSI_TLV_TEMPLATE_CALLBACK				7
	#define KSI_TLV_TEMPLATE_NATIVE_INT				8

	#define KSI_TLV_FULL_TEMPLATE_DEF(typ, tg, nc, fw, gttr, sttr, constr, destr, subTmpl, appnd, mul, elConstr, elDestr, cbEnc, cbDec) { typ, tg, nc, fw, (getter_t)gttr, (setter_t)sttr, (int (*)(KSI_CTX *, void **)) constr, (void (*)(void *)) destr, subTmpl, (int (*)(void *, void *))appnd, mul, (int (*)(KSI_CTX *, void **)) elConstr, (void (*)(void *)) elDestr, (cb_encode_t)cbEnc, (cb_decode_t)cbDec},
	#define KSI_TLV_PRIMITIVE_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter) KSI_TLV_FULL_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL)

	#define KSI_DEFINE_TLV_TEMPLATE(name)	const KSI_TlvTemplate name##_template[] = {
	#define KSI_TLV_INTEGER(tag, isNonCritical, isForward, getter, setter) 					KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_INTEGER, tag, isNonCritical, isForward, getter, setter)
	#define KSI_TLV_NATIVE_INT(tag, isNonCritical, isForward, getter, setter) 				KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_NATIVE_INT, tag, isNonCritical, isForward, getter, setter)
	#define KSI_TLV_OCTET_STRING(tag, isNonCritical, isForward, getter, setter) 			KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_OCTET_STRING, tag, isNonCritical, isForward, getter, setter)
	#define KSI_TLV_UTF8_STRING(tag, isNonCritical, isForward, getter, setter) 				KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_UTF8_STRING, tag, isNonCritical, isForward, getter, setter)
	#define KSI_TLV_IMPRINT(tag, isNonCritical, isForward, getter, setter) 					KSI_TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_IMPRINT, tag, isNonCritical, isForward, getter, setter)
	#define KSI_TLV_COMPOSITE(tag, isNonCritical, isForward, getter, setter, sub) 			{KSI_TLV_TEMPLATE_COMPOSITE, tag, isNonCritical, isForward, (int (*)(const void *, const void **))getter, (int(*)(void *, void*))setter, (int (*)(KSI_CTX *, void **))sub##_new, (void(*)(void *)) sub##_free, sub##_template, NULL, 0, NULL, NULL, NULL, NULL},
	#define KSI_TLV_LIST(tag, isNonCritical, isForward, getter, setter, type, sub) 			{KSI_TLV_TEMPLATE_LIST, tag, isNonCritical, isForward, (int (*)(const void *, const void **))getter, (int(*)(void *, void*))setter, type##List_new, type##List_free, sub##_template, (int(*)(void *, void *))sub##_append, 1, (int (*)(KSI_CTX *, void **))sub##_new, (void (*)(void *))sub##_free, NULL, NULL}
	#define KSI_TLV_CALLBACK(tag, isNonCritical, isForward, getter, setter, encode, decode)	KSI_TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_CALLBACK, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 1, NULL, NULL, encode, decode)
	#define KSI_END_TLV_TEMPLATE { -1, 0, 0, 0, NULL, NULL}};


	int KSI_TlvTemplate_extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder);
	int KSI_TlvTemplate_construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *template);

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_TEMPLATE_H_ */
