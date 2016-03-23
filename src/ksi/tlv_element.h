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

	/**
	 * The KSI_TlvElement_st structure represents a complete TLV. If the structure is parsed only a minimal amount
	 * of data is copied - all the substructures use the pointer of its parent.
	 */
	struct KSI_TlvElement_st {
		KSI_FTLV ftlv;
		unsigned char *ptr;
		int ptr_own;

		KSI_LIST(KSI_TlvElement) *subList;

		size_t ref;
	};

	/**
	 * Creates a new #KSI_TlvElement.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_new(KSI_TlvElement **out);

	/**
	 * Cleanup method for the #KSI_TlvElement.
	 * \param[in]	t		Pointer to the #KSI_TlvElement.
	 */
	void KSI_TlvElement_free(KSI_TlvElement *t);

	/**
	 * This function serializes the #KSI_TlvElement. The buffer \c buf may be NULL, but only
	 * if the buffer size \c buf_size is equal to 0 - this can be used to calculate the length
	 * of the serialized value and after that allocate the buffer.
	 * \param[in]	element		Pointer to the #KSI_TlvElement.
	 * \param[in]	buf			Pointer to the buffer where to serialize the element.
	 * \param[in]	buf_size	Size of the buffer.
	 * \param[out]	len			Length of the serialized data (may be NULL).
	 * \param[in]	opt			Options for serialization. (see #KSI_Serialize_Opt_en).
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_serialize(KSI_TlvElement *element, unsigned char *buf, size_t buf_size, size_t *len, int opt);

	/**
	 * Access method for a nested #KSI_Utf8String value  by the given tag. If there is no value with the
	 * specified tag, the output is evaluated to \c NULL.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \note The output object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_getUtf8String(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Utf8String **out);

	/**
	 * Access method for a nested #KSI_OctetString value  by the given tag. If there is no value with the
	 * specified tag, the output is evaluated to \c NULL.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \note The output object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_getOctetString(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_OctetString **out);

	/**
	 * Access method for a nested #KSI_Integer value by the given tag. If there is no value with the
	 * specified tag, the output is evaluated to \c NULL.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \note The output object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_getInteger(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Integer **out);

	/**
	 * A setter method for a nested #KSI_Utf8String value. If the element already exists as
	 * a sub-element of \c parent, the sub-element is replaced with the new value.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	value		Pointer to the receiving pointer.
	 * \note The input value object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_setUtf8String(KSI_TlvElement *parent, unsigned tag, KSI_Utf8String *value);

	/**
	 * A setter method for a nested #KSI_Integer value. If the element already exists as
	 * a sub-element of \c parent, the sub-element is replaced with the new value.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	value		Pointer to the receiving pointer.
	 * \note The input value object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_setInteger(KSI_TlvElement *parent, unsigned tag, KSI_Integer *value);

#ifdef __cplusplus
}
#endif

#endif /* TLV_ELEMENT_H_ */
