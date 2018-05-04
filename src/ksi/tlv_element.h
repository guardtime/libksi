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
#define KSI_TlvElementList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_TlvElementList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_TlvElementList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_TlvElementList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_TlvElementList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_TlvElementList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_TlvElementList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_TlvElementList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_TlvElementList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)
	KSI_DEFINE_REF(KSI_TlvElement);

	/**
	 * The KSI_TlvElement_st structure represents a complete TLV. If the structure is parsed only a minimal amount
	 * of data is copied - all the substructures use the pointer of its parent.
	 */
	struct KSI_TlvElement_st {
		/** Reference counter. */
		size_t ref;
		/** Basic properties of the TLV. */
		KSI_FTLV ftlv;
		/** Pointer to the underlying TLV. Payload begins at ptr + ftlv.hdr_len. */
		unsigned char *ptr;
		/** Does the element own the pointer (can and should it be freed by #KSI_TlvElement_free and #KSI_TlvElement_detach). */
		int ptr_own;
		/** List of sub elements. */
		KSI_LIST(KSI_TlvElement) *subList;
	};

	/**
	 * Creates a new #KSI_TlvElement.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_new(KSI_TlvElement **out);

	/**
	 * Parses the input as a #KSI_TlvElement object. The parsing process does not consume
	 * the input data pointer thus the data pointer may not be freed or modified. To detatch
	 * the data pointer from the object use #KSI_TlvElement_detach.
	 * \param[in]	dat		Pointer to the serialized TLV.
	 * \param[in]	dat_len	Length of the serialized TLV.
	 * \param[out]	out		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_TlvElement_free, #KSI_TlvElement_detach.
	 */
	int KSI_TlvElement_parse(unsigned char *dat, size_t dat_len, KSI_TlvElement **out);

	/**
	 * This function detaches the element from outer resources. This is useful after
	 * #KSI_TlvElement_parse function call if the underlying pointer needs to be reused or
	 * if the element has been altered (new sub-elements added or removed).
	 * \param[in]	el		The #KSI_TlvElement.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_detach(KSI_TlvElement *el);

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
	int KSI_TlvElement_serialize(const KSI_TlvElement *element, unsigned char *buf, size_t buf_size, size_t *len, int opt);

	/**
	 * Append an element as the last child. The caller is responsible of freeing the sub element.
	 * \param[in]	parent		The parent element.
	 * \param[in]	child		The child element.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_appendElement(KSI_TlvElement *parent, KSI_TlvElement *child);

	/**
	 * Inserts or replaces an element with the concrete TLV tag. There process will fail
	 * if there are already more than one elements with the same tag. The caller is
	 * responsible of freeing the sub element.
	 * \param[in]	parent		The parent element.
	 * \param[in]	child		The child element.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_setElement(KSI_TlvElement *parent, KSI_TlvElement *child);

	/**
	 * Find and extract a sub element. The output variable will be \c NULL if the element
	 * does not exist. If there are more than one elements with the given tag, the process
	 * will fail with an error.
	 * \param[in]	parent		Parent element.
	 * \param[in]	tag			Tag value of the element being extracted.
	 * \param[out]	el			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It is the responsibility of the caller to free the output element.
	 */
	int KSI_TlvElement_getElement(KSI_TlvElement *parent, unsigned tag, KSI_TlvElement **el);

	/**
	 * Removes a child element with the specified TLV tag. The process will fail if there is
	 * already more than one element or no elements with the same tag. If output variable \c el
	 * is not \c NULL, the the caller is responsible of freeing the removed element.
	 * \param[in]	parent		The parent element.
	 * \param[in]	tag			Tag value of the element being removed.
	 * \param[out]	el			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_removeElement(KSI_TlvElement *parent, unsigned tag, KSI_TlvElement **el);

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
	 * A setter method for a nested #KSI_OctetString value. If the element already exists as
	 * a sub-element of \c parent, the sub-element is replaced with the new value.
	 * \param[in]	parent		Pointer to the parent element.
	 * \param[in]	tag			Tag of the requested element.
	 * \param[out]	value		Pointer to the receiving pointer.
	 * \note The input value object must be free by the caller.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TlvElement_setOctetString(KSI_TlvElement *parent, unsigned tag, KSI_OctetString *value);

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
