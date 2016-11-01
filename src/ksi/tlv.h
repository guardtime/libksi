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

#ifndef KSI_TLV_H_
#define KSI_TLV_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup tlv TLV manipulation
	 * Most KSI objects use a type-length-value (TLV) encoding scheme. The TLV scheme is used
	 * to encode both the KSI data structures and also protocol data units (PDUs) for transferring
	 * them between the entities during the signature generation process. The values are octet
	 * strings of given lengths that carry information to be interpreted as specified by the types.
	 * The value part of an encoded object may contain nested TLV objects.
	 *
	 * For space efficiency, two TLV encodings are used:
	 * - A 16-bit TLV (TLV16) encodes a 13-bit type and 16-bit length (and can thus contain at most
	 * 65535 octets of data in the value part).
	 * - An 8-bit TLV (TLV8) encodes a 5-bit type and 8-bit length (at most 255 octets of value data).
	 *
	 * Smaller objects are encoded as TLV8 for lower overhead. A TLV8 type has local significance and
	 * identifies the encapsulated structure in the context where it is used. A TLV16 type < 256 has
	 * still local significance, but may be used to encode data that needs 16-bit length. A TLV16
	 * type >= 256 has global significance and identifies the encapsulated structure in the context of
	 *  the whole signature generation system.
	 *
	 * TLV8 and TLV16 are distinguished by the `16-Bit' flag in the first octet of the type field.
	 * @{
	 */

	KSI_DEFINE_GET_CTX(KSI_TLV);

	/**
	 * This function creates an new TLV.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Numeric TLV tag.
	 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
	 * \param[in]	isForward	Value of the forward-flag (1 or 0).
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_new(KSI_CTX *ctx, unsigned tag, int isLenient, int isForward, KSI_TLV **tlv);

	/**
	 * This function creates a new TLV and initializes its payload with the given string \c str.
	 * The \c NUL terminator is included in the payload.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Numeric TLV tag.
	 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
	 * \param[in]	isForward	Value of the forward-flag (1 or 0).
	 * \param[in]	str			\c NUL terminated string value.
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_fromString(KSI_CTX *ctx, unsigned tag, int isLenient, int isForward, char *str, KSI_TLV **tlv);

	/**
	 * Parses a memory area and creates a new TLV.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	data		Pointer to memory to be parsed.
	 * \param[in]	data_length	Length of the buffer.
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_parseBlob(KSI_CTX *ctx, const unsigned char *data, size_t data_length, KSI_TLV **tlv);

	/**
	 * Parses a raw TLV into a #KSI_TLV.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	data		Pointer to the raw TLV.
	 * \param[in]	data_length	Length of the raw data.
	 * \param[in]	ownMemory	Determines if the data pointer should be owned by the new TLV (1) or not (0).
	 * \param[out]	tlv			Pointer to the receiving pointer.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 *
	 */
	int KSI_TLV_parseBlob2(KSI_CTX *ctx, unsigned char *data, size_t data_length, int ownMemory, KSI_TLV **tlv);

	/**
	 * This function extracts the binary data from the TLV.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	buf		Pointer to output pointer.
	 * \param[out]	len		Length of the raw value.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getRawValue(KSI_TLV *tlv, const unsigned char **buf, size_t *len);

	/**
	 * Integer value accessor method.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	value	Pointer to pointer of the integer value.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getInteger(KSI_TLV *tlv, KSI_Integer **value);

	/**
	 * This function extracts the unsigned 64 bit integer value.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	val		Pointer to output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getUInt64Value(const KSI_TLV *tlv, KSI_uint64_t *val);

	/**
	 * This function returns the list of nested elements of the TLV. The list is
	 * ordered and will be serialized in this order. The list may not be freed
	 * by the caller.
	 *
	 * \param[in]	tlv		The composite TLV object.
	 * \param[out]	list	Pointer to the receiving list pointer.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getNestedList(KSI_TLV *tlv, KSI_LIST(KSI_TLV) **list);
	/**
	 * Destructor for a TLV object.
	 * \param[in]	tlv 	TLV to be freed.
	 */
	void KSI_TLV_free(KSI_TLV *tlv);

	/**
	 * This is an access method for the TLV lenient-flag.
	 *
	 * \param[in]	tlv		TLV.
	 *
	 * \return 1 if the lenient-flag is set, 0 otherwise.
	 */
	int KSI_TLV_isNonCritical(KSI_TLV *tlv);

	/**
	 * This is an access method for the TLV forward-flag.
	 *
	 * \param[in]	tlv		TLV.
	 *
	 * \return 1 if the forward-flag is set, 0 otherwise.
	 */
	int KSI_TLV_isForward(KSI_TLV *tlv);

	/**
	 * This is an access method for the TLV numeric type.
	 *
	 * \param[in]	tlv		TLV.
	 *
	 * \return Numeric value of the TLV type.
	 */
	unsigned KSI_TLV_getTag(KSI_TLV *tlv);

	/**
	 * This function serialises the tlv into a given buffer with \c len bytes of free
	 * space.
	 *
	 * \param[in]		tlv				TLV.
	 * \param[in]		buf				Pointer to buffer.
	 * \param[in]  		buf_size		Size of the buffer.
	 * \param[out]		len				Length of the serialized data.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_serialize_ex(const KSI_TLV *tlv, unsigned char *buf, size_t buf_size, size_t *len);

	/**
	 *  This function serialises the TLV value into a buffer. The output buffer value
	 *  has to be freed (see #KSI_free) by the caller.
	 *
	 *  \param[in]		tlv		TLV to be serialized.
	 *  \param[out]		buf		Pointer to the receiving buffer pointer.
	 *  \param[out]		buf_len	Pointer to the receiving buffer length variable.
	 */
	int KSI_TLV_serialize(const KSI_TLV *tlv, unsigned char **buf, size_t *buf_len);

	/**
	 * This function serialises the tlv payload into a given buffer with \c len bytes of free
	 * space.
	 *
	 * \param[in]		tlv		TLV.
	 * \param[in]		buf		Pointer to buffer.
	 * \param[in,out]  	len		Length of the buffer, after execution its value will be the length of the serialized TLV.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_serializePayload(KSI_TLV *tlv, unsigned char *buf, size_t *len);

	/**
	 * Replaces a nested TLV.
	 * \param[in]	parentTlv		Pointer to the parent TLV.
	 * \param[in]	oldTlv			Pointer to the previous TLV to be replaced.
	 * \param[in]	newTlv			Pointer to the replacement TLV.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 * \note The \c oldTlv will be freed.
	 */
	int KSI_TLV_replaceNestedTlv(KSI_TLV *parentTlv, KSI_TLV *oldTlv, KSI_TLV *newTlv);

	/**
	 * This function appends a nested TLV to the target TLV as the last element in the internal list.
	 *
	 *	\param[in]	target		Target TLV where to add the new value as nested TLV.
	 *	\param[in]	tlv			The TLV to be appended.
	 */
	int KSI_TLV_appendNestedTlv(KSI_TLV *target, KSI_TLV *tlv);

	int KSI_TLV_writeBytes(const KSI_TLV *tlv, unsigned char *buf, size_t buf_size, size_t *buf_len, int opt);

	/**
	 * This function creates a human readable representation of the TLV object.
	 *
	 * \param[in]	tlv			The TLV object.
	 * \param[in]	buffer		Pointer to variable receiving the string.
	 * \param[in]	buffer_len	Length of the buffer.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	char *KSI_TLV_toString(const KSI_TLV *tlv, char *buffer, size_t buffer_len);

	/**
	 * This functions makes an identical copy of a TLV by serializing, parsing
	 * the serialized value and restoring the internal structure.
	 *
	 * \param[in]	tlv			The TLV object to be cloned.
	 * \param[out]	clone		Pointer to the receiving pointer of the cloned value.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_clone(const KSI_TLV *tlv, KSI_TLV **clone);

	/**
	 * Set a raw value to the TLV object.
	 * \param[in]	tlv			The TLV object.
	 * \param[in]	data		Pointer to the raw data.
	 * \param[in]	data_len	Length of the raw data.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_setRawValue(KSI_TLV *tlv, const void *data, size_t data_len);

	/**
	 * Returns the absolute offset of the TLV object in the source raw data. If the TLV object is
	 * created using #KSI_TLV_new, the offset is 0.
	 * \param[in]	tlv			The TLV object.
	 *
	 * \return The absolute offset of the TLV object.
	 */
	size_t KSI_TLV_getAbsoluteOffset(const KSI_TLV *tlv);

	/**
	 * Returns the relative offset of the TLV object in the source raw data. (i.e. if this is a nested TLV
	 *  object, the offset is calculated only within the payload of the parent TLV object)If the TLV object is
	 * created using #KSI_TLV_new, the offset is 0.
	 * \param[in]	tlv			The TLV object.
	 *
	 * \return The absolute offset of the TLV object.
	 */
	size_t KSI_TLV_getRelativeOffset(const KSI_TLV *tlv);

	KSI_DEFINE_GET_CTX(KSI_TLV);

	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_H_ */
