#ifndef KSI_TLV_H_
#define KSI_TLV_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * This enum contains all the legal values for a TLV payload type.
	 */
	enum KSI_TLV_PayloadType_en {
		/* The payload of the TLV is encoded as a raw blob. */
		KSI_TLV_PAYLOAD_RAW,
		/* The payload of the TLV is encoded as a null terminated string.
		 * \note Unless the string itself contains a null character, the trailing
		 * will not be serialized. */
		KSI_TLV_PAYLOAD_STR,
		/* The payload is encoded as a 64 bit unsigned integer.
		 * \note The value will be serialized as big-endian. */
		KSI_TLV_PAYLOAD_INT,
		/* The payload of this TLV is a list of TLV's. */
		KSI_TLV_PAYLOAD_TLV
	};

	KSI_DEFINE_GET_CTX(KSI_TLV);
	/**
	 * \ingroup tlv
	 * This function creates an new TLV.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	payloadType	Payload type of the TLV.
	 * \param[in]	tag			Numeric TLV tag.
	 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
	 * \param[in]	isForward	Value of the forward-flag (1 or 0).
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_new(KSI_CTX *ctx, int payloadType, int tag, int isLenient, int isForward, KSI_TLV **tlv);

	/**
	 * \ingroup tlv
	 * This function creates a new TLV and initializes its payload with the given \c uint value.
	 * The payload type will be #KSI_TLV_PAYLOAD_INT.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Numeric TLV tag.
	 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
	 * \param[in]	isForward	Value of the forward-flag (1 or 0).
	 * \param[in]	uint		64-bit unsigned value.
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_fromUint(KSI_CTX *ctx, int tag, int isLenient, int isForward, KSI_uint64_t uint, KSI_TLV **tlv);

	/**
	 * \ingroup tlv
	 * This function creates a new TLV and initializes its payload with the given string \c str.
	 * The payload type will be #KSI_TLV_PAYLOAD_INT. The null value is included in the payload.
	 *
	 * \param[in]	ctx			KSI context.
	 * \param[in]	tag			Numeric TLV tag.
	 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
	 * \param[in]	isForward	Value of the forward-flag (1 or 0).
	 * \param[in]	str			Null-terminated string value.
	 * \param[out]	tlv			Pointer to the output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_fromString(KSI_CTX *ctx, int tag, int isLenient, int isForward, char *str, KSI_TLV **tlv);
	/**
	 * This function changes the internal representation of the TLV payload.
	 * \param[in]	tlv			TLV which payload will be casted.
	 * \param[in]	payloadType	Payload type (see #KSI_TLV_PayloadType_en).
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_cast(KSI_TLV *tlv, int payloadType);

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
	int KSI_TLV_parseBlob(KSI_CTX *ctx, unsigned char *data, size_t data_length, KSI_TLV **tlv);

	/**
	 * This function extracts the binary data from the TLV.
	 *
	 * \note This operation is available only if the TLV payloadType is #KSI_TLV_PAYLOAD_RAW. To
	 * change the payload type use #KSI_TLV_cast function.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	buf		Pointer to output pointer.
	 * \param[out]	len		Length of the raw value.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getRawValue(KSI_TLV *tlv, const unsigned char **buf, int *len);

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
	 * \note This operation is available only if the TLV payloadType is #KSI_TLV_PAYLOAD_INT. To
	 * change the payload type use #KSI_TLV_cast function.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	val		Pointer to output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getUInt64Value(KSI_TLV *tlv, KSI_uint64_t *val);

	/**
	 * This function extracts string value from the TLV.
	 *
	 * \note This operation is available only if the TLV payloadType is #KSI_TLV_PAYLOAD_STR. To
	 * change the payload type use #KSI_TLV_cast function.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	buf		Pointer to output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getStringValue(KSI_TLV *tlv, const char **buf);

	/**
	 * This function extracts the next nested TLV value from the TLV.
	 *
	 * \note This operation is available only if the TLV payloadType is #KSI_TLV_PAYLOAD_TLV. To
	 * change the payload type use #KSI_TLV_cast function.
	 *
	 * \param[in]	tlv		TLV from where to extract the value.
	 * \param[out]	nested	Pointer to output variable.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_getNextNestedTLV(KSI_TLV *tlv, KSI_TLV **nested);
	int KSI_TLV_iterNested(KSI_TLV *tlv);

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
	int KSI_TLV_isLenient(KSI_TLV *tlv);

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
	int KSI_TLV_getTag(KSI_TLV *tlv);

	/**
	 * TODO!
	 */
	int KSI_TLV_getPayloadType(KSI_TLV *tlv);


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
	int KSI_TLV_serialize_ex(const KSI_TLV *tlv, unsigned char *buf, int buf_size, int *len);

	/**
	 *  This function serialises the TLV value into a buffer. The output buffer value
	 *  has to be freed (see #KSI_free) by the caller.
	 *
	 *  \param[in]		tlv		TLV to be serialized.
	 *  \param[out]		buf		Pointer to the receiving buffer pointer.
	 *  \param[out]		buf_len	Pointer to the receiving buffer length variable.
	 */
	int KSI_TLV_serialize(const KSI_TLV *tlv, unsigned char **buf, int *buf_len);

	/**
	 * This function serialises the tlv payload into a given buffer with \c len bytes of free
	 * space.
	 *
	 * \param[in]		tlv		TLV.
	 * \param[in]		buf		Pointer to buffer.
	 * \param[in,out]  	len		Length of the buffer, after execution its value will be the lenght of the serialized TLV.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_serializePayload(KSI_TLV *tlv, unsigned char *buf, int *len);

	/**
	 *
	 */
	int KSI_TLV_replaceNestedTlv(KSI_TLV *parentTlv, KSI_TLV *oldTlv, KSI_TLV *newTlv);

	/**
	 * This function appends a nested tlv to the target TLV. The target TLV is required to
	 * have payload type #KSI_TLV_PAYLOAD_TLV. The added TLV will be added after the TLV
	 * given as the second parameter. If the second parameter is NULL the new TLV is added
	 * as the last element in the internal list.
	 *
	 *	\param[in]	target		Target TLV where to add the new value as nested TLV.
	 *	\param[in]	after		After which nested TLV the value should be added (single layer only).
	 *							If the parameter is NULL, the TLV is added to the end.
	 *	\param[in]	tlv			The TLV to be appended.
	 */
	int KSI_TLV_appendNestedTlv(KSI_TLV *target, KSI_TLV *after, KSI_TLV *tlv);

	/**
	 * Removes the given TLV from the parent iff the given TLV is a immediate child
	 * of the parent.
	 *
	 * \param[in]		target			The parent TLV.
	 * \param[in]		tlv				TLV value to be removed.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_removeNestedTlv(KSI_TLV *target, KSI_TLV *tlv);

	/**
	 * This function creates a human readable representation of the TLV object.
	 *
	 * \param[in]	tlv		The TLV object.
	 * \param[out]	str		Pointer to variable receiving the string pointer.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_toString(KSI_TLV *tlv, char **str);

	/**
	 * This functions makes an identical copy of a TLV by serializing, parsing
	 * the serialized value and restoring the internal structure.
	 *
	 * \param[in]	tlv			TLV to be cloned.
	 * \param[out]	clone		Pointer to the receiving pointer of the cloned value.
	 *
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int KSI_TLV_clone(const KSI_TLV *tlv, KSI_TLV **clone);

	int KSI_TLV_setUintValue(KSI_TLV *tlv, KSI_uint64_t val);
	int KSI_TLV_setRawValue(KSI_TLV *tlv, const void *data, int data_len);
	int KSI_TLV_setStringValue(KSI_TLV *tlv, const char *str);
	int KSI_TLV_fromReader(KSI_RDR *rdr, KSI_TLV **tlv);

	int KSI_TLV_getAbsoluteOffset(const KSI_TLV *tlv);
	int KSI_TLV_getRelativeOffset(const KSI_TLV *tlv);

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_H_ */
