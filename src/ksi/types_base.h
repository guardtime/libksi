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

#ifndef TYPES_BASE_H_
#define TYPES_BASE_H_

#include <stdint.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_DEFINE_FN_FROM_TLV(typ) \
/*!
	Function to convert a plain #KSI_TLV to a \ref typ. The TLV meta data (i.e.
	tag, length and flags) are not preserved.
	\param[in]	tlv		Pointer to #KSI_TLV.
	\param[out]	o		Pointer to receiving pointer.
	\return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	\see \ref typ##_fromTlv
*/ \
int typ##_fromTlv(KSI_TLV *tlv, typ **o	);

#define KSI_DEFINE_FN_TO_TLV(typ) \
/*!
	Function to convert a \ref typ to a plain #KSI_TLV object.
	\param[in]	ctx				KSI context.
	\param[in]	o				Pointer to \ref typ
	\param[in]	tag				Tag value of the #KSI_TLV
	\param[in]	isNonCritical	Flag is-non-critical.
	\param[in]	isForward		Flag is-forward.
	\param[out]	tlv				Pointer to the receiving pointer.
	\return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	\see \ref typ##_fromTlv, \ref KSI_TLV_free
*/ \
int typ##_toTlv(KSI_CTX *ctx, typ *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);


#define KSI_DEFINE_REF(typ) \
	/*!
	 * Increases the inner reference count of that object.
	 * \param[in]	o		Pointer to \ref typ
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 * \see \ref typ##_free
	 */ \
	int typ##_ref(typ *o)

#define KSI_DEFINE_OBJECT_PARSE(typ) \
	/*!
	 * This function is used to parse a raw blob into a \ref typ object.
	 * \param[in]	ctx		KSI context.
	 * \param[in]	raw		Pointer to the raw blob to be parsed.
	 * \param[in]	len		Length of the raw blob.
	 * \param[out]	t		Pointer to the receiving pointer to the \ref typ object.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 * \see \ref typ##_serialize
	 */ \
	int typ##_parse(KSI_CTX *ctx, const unsigned char *raw, size_t len, typ **t);

#define KSI_DEFINE_OBJECT_SERIALIZE(typ) \
	/*!
	 * This function serializes \ref #typ object into a blob.
	 * \param[in]	t		Pointer to the \ref typ object.
	 * \param[out]	raw		Pointer to the receiving pointer.
	 * \param[out]	len		Pointer to the receiving length variable.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 * \see \ref typ##_parse
	 * @return
	 */\
	int typ##_serialize(const typ *t, unsigned char **raw, size_t *len);

#define KSI_DEFINE_WRITE_BYTES(typ) \
	/*!
	 * This function serializes the #typ object and writes the result into a pre-allocated buffer.
	 * \param[in]	o			Object to be serialized.
	 * \param[in]	buf			Pointer to pre-allocated buffer.
	 * \param[in]	buf_size	Buffer size.
	 * \param[out]	buf_len		Serialized buffer length.
	 * \param[in]	opt			Serialization options.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */\
	 int typ##_writeBytes(typ *o, unsigned char *buf, size_t buf_size, size_t *buf_len, int opt)

/**
 * \addtogroup base_types Base types
 *  @{
 */
	#define KSI_uint64_t uint64_t
	#define KSI_DEFINE_GET_CTX(type) KSI_CTX *type##_getCtx(const type *o);

	/**
	 * Logger callback function pointer type.
	 * \param[in]	logCtx		Logger context.
	 * \param[in]	level		Log level information.
	 * \param[in]	message		Pointer to the logged message.
	 * \return Implementation must return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	typedef int (*KSI_LoggerCallback)(void *logCtx, int level, const char *message);

	/**
	 * This is the central object of the SDK - the context. Instances of the context may not
	 * be shared between threads. There are no limits how many instances one thread can have,
	 * but objects created using this context should not be mixed with each other.
	 *
	 * \see #KSI_CTX_new, #KSI_CTX_free.
	 */
	typedef struct KSI_CTX_st KSI_CTX;

	/**
	 * This type represents a plain Type Length Value (TLV) object.
	 */
	typedef struct KSI_TLV_st KSI_TLV;

	/**
	 * Type for easy error handling with stacktrace and error messages.
	 */
	typedef struct KSI_ERR_st KSI_ERR;

	/**
	 * Reader object for parsing raw data into TLV's.
	 */
	typedef struct KSI_RDR_st KSI_RDR;

	/**
	 * Immutable object representing a 64-bit integer.
	 * \see #KSI_Integer_new, #KSI_Integer_free.
	 */
	typedef struct KSI_Integer_st KSI_Integer;

	/**
	 * Octet string type for storing binary data.
	 */
	typedef struct KSI_OctetString_st KSI_OctetString;

	/**
	 * Utf-8 string type.
	 */
	typedef struct KSI_Utf8String_st KSI_Utf8String;

	/**
	 * An utf-8 string which must have at least one printable character.
	 */
	typedef KSI_Utf8String KSI_Utf8StringNZ;

	/**
	 * Method to free or dereference a KSI_Integer object. The object is
	 * not freed if the object is still referenced from somewhere.
	 * \param[in]	o		Pointer to be freed
	 * \see #KSI_Integer_new, #KSI_Integer_ref
	 */
	void KSI_Integer_free(KSI_Integer *o);

	/**
	 * This method converts the #KSI_Integer value as UTC time and converts
	 * its value to a string with the following format: "%Y-%m-%d %H:%M:%S UTC".
	 * The result is written to buffer. If the buffer is too short, the remainder
	 * is discarded. It is guaranteed to set a terminating '\\0' to the end of the
	 * result.
	 *
	 * \param[in]	o		Pointer to #KSI_Integer.
	 * \param[in]	buf		Pointer to buffer.
	 * \param[in]	buf_len	Length of the buffer.
	 * \return On success returns buf and NULL if an error occurred.
	 */
	char *KSI_Integer_toDateString(const KSI_Integer *o, char *buf, size_t buf_len);

	/**
	 * Returns the native 64-bit value of the #KSI_Integer.
	 * \param[in]	o		Pointer to #KSI_Integer.
	 * \return The native 64-bit value.
	 */
	KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *o);

	/**
	 * Constructor to create a new #KSI_Integer.
	 * \param[in]	ctx		KSI context.
	 * \param[in]	value	Value of the new #KSI_Integer.
	 * \param[out]	o		Pointer to the receiving pointer.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **o);

	/**
	 * Function to determine equality of the values of the two
	 * #KSI_Integer objects.
	 * \param[in]	a		Left operand.
	 * \param[in]	b		Right operand.
	 * \return 0 if the values differ, otherwise returns value greater than 0.
	 */
	int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b);

	/**
	 * Function to compare the values of two #KSI_Integer objects.
	 * \param[in]	a		Left operand.
	 * \param[in]	b		Right operand.
	 * \return Returns 0 if the values are equal, -1 if b is greater and 1 otherwise.
	 * \note NULL values are treated as they where #KSI_Integer objects with value 0.
	 */
	int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b);

	/**
	 * Function to compare the equality of a #KSI_Integer with a native
	 * unsigned value.
	 * \param[in]	o		Pointer to #KSI_Integer.
	 * \param[in]	i		Native unsigned value
	 * \return Returns 0 if the values differ, otherwise value greater than 0.
	 * \note If a == NULL, the result is always not true.
	 */
	int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i);


	KSI_DEFINE_REF(KSI_Integer);
	KSI_DEFINE_FN_FROM_TLV(KSI_Integer);
	KSI_DEFINE_FN_TO_TLV(KSI_Integer);

	/**
	 * Free the object.
	 * \param[in]	t		Object to be freed.
	 */
	void KSI_OctetString_free(KSI_OctetString *t);

	/**
	 * Constructor.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	data		Pointer to the data.
	 * \param[in]	data_len	Length of the data.
	 * \param[out]	t			Pointer to the receiving pointer.
	 */
	int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, size_t data_len, KSI_OctetString **t);
	int KSI_OctetString_extract(const KSI_OctetString *t, const unsigned char **data, size_t *data_len);

	/**
	 * Function to check for the equality of two octet strings.
	 * \param[in]	left	Left operand.
	 * \param[in]	right	Right operand.
	 * \return Returns 0 if the octet strings are not equal.
	 */
	int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right);

	KSI_DEFINE_REF(KSI_OctetString);
	KSI_DEFINE_FN_FROM_TLV(KSI_OctetString);
	KSI_DEFINE_FN_TO_TLV(KSI_OctetString);

	/*
	 * KSI_Utf8String
	 */

	/**
	 * Cleanup method for the #KSI_Utf8String object.
	 * \param[in]		t			Pointer to the object to be freed.
	 */
	void KSI_Utf8String_free(KSI_Utf8String *t);

	/**
	 * Creates a new #KSI_Utf8String object.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		str			String value.
	 * \param[in]		len			Length of the string.
	 * \param[out]		t			Pointer to the receiving pointer.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 * \see #KSI_Utf8String_free, #KSI_Utf8String_cstr
	 */
	int KSI_Utf8String_new(KSI_CTX *ctx, const char *str, size_t len, KSI_Utf8String **t);

	/**
	 * Returns the actual size of the string in bytes.
	 * \param[in]		t		KSI utf8 string object.
	 * \return Returns the actual size of the string in bytes or 0 if the object is NULL.
	 */
	size_t KSI_Utf8String_size(const KSI_Utf8String *t);

	/**
	 * Returns a constant pointer to a buffer containing the null terminated c string or NULL if the
	 * object is NULL.
	 * \param[in]		o			Pointer to the string object.
	 *
	 * \return Pointer to the null terminated c string.
	 */
	const char *KSI_Utf8String_cstr(const KSI_Utf8String *o);

	KSI_DEFINE_REF(KSI_Utf8String);
	KSI_DEFINE_FN_FROM_TLV(KSI_Utf8String);
	KSI_DEFINE_FN_TO_TLV(KSI_Utf8String);

	/**
	 * Functions as #KSI_Utf8String_fromTlv, but adds constraint to the content not
	 * being empty.
	 * \param[in]	tlv		Pointer to #KSI_TLV.
	 * \param[out]	o		Pointer to receiving pointer.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Utf8StringNZ_fromTlv(KSI_TLV *tlv, KSI_Utf8String **o);

	/**
	 * Functions as #KSI_Utf8String_toTlv, but adds constraint to the content not
	 * being empty.
	 * \param[in]	ctx					KSI context.
	 * \param[in]	o					String to be encoded as TLV.
	 * \param[in]	tag					Tag of the TLV.
	 * \param[in]	isNonCritical		Is-non-critical flag.
	 * \param[in]	isForward			Is-forward flag.
	 * \param[out]	tlv					Pointer to the receiving pointer.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Utf8StringNZ_toTlv(KSI_CTX *ctx, KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* TYPES_BASE_H_ */
