#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>

#include "ksi_base.h"
#include "ksi_err.h"
#include "ksi_io.h"
#include "ksi_log.h"
#include "ksi_tlv_tags.h"

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_calloc(sizeof(typeVar), 1))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

/* Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr)

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_CTX_st {

	/******************
	 *  ERROR HANDLING.
	 ******************/

	/* Status code of the last executed function. */
	int statusCode;

	/* Array of errors. */
	KSI_ERR *errors;

	/* Length of error array. */
	size_t errors_size;

	/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
	size_t errors_count;

	/**********
	 * LOGGING.
	 **********/

	/* Log level see enum KSI_LOG_LVL_en */
	int logLevel;
	/* Filename where to write the log. NULL or "-" means stdout. */
	char *logFile;

	/* Stream to write log. */
	FILE *logStream; // TODO! Do we need more options?

	/************
	 * TRANSPORT.
	 ************/

	/** This structure is used from the current implementation of network provider. */
	struct {
		/** Cleanup for the provider, gets the #providerCtx as parameter. */
		void (*providerCleanup)(void *);

		/** Function for sending requests. This needs to be non blocking. */
		int (*sendRequest)(KSI_NetHandle *);

		/** Dedicated context for the net provider */
		void *poviderCtx;
	} netProvider;

	/****************
	 * CONFIGURATION.
	 ****************/
	struct {
		struct {
			int connectTimeoutSeconds;
			int readTimeoutSeconds;
			char *urlSigner;
			char *agent;
		} net;
	} conf;
};

/**
 * KSI Signature object
 */
struct KSI_Signature_st {
	/* TODO! */
	int mock;
};

void KSI_Signature_free(KSI_Signature *sig);

void *KSI_malloc(size_t size);
void *KSI_calloc(size_t num, size_t size);
void *KSI_realloc(void *ptr, size_t size);
void KSI_free(void *ptr);

/**********
 * KSI TLV
 **********/
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

/**
 * \ingroup tlv
 * This function creates an new TLV. If #data pointer is NULL a new memory block (with size 0xffff+1) is allocated,
 * otherwise the pointer itself and data_len is used for the payload.
 *
 * \param[in]	ctx			KSI context.
 * \param[in]	payloadType	Payload type of the TLV.
 * \param[in]	tag			Numeric TLV tag.
 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
 * \param[in]	isForward	Value of the forward-flag (1 or 0).
 * \param[in]	data		NULL or pointer to shared memory area.
 * \param[in]	data_len	Length of shared memory area, value will be ignored if #data == NULL
 * \param[in]	copy		Should the data be copyd to internal buffer, on can the data pointer be reused.
 * \param[out]	tlv			Pointer to the output variable.
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TLV_new(KSI_CTX *ctx, int payloadType, int tag, int isLenient, int isForward, void *data, size_t data_len, int copy, KSI_TLV **tlv);

/**
 * \ingroup tlv
 * This function creates a new TLV and initializes its payload with the given \c uint value.
 * The payload type will be #KSI_TLV_PAYLOAD_INT.
 *
 * \param[in]	ctx			KSI context.
 * \param[in]	tag			Numeric TLV tag.
 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
 * \param[in]	isForward	Value of the forward-flag (1 or 0).
 * \param[in]	data		NULL or pointer to shared memory area.
 * \param[in]	data_len	Length of shared memory area, value will be ignored if #data == NULL
 * \param[out]	tlv			Pointer to the output variable.
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TLV_fromUint(KSI_CTX *ctx, int tag, int isLenient, int isForward, uint64_t uint, KSI_TLV **tlv);

/**
 * \ingroup tlv
 * This function creates a new TLV and initializes its payload with the given string \c str.
 * The payload type will be #KSI_TLV_PAYLOAD_INT.
 *
 * \param[in]	ctx			KSI context.
 * \param[in]	tag			Numeric TLV tag.
 * \param[in]	isLenient	Value of the lenient-flag (1 or 0).
 * \param[in]	isForward	Value of the forward-flag (1 or 0).
 * \param[in]	data		NULL or pointer to shared memory area.
 * \param[in]	data_len	Length of shared memory area, value will be ignored if #data == NULL
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
int KSI_TLV_cast(KSI_TLV *tlv, enum KSI_TLV_PayloadType_en payloadType);

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
 * \param[int]	copy	0 - do not create, 1 - create a copy (has to be freed by the user with #KSI_free).
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TLV_getRawValue(KSI_TLV *tlv, unsigned char **buf, int *len, int copy);

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
int KSI_TLV_getUInt64Value(KSI_TLV *tlv, uint64_t *val);

/**
 * This function extracts string value from the TLV.
 *
 * \note This operation is available only if the TLV payloadType is #KSI_TLV_PAYLOAD_STR. To
 * change the payload type use #KSI_TLV_cast function.
 *
 * \param[in]	tlv		TLV from where to extract the value.
 * \param[out]	buf		Pointer to output variable.
 * \param[in]	copy	0 - do not create, 1 - create a copy (has to be freed by the user with #KSI_free).
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TLV_getStringValue(KSI_TLV *tlv, char **buf, int copy);

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
int KSI_TLV_getType(KSI_TLV *tlv);

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
int KSI_TLV_serialize_ex(KSI_TLV *tlv, unsigned char *buf, int buf_size, int *len);

/**
 *  TODO!
 */

int KSI_TLV_serialize(KSI_TLV *tlv, unsigned char **outBuf, int *outBuf_len);

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
int KSI_TLV_appendNestedTLV(KSI_TLV *target, KSI_TLV *after, KSI_TLV *tlv);

/**
 * This function creates a human readable representation of the TLV object.
 *
 * \param[in]	tlv		The TLV object.
 * \param[out]	str		Pointer to variable receiving the string pointer.
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TLV_toString(KSI_TLV *tlv, char **str);

/************
 *
 * KSI READER
 *
 ************/

/* TODO
 *
 */
int KSI_RDR_fromStream(KSI_CTX *ctx, FILE *file, KSI_RDR **rdr);

/* TODO!
 *
 */
int KSI_RDR_fromFile(KSI_CTX *ctx, const char *fileName, const char *flags, KSI_RDR **rdr);

/* TODO!
 *
 */
int KSI_RDR_fromMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, int ownCopy, KSI_RDR **rdr);

/* TODO!
 *
 */
int KSI_RDR_isEOF(KSI_RDR *rdr);

/* TODO!
 * Reads at maximum #bufferLength bytes into #buffer and strores number of read bytes in #readCount.
 *
 * \return KSI_OK when no errors occured.
 */
int KSI_RDR_read_ex(KSI_RDR *rdr, unsigned char *buffer, const size_t bufferLength, int *readCount);

/* TODO!
 * Method for reading from reader without copyng data. The pointer #ptr will point to the parent payload
 * area (which itself may not belong to the parent).
 *
 * \return The method will return KSI_OK when no error occured.
 *
 * \note This method can be applied to only #KSI_RDR which is based on a memory buffer.
 */
int KSI_RDR_read_ptr(KSI_RDR *rdr, unsigned char **ptr, const size_t len, int *readCount);

/* TODO!
 *
 */
void KSI_RDR_close(KSI_RDR *rdr);

void KSI_NET_Handle_freeNetContext(void *netCtx);

int KSI_NET_global_init(void);

void KSI_NET_global_cleanup(void);


#ifdef __cplusplus
}
#endif


#endif
