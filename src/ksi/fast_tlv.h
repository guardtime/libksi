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

#ifndef FAST_TLV_H_
#define FAST_TLV_H_

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct fast_tlv_s KSI_FTLV;

	struct fast_tlv_s {
		/** Offset. */
		size_t off;

		/** Header length. */
		size_t hdr_len;

		/** Payload length. */
		size_t dat_len;

		/** TLV tag */
		unsigned tag;

		/* Flag - is non critical. */
		int is_nc;

		/* Flag - is forward. */
		int is_fwd;
	};

	enum KSI_Serialize_Opt_en {
		/** Do not write the header while serializing. */
		KSI_TLV_OPT_NO_HEADER = 0x01,
		/** Keep the TLV serialized to the end of the buffer. */
		KSI_TLV_OPT_NO_MOVE = 0x02,
	};

	/**
	 * Read the TLV from a file.
	 * \param[in]	f			File descriptor.
	 * \param[in]	buf			Pointer to memory buffer.
	 * \param[in]	len			Length of the buffer.
	 * \param[out]	consumed	Number of bytes read.
	 * \param[in]	t			Pointer to  the #KSI_FTLV object.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_FTLV_fileRead(FILE *f, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t);

	/**
	 * Read the TLV from a socket.
	 * \param[in]	fd			Socket descriptor.
	 * \param[in]	buf			Pointer to memory buffer.
	 * \param[in]	len			Length of the buffer.
	 * \param[out]	consumed	Number of bytes read.
	 * \param[in]	t			Pointer to  the #KSI_FTLV object.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_FTLV_socketRead(int fd, unsigned char *buf, size_t len, size_t *consumed, KSI_FTLV *t);

	/**
	 * Read the TLV from a memory buffer.
	 * \param[in]	m		Pointer to the memory buffer.
	 * \param[in]	l		Length of the buffer.
	 * \param[in]	t		Pointer to the #KSI_FTLV object.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_FTLV_memRead(const unsigned char *m, size_t l, KSI_FTLV *t);

	/**
	 * Reads up to \c arr_len TLV's  from the buffer. The number of read elements is returned via \c rd
	 * output parameter. If the \c arr pointer is set to \c NULL and \c arr_len equals 0, the function
	 * calculates the required length for the buffer \c arr.
	 * \param[in]	buf		Pointer to the memory buffer.
	 * \param[in]	buf_len	Length of the buffer.
	 * \param[in]	arr		Pointer to the output buffer (can be \c NULL).
	 * \param[in]	arr_len	Length of the output buffer (must be equal to 0, if \c arr is \c NULL).
	 * \param[out]	rd		Output parameter for the number of TLV read (can be \c NULL).
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 * \note This method is using optimized to do as little copy operations as possible. In case of an
	 * error during this process, the buffer will probably get corrupted. If this corruption of the
	 * buffer is an issue, you may call this function twice - the first time just leave \c arr as \c NULL
	 * and \c arr_len equal to 0.
	 */
	int KSI_FTLV_memReadN(const unsigned char *buf, size_t buf_len, KSI_FTLV *arr, size_t arr_len, size_t *rd);


#ifdef __cplusplus
}
#endif

#endif /* FAST_TLV_H_ */
