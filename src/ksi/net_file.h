/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#ifndef KSI_NET_FILE_H_
#define KSI_NET_FILE_H_

#include "net.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KSI_FsClient_st KSI_FsClient;

	/**
	 * Creates a new file system client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_FsClient_new(KSI_CTX *ctx, KSI_NetworkClient **client);

	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	path		Null-terminated file path.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_FsClient_setPublicationUrl(KSI_NetworkClient *client, const char *path);


	/**
	 * Setter for the file system client extender parameters.
	 * \param[in]	client		Pointer to tcp client.
	 * \param[in]	path		Path to the file.
	 * \param[in]	user		NULL-terminated user name
	 * \param[in]	pass		NULL-terminated password
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_FsClient_setExtender(KSI_NetworkClient *client, const char *path, const char *user, const char *pass);

	/**
	 * Setter for the file system aggregator parameters.
	 * \param[in]	client		Pointer to tcp client.
	 * \param[in]	path		Path to the file.
	 * \param[in]	user		NULL-terminated user name
	 * \param[in]	pass		NULL-terminated password
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_FsClient_setAggregator(KSI_NetworkClient *client, const char *path, const char *user, const char *pass);

	/**
	 * Extract file path from URI
	 * \param[in]   uri         File URI.
	 * \param[out]  path        Path to the file
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_FsClient_extractPath(const char *uri, char **path);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_FILE_H_ */
