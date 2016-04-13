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


#ifndef BLOCKSIGNER_C_
#define BLOCKSIGNER_C_

#include "internal.h"
#include "blocksigner.h"
#include "tree_builder.h"

#ifdef __cplusplus
extern "C" {
#endif

KSI_DEFINE_LIST(KSI_BlocksignerHandle);
KSI_IMPLEMENT_LIST(KSI_BlocksignerHandle, KSI_BlocksignerHandle_free);


struct KSI_Blocksigner_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_TreeBuilder *builder;
	KSI_LIST(KSI_BlocksignerHandle) *leafList;
	KSI_Signature *signature;
	KSI_DataHash *prevLeaf;
	KSI_OctetString *iv;
	KSI_MetaData *metaData;

	KSI_TreeBuilderLeafProcessor metaDataProcessor;
};

struct KSI_BlocksignerHandle_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_TreeLeafHandle *leafHandle;
	KSI_Blocksigner *signer;
};

static KSI_DEFINE_REF(KSI_Blocksigner);
static KSI_IMPLEMENT_REF(KSI_Blocksigner);

static KSI_DEFINE_REF(KSI_BlocksignerHandle);
static KSI_IMPLEMENT_REF(KSI_BlocksignerHandle);

void KSI_BlocksignerHandle_free(KSI_BlocksignerHandle *handle) {
	if (handle != NULL && --handle->ref == 0) {
		KSI_TreeLeafHandle_free(handle->leafHandle);
		KSI_free(handle);
	}
}

static int KSI_BlocksignerHandle_new(KSI_CTX *ctx, KSI_BlocksignerHandle **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlocksignerHandle *tmp = NULL;

	if (out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_BlocksignerHandle);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->leafHandle = NULL;
	tmp->signer = NULL;
	tmp->ref = 1;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_BlocksignerHandle_free(tmp);

	return res;

}

static int metaDataProcessor(KSI_TreeNode *in, void *c, KSI_TreeNode **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Blocksigner *signer = c;
	KSI_TreeNode *tmp = NULL;

	if (in == NULL || c == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (signer->metaData != NULL) {
		res = KSI_TreeNode_new(signer->ctx, NULL, signer->metaData, in->level, &tmp);
		if (res != KSI_OK) goto cleanup;

		*out = tmp;
		tmp = NULL;
	} else {
		*out = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(tmp);

	return res;
}

int KSI_Blocksigner_new(KSI_CTX *ctx, KSI_HashAlgorithm algoId, KSI_DataHash *prevLeaf, KSI_OctetString *initVal, KSI_Blocksigner **signer) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Blocksigner *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || signer == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Blocksigner);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->builder = NULL;
	tmp->leafList = NULL;
	tmp->signature = NULL;
	tmp->prevLeaf = NULL;
	tmp->iv = NULL;
	tmp->metaData = NULL;

	tmp->metaDataProcessor.c = tmp;
	tmp->metaDataProcessor.fn = metaDataProcessor;

	res = KSI_TreeBuilder_new(ctx, algoId, &tmp->builder);
	if (res != KSI_OK) goto cleanup;

	res = KSI_BlocksignerHandleList_new(&tmp->leafList);
	if (res != KSI_OK) goto cleanup;

	tmp->prevLeaf = KSI_DataHash_ref(prevLeaf);
	tmp->iv = KSI_OctetString_ref(initVal);

	/* Add the client id handle. */
	res = KSI_TreeBuilderLeafProcessorList_append(tmp->builder->cbList, &tmp->metaDataProcessor);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*signer = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Blocksigner_free(tmp);

	return res;
}

void KSI_Blocksigner_free(KSI_Blocksigner *signer) {
	if (signer != NULL && --signer->ref == 0) {
		KSI_TreeBuilder_free(signer->builder);
		KSI_BlocksignerHandleList_free(signer->leafList);
		KSI_Signature_free(signer->signature);
		KSI_free(signer);
	}
}

int KSI_Blocksigner_close(KSI_Blocksigner *signer, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;
	KSI_Signature *sig = NULL;

	if (signer == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	KSI_LOG_debug(signer->ctx, "Closing block signer instance.");

	/* Finalize the tree. */
	res = KSI_TreeBuilder_close(signer->builder);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(signer->ctx, "Signing the root hash value of the block signer.");
	/* Sign the root hash. */
	res = KSI_Signature_signAggregated(signer->ctx, signer->builder->rootNode->hash, signer->builder->rootNode->level, &signer->signature);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	/* If the output parameter is set, populate the multi signature container. */
	if (ms != NULL) {
		size_t i;

		KSI_LOG_debug(signer->ctx, "Creating a multi signature output value for the block signer.");

		res = KSI_MultiSignature_new(signer->ctx, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		for (i = 0; i < KSI_BlocksignerHandleList_length(signer->leafList); i++) {
			KSI_BlocksignerHandle *hndl = NULL;

			/* Extract the element from the list. */
			res = KSI_BlocksignerHandleList_elementAt(signer->leafList, i, &hndl);
			if (res != KSI_OK) {
				KSI_pushError(signer->ctx, res, NULL);
				goto cleanup;
			}

			/* Create a proper signature. */
			res = KSI_BlocksignerHandle_getSignature(hndl, &sig);
			if (res != KSI_OK) {
				KSI_pushError(signer->ctx, res, NULL);
				goto cleanup;
			}

			/* Add the signature to the multi signature container. */
			res = KSI_MultiSignature_add(tmp, sig);
			if (res != KSI_OK) {
				KSI_pushError(signer->ctx, res, NULL);
				goto cleanup;
			}

			/* Free the signature, as it is no longer needed. */
			KSI_Signature_free(sig);
			sig = NULL;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Blocksigner_reset(KSI_Blocksigner *signer) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeBuilder *builder = NULL;
	KSI_LIST(KSI_BlocksignerHandle) *leafList = NULL;

	if (signer == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	res = KSI_TreeBuilder_new(signer->ctx, signer->builder->algo, &builder);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_BlocksignerHandleList_new(&leafList);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	KSI_Signature_free(signer->signature);
	signer->signature = NULL;

	KSI_TreeBuilder_free(signer->builder);
	signer->builder = builder;
	builder = NULL;

	KSI_BlocksignerHandleList_free(signer->leafList);
	signer->leafList = leafList;
	leafList = NULL;

	res = KSI_OK;

cleanup:

	KSI_TreeBuilder_free(builder);
	KSI_BlocksignerHandleList_free(leafList);

	return res;
}

int KSI_Blocksigner_addLeaf(KSI_Blocksigner *signer, KSI_DataHash *hsh, int level, KSI_MetaData *metaData, KSI_BlocksignerHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeLeafHandle *leafHandle = NULL;
	KSI_BlocksignerHandle *tmp = NULL;

	if (signer == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	/* Set the pointer to the meta data value. */
	signer->metaData = metaData;

	res = KSI_TreeBuilder_addDataHash(signer->builder, hsh, level, &leafHandle);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_BlocksignerHandle_new(signer->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	tmp->leafHandle = leafHandle;
	tmp->signer = signer;

	res = KSI_BlocksignerHandleList_append(signer->leafList, tmp);
	if (res != KSI_OK) goto cleanup;

	if (handle != NULL) {
		*handle = KSI_BlocksignerHandle_ref(tmp);
	}

	tmp = NULL;

	leafHandle = NULL;

	res = KSI_OK;

cleanup:

	/* Cleanup the value, as this is only a pointer to a memory we do not control. */
	signer->metaData = NULL;

	KSI_BlocksignerHandle_free(tmp);
	KSI_TreeLeafHandle_free(leafHandle);

	return res;
}

int KSI_BlocksignerHandle_getSignature(KSI_BlocksignerHandle *handle, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_AggregationHashChain *aggr = NULL;

	if (handle == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (handle->signer->signature == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_STATE, NULL);
		goto cleanup;
	}

	/* Create a hard copy of the signature. */
	res = KSI_Signature_clone(handle->signer->signature, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the calculated aggregation hash chain. */
	res = KSI_TreeLeafHandle_getAggregationChain(handle->leafHandle, &aggr);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Append the aggregation hash chain to the signature. */
	res = KSI_Signature_appendAggregationChain(tmp, aggr);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationHashChain_free(aggr);
	KSI_Signature_free(tmp);

	return res;
}


#ifdef __cplusplus
}
#endif

#endif /* BLOCKSIGNER_C_ */
