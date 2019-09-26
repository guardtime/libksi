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


#include "internal.h"
#include "blocksigner.h"
#include "tree_builder.h"
#include "hashchain.h"
#include "signature_builder.h"


KSI_IMPLEMENT_LIST(KSI_BlockSignerHandle, KSI_BlockSignerHandle_free)


struct KSI_BlockSigner_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_TreeBuilder *builder;
	KSI_Signature *signature;
	KSI_DataHash *prevLeaf;
	KSI_DataHash *origPrevLeaf;
	KSI_OctetString *iv;
	KSI_MetaData *metaData;

	/** Common hasher object. */
	KSI_DataHasher *hsr;

	KSI_TreeBuilderLeafProcessor metaDataProcessor;
	KSI_TreeBuilderLeafProcessor maskingProcessor;
};

struct KSI_BlockSignerHandle_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_TreeLeafHandle *leafHandle;
	KSI_BlockSigner *signer;
};

static KSI_IMPLEMENT_REF(KSI_BlockSignerHandle)

void KSI_BlockSignerHandle_free(KSI_BlockSignerHandle *handle) {
	if (handle != NULL && --handle->ref == 0) {
		KSI_TreeLeafHandle_free(handle->leafHandle);
		KSI_free(handle);
	}
}

static int KSI_BlockSignerHandle_new(KSI_CTX *ctx, KSI_BlockSignerHandle **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSignerHandle *tmp = NULL;

	if (out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_BlockSignerHandle);
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

	KSI_BlockSignerHandle_free(tmp);

	return res;

}

static int metaDataProcessor(KSI_TreeNode *in, void *c, KSI_TreeNode **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *signer = c;
	KSI_TreeNode *tmp = NULL;

	if (in == NULL || c == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (signer->metaData != NULL) {
		res = KSI_TreeNode_new(signer->ctx, NULL, signer->metaData, (int)in->level, &tmp);
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

static int maskingProcessor(KSI_TreeNode *in, void *c, KSI_TreeNode **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *signer = c;
	KSI_TreeNode *tmp = NULL;
	KSI_DataHash *mask = NULL;
	KSI_DataHash *leafHash = NULL;
	unsigned char tmpLvl;

	if (in == NULL || c == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	if (signer->iv != NULL && signer->prevLeaf != NULL) {
		/* For now only masking real hash values is supported. */
		if (in->hash == NULL) {
			KSI_pushError(signer->ctx, res = KSI_INVALID_STATE, "Only a tree node with a hash value may be used for masking.");
			goto cleanup;
		}

		/* Calculate the mask value. */
		res = KSI_DataHasher_reset(signer->builder->hsr);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		/* Change here, if there is a need, to add previous values that are not nodes containing hash values. */
		res = KSI_DataHasher_addImprint(signer->builder->hsr, signer->prevLeaf);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_addOctetString(signer->builder->hsr, signer->iv);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_close(signer->builder->hsr, &mask);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		/* Add the mask as left link of the calculation. */
		res = KSI_TreeNode_new(signer->ctx, mask, NULL, (int)in->level, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		/* Calculate the actual leaf value. */
		res = KSI_DataHasher_reset(signer->builder->hsr);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_addImprint(signer->builder->hsr, mask);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_addImprint(signer->builder->hsr, in->hash);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		if (!KSI_IS_VALID_TREE_LEVEL(in->level + 1)) {
			KSI_pushError(signer->ctx, res = KSI_INVALID_STATE, "The tree height is too large.");
			goto cleanup;
		}

		tmpLvl = (unsigned char)(in->level + 1);

		res = KSI_DataHasher_add(signer->builder->hsr, &tmpLvl, 1);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_close(signer->builder->hsr, &leafHash);
		if (res != KSI_OK) {
			KSI_pushError(signer->ctx, res, NULL);
			goto cleanup;
		}

		/* Swap the previous leaf hash value. */
		KSI_DataHash_free(signer->prevLeaf);
		signer->prevLeaf = KSI_DataHash_ref(leafHash);

		*out = tmp;
		tmp = NULL;
	} else {
		*out = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(mask);
	KSI_DataHash_free(leafHash);

	KSI_TreeNode_free(tmp);

	return res;
}

int KSI_BlockSigner_new(KSI_CTX *ctx, KSI_HashAlgorithm algoId, KSI_DataHash *prevLeaf, KSI_OctetString *initVal, KSI_BlockSigner **signer) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || signer == NULL || (prevLeaf == NULL && initVal != NULL) || (prevLeaf != NULL && initVal == NULL)) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (!KSI_isHashAlgorithmTrusted(algoId)) {
		KSI_pushError(ctx, res = KSI_UNTRUSTED_HASH_ALGORITHM, "The aggregation hash algorithm is no longer trusted.");
		goto cleanup;
	}

	tmp = KSI_new(KSI_BlockSigner);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->builder = NULL;
	tmp->signature = NULL;
	tmp->prevLeaf = NULL;
	tmp->origPrevLeaf = NULL;
	tmp->iv = NULL;
	tmp->metaData = NULL;
	tmp->hsr = NULL;

	tmp->metaDataProcessor.c = tmp;
	tmp->metaDataProcessor.fn = metaDataProcessor;
	tmp->metaDataProcessor.levelOverhead = 1;

	tmp->maskingProcessor.c = tmp;
	tmp->maskingProcessor.fn = maskingProcessor;
	tmp->maskingProcessor.levelOverhead = 1;

	res = KSI_DataHasher_open(ctx, algoId, &tmp->hsr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TreeBuilder_new(ctx, algoId, &tmp->builder);
	if (res != KSI_OK) goto cleanup;

	tmp->prevLeaf = KSI_DataHash_ref(prevLeaf);
	tmp->origPrevLeaf = KSI_DataHash_ref(prevLeaf);
	tmp->iv = KSI_OctetString_ref(initVal);

	/* Add the masking handle. */
	res = KSI_TreeBuilderLeafProcessorList_append(tmp->builder->cbList, &tmp->maskingProcessor);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

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

	KSI_BlockSigner_free(tmp);

	return res;
}

void KSI_BlockSigner_free(KSI_BlockSigner *signer) {
	if (signer != NULL && --signer->ref == 0) {
		KSI_TreeBuilder_free(signer->builder);
		KSI_Signature_free(signer->signature);
		KSI_OctetString_free(signer->iv);
		KSI_DataHash_free(signer->prevLeaf);
		KSI_DataHash_free(signer->origPrevLeaf);
		KSI_DataHasher_free(signer->hsr);
		KSI_free(signer);
	}
}

int KSI_BlockSigner_closeAndSign(KSI_BlockSigner *signer) {
	int res = KSI_UNKNOWN_ERROR;

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


	res = KSI_OK;

cleanup:

	return res;
}

int KSI_BlockSigner_close(KSI_BlockSigner *signer, void KSI_UNUSED(*dummy)) {
	return KSI_BlockSigner_closeAndSign(signer);
}

int KSI_BlockSigner_reset(KSI_BlockSigner *signer) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeBuilder *builder = NULL;

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

	KSI_Signature_free(signer->signature);
	signer->signature = NULL;

	KSI_TreeBuilder_free(signer->builder);
	signer->builder = builder;
	builder = NULL;

	/* Add the masking handle. */
	res = KSI_TreeBuilderLeafProcessorList_append(signer->builder->cbList, &signer->maskingProcessor);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	/* Add the client id handle. */
	res = KSI_TreeBuilderLeafProcessorList_append(signer->builder->cbList, &signer->metaDataProcessor);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	KSI_DataHash_free(signer->prevLeaf);
	signer->prevLeaf = KSI_DataHash_ref(signer->origPrevLeaf);
	res = KSI_OK;

cleanup:

	KSI_TreeBuilder_free(builder);

	return res;
}

int KSI_BlockSigner_addLeaf(KSI_BlockSigner *signer, KSI_DataHash *hsh, int level, KSI_MetaData *metaData, KSI_BlockSignerHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeLeafHandle *leafHandle = NULL;
	KSI_BlockSignerHandle *tmp = NULL;
	KSI_HashAlgorithm algoId;

	if (signer == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	/* Make sure the input hash algorithm is still trusted. */
	res = KSI_DataHash_extract(hsh, &algoId, NULL, NULL);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_isHashAlgorithmTrusted(algoId)) {
		KSI_pushError(signer->ctx, res = KSI_UNTRUSTED_HASH_ALGORITHM, "The hash algorithm is no longer trusted as a leaf hash.");
		goto cleanup;
	}

	/* Set the pointer to the meta data value. */
	signer->metaData = metaData;

	res = KSI_TreeBuilder_addDataHash(signer->builder, hsh, level, &leafHandle);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_BlockSignerHandle_new(signer->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(signer->ctx, res, NULL);
		goto cleanup;
	}

	tmp->leafHandle = leafHandle;
	tmp->signer = signer;

	if (handle != NULL) {
		*handle = KSI_BlockSignerHandle_ref(tmp);
	}

	leafHandle = NULL;

	res = KSI_OK;

cleanup:

	/* Cleanup the value, as this is only a pointer to a memory we do not control. */
	if (signer != NULL) {
		signer->metaData = NULL;
	}

	KSI_BlockSignerHandle_free(tmp);
	KSI_TreeLeafHandle_free(leafHandle);

	return res;
}

int KSI_BlockSigner_getPrevLeaf(const KSI_BlockSigner *signer, KSI_DataHash **prevLeaf) {
	int res = KSI_UNKNOWN_ERROR;

	if (signer == NULL || signer->ctx == NULL || prevLeaf == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(signer->ctx);

	*prevLeaf = KSI_DataHash_ref(signer->prevLeaf);

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_BlockSignerHandle_getSignature(const KSI_BlockSignerHandle *handle, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_AggregationHashChain *aggr = NULL;
	KSI_SignatureBuilder *builder = NULL;
	KSI_TreeNode *node = NULL;

	if (handle == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (handle->signer->signature == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_STATE, "The blocksigner is not closed.");
		goto cleanup;
	}

	/* Extract the calculated aggregation hash chain. */
	res = KSI_TreeLeafHandle_getAggregationChain(handle->leafHandle, &aggr);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Build a new signature with the appended aggregation hash chain. */
	res = KSI_SignatureBuilder_openFromSignature(handle->signer->signature, &builder);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TreeLeafHandle_getTreeNode(handle->leafHandle, &node);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}
	if (node == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "Leaf node is missing.");
		goto cleanup;
	}

	res = KSI_SignatureBuilder_setAggregationChainStartLevel(builder, node->level);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_SignatureBuilder_appendAggregationChain(builder, aggr);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_SignatureBuilder_close(builder, node->level, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_SignatureBuilder_free(builder);
	KSI_AggregationHashChain_free(aggr);
	KSI_Signature_free(tmp);

	return res;
}
