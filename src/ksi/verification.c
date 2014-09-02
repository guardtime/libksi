#include <string.h>
#include "internal.h"
#include "verification_impl.h"

int KSI_VerificationStepResult_success(KSI_VerificationStepResult *result) {
	KSI_ERR err;
	KSI_PRE(&err, result != NULL) goto cleanup;
	KSI_BEGIN(result->ctx, &err);

	KSI_LOG_debug(result->ctx, "Verification step %d succeeded.", (int)result->step);

	result->succeeded = true;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_VerificationStepResult_fail(KSI_VerificationStepResult *result, const char *description) {
	KSI_ERR err;
	KSI_PRE(&err, result != NULL) goto cleanup;
	KSI_BEGIN(result->ctx, &err);

	KSI_LOG_debug(result->ctx, "Verification step %d failed: .", (int)result->step, (description != NULL) ? description : "N/A");

	result->succeeded = false;
	strncpy(result->description, (description != NULL) ? description : "N/A", sizeof(result->description));

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

int KSI_VerificationResult_reset(KSI_VerificationResult *info) {
	int res = KSI_UNKNOWN_ERROR;

	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	info->stepsFailed = 0;
	info->stepsPerformed = 0;

	info->verifyDocumentHash = false;
	info->documentHash = NULL;

	info->useUserPublication = false;
	info->userPublication = NULL;

	info->steps_len = 0;

	KSI_DataHash_free(info->aggregationHash);
	info->aggregationHash = NULL;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationResult_init(KSI_CTX *ctx, KSI_VerificationResult *info) {
	int res = KSI_UNKNOWN_ERROR;
	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_VerificationResult_reset(info);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}


static int addVerificationStepResult(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc, bool succeeded) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationStepResult *result = NULL;
	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!succeeded) {
		info->stepsFailed |= step;
	}
	info->stepsPerformed |= step;
	result = info->steps + info->steps_len++;
	result->step = step;
	result->succeeded = succeeded;
	if (desc != NULL) {
		strncpy(result->description, desc, sizeof(result->description));
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationResult_addFailure(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc) {
	return addVerificationStepResult(info, step, desc, 0);
}

int KSI_VerificationResult_addSuccess(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc) {
	return addVerificationStepResult(info, step, desc, 1);
}

void KSI_VerificationResult_dump(KSI_VerificationResult *info) {
	int res;
	size_t i;

	if (info != NULL) {
		for (i = 0; i < info->steps_len; i++) {
			KSI_VerificationStepResult *result = info->steps + i;

			printf("step: %d\nresult: %s\ndesc: %s\n\n", result->step, result->succeeded ? "success": "fail", result->description);
		}
	} else {
		printf("Verification object is NULL\n");
	}

cleanup:
	if (res != KSI_OK) {
		fprintf(stderr, "\nUnknown error: %d\n", res);
	}
	return;
}
