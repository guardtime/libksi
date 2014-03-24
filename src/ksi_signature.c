#include "ksi_internal.h"

void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_free(sig);
	}
}

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *data, int data_len, KSI_Signature **sig) {
	KSI_LOG_fatal(ctx, "Unimplemented");
	int res;


	/* TODO! */
	return KSI_OK;
}
