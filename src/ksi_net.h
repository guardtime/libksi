#ifndef KSI_NET_H_
#define KSI_NET_H_

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_NetHandle_st {
	/** KSI context. */
	KSI_CTX *ctx;
	/** Request destination. */
	char *url;
	/** Original request. */
	unsigned char *request;
	/** Length of the original request. */
	int request_length;
	/** Response for the request. NULL if not yet present. */
	unsigned char *response;
	/** Length of the response. */
	int response_length;

	void (*netCtx_free)(void *);

	int (*readResponse)(KSI_NetHandle *);

	/** Addidtional context for the trasnport layer. */
	void *netCtx;
};

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_H_ */
