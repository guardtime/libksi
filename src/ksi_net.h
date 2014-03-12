#ifndef KSI_TRANSPORT_H_
#define KSI_TRANSPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_NET_Handle_st {
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

	int (*readResponse)(KSI_NET_Handle *);

	/** Addidtional context for the trasnport layer. */
	void *netCtx;
};

#ifdef __cplusplus
}
#endif

#endif /* KSI_TRANSPORT_H_ */
