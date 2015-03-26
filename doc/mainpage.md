SDK Overview {#mainpage}
============

The SDK
-------

The SDK provides the following functionality:
* @ref hash "Data hashing functions",
* @ref base "Siging functions",
* @ref base "Signature verification functions",
* @ref base "Signature extending functions",
* Low-level functions for signature, request and response manipulation.

KSI Context
-----------

The KSI context #KSI_CTX is the central object. It contains configuration, logging support, error stack traces and more. The
context makes it possible to use the SDK safely in a multi-threaded application. The context may not be freed before all objects
created using this context are freed.

Every thread using the SDK must own at least one instance of #KSI_CTX, but the number is not limited. In order to maintain thread safety
one context may not be shared between contexts. Using multiple contexts however limits the scope where all the KSI object may be used.

All objects originating from one context should not be mixed with objects from an other context.
The context is created using #KSI_CTX_new which will create a new instance. The instance can be freed using #KSI_CTX_free after all
objects created using this context are freed.

Memory Management
-----------------

The memory management obeys the following rules:
* Every object you create, belongs to you.
* Every object you own, must be freed by you.
* Using setter methods you loose the ownership of the object.
* Replacing an existing value with a setter method, you are responsible for freeing the old value.
* Adding elements to lists you loose the ownership of the object.
* All pointers are returned using via pointer to pointer pointers.
* Using free function on \c NULL does nothing and won't crash.
* Constant input pointers will not change ownership.
* Every time you reference an object, a free must be called on it.

Logging
-------

The logging mechanism is based on a single callback function with three parameters (see #KSI_LoggerCallback). A simple
logging function #KSI_LOG_StreamLogger is included in the SDK, where the \c logCtx is meant to be a \c FILE pointer
to the output stream (may also be \c stdout or \c stderr). The stream has to be closed externally.

The callback is set with the #KSI_CTX_setLoggerCallback function. The log level can be changed using #KSI_CTX_setLogLevel. The
default logger is turned of and the output will be written to \c stdout, if the log level is changed to something other
than #KSI_LOG_NONE (e.g #KSI_LOG_DEBUG). For more information on log levels see #KSI_LOG_LVL_en.

Troubleshooting
---------------

There are several ways to troubleshoot problems related to the SDK.
* Logging
* #KSI_ERR_statusDump
* Status codes and #KSI_getErrorString
* #KSI_ERR_getBaseErrorMessage

Dependencies
------------

The SDK is using the following third party components:
* OpenSSL [openssl.org](http://www.openssl.org)
* cURL [curl.haxx.se](http://curl.haxx.se)

Acknowledgments
----------------

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (<a href="http://www.openssl.org/">www.openssl.org</a>).

This product includes cryptographic software written by Eric Young (eay@cryptsoft.com). This product includes software written by Tim Hudson (tjh@cryptsoft.com).

This product includes networking software developed by the cURL Project (<a href="http://curl.haxx.se/">curl.haxx.se</a>).

