#Selecting of C Run-Time library and output format. 
!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

#Selecting of different functionality providers
!IF "$(NET_PROVIDER)" != "CURL" && "$(NET_PROVIDER)" != "WININET" && "$(NET_PROVIDER)" != "WINHTTP"
NET_PROVIDER = CURL
!ENDIF

!IF "$(HASH_PROVIDER)" != "OPENSSL" && "$(HASH_PROVIDER)" != "CRYPTOAPI"
HASH_PROVIDER = OPENSSL
!ENDIF

!IF "$(TRUST_PROVIDER)" != "OPENSSL" && "$(TRUST_PROVIDER)" != "CRYPTOAPI"
TRUST_PROVIDER = OPENSSL
!ENDIF

!IF "$(CRYPTO_PROVIDER)" == "OPENSSL" || "$(CRYPTO_PROVIDER)" == "CRYPTOAPI"
TRUST_PROVIDER = "$(CRYPTO_PROVIDER)"
HASH_PROVIDER = "$(CRYPTO_PROVIDER)"
!ENDIF

!IF "$(OPENSSL_CA_FILE)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_FILE=\"$(OPENSSL_CA_FILE:\=\\)\"
!ENDIF

!IF "$(OPENSSL_CA_DIR)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_DIR=\"$(OPENSSL_CA_DIR:\=\\)\" 
!ENDIF

SRC_DIR = .
OBJ_DIR = ..\..\obj\$(DLL)$(RTL)
LIB_DIR = ..\..\out\$(DLL)
INCLUDE_DIR = ..\..\out\include\ksi
EXLUDED_INCS = $(SRC_DIR)\exluded_includes.txt
LIB_DEF = $(SRC_DIR)\libksiapi.def

LIB_NAME = libksiapi

LIB_OBJ = \
	$(OBJ_DIR)\base.obj \
	$(OBJ_DIR)\base32.obj \
	$(OBJ_DIR)\crc32.obj \
	$(OBJ_DIR)\hash.obj \
	$(OBJ_DIR)\hashchain.obj \
	$(OBJ_DIR)\io.obj \
	$(OBJ_DIR)\list.obj \
	$(OBJ_DIR)\log.obj \
	$(OBJ_DIR)\net.obj \
	$(OBJ_DIR)\net_http.obj \
	$(OBJ_DIR)\publicationsfile.obj \
	$(OBJ_DIR)\signature.obj \
	$(OBJ_DIR)\tlv.obj \
	$(OBJ_DIR)\tlv_template.obj \
	$(OBJ_DIR)\types.obj \
	$(OBJ_DIR)\types_base.obj \
	$(OBJ_DIR)\verification.obj \
	$(OBJ_DIR)\hmac.obj

#Compiler and linker configuration
EXT_LIB = wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib  

!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include"
!IF "$(DLL)" == "dll"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\$(DLL)"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).lib advapi32.lib  
!ENDIF
!ENDIF

!IF "$(HASH_PROVIDER)" == "CRYPTOAPI" || "$(TRUST_PROVIDER)" == "CRYPTOAPI"
EXT_LIB = $(EXT_LIB) Crypt32.lib advapi32.lib
!ENDIF

	
#Configuration of net provider	
!IF "$(NET_PROVIDER)"=="CURL"
CCFLAGS = /I"$(CURL_DIR)\include"
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_CURL
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_curl.obj
!IF "$(DLL)" == "dll"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(CURL_DIR)\$(DLL)"
EXT_LIB = $(EXT_LIB) libcurl$(RTL).lib
CCFLAGS = $(CCFLAGS) /DCURL_STATICLIB
!ELSE
CCFLAGS = $(CCFLAGS) /DCURL_STATICLIB
!ENDIF

!ELSE IF "$(NET_PROVIDER)" == "WININET"
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_WININET
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_wininet.obj
EXT_LIB = $(EXT_LIB) wininet.lib

!ELSE IF "$(NET_PROVIDER)" == "WINHTTP" 
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_WINHTTP
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_winhttp.obj
EXT_LIB = $(EXT_LIB) winhttp.lib 
!ENDIF

#Selecting of hash provider
!IF "$(HASH_PROVIDER)"=="OPENSSL"
CCFLAGS = $(CCFLAGS) /DKSI_HASH_IMPL=KSI_IMPL_OPENSSL
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\hash_openssl.obj
!ELSE IF "$(HASH_PROVIDER)"=="CRYPTOAPI"
CCFLAGS = $(CCFLAGS) /DKSI_HASH_IMPL=KSI_IMPL_CRYPTOAPI
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\hash_cryptoapi.obj
!ENDIF

#Selecting of trust provider
!IF "$(TRUST_PROVIDER)"=="OPENSSL"
CCFLAGS = $(CCFLAGS) /DKSI_PKI_TRUSTSTORE_IMPL=KSI_IMPL_OPENSSL
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\pkitruststore_openssl.obj
!ELSE IF "$(TRUST_PROVIDER)"=="CRYPTOAPI"
CCFLAGS = $(CCFLAGS) /DKSI_PKI_TRUSTSTORE_IMPL=KSI_IMPL_CRYPTOAPI
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\pkitruststore_cryptoapi.obj
!ENDIF


CCFLAGS = $(CCFLAGS) /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR)\ksi /I$(SRC_DIR)\example /I$(SRC_DIR)
LDFLAGS = $(LDFLAGS) /NOLOGO /LIBPATH:$(LIB_DIR) 

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF


CCFLAGS = $(CCFLAGS) $(CCEXTRA) $(TRUSTSTORE_MACROS)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)

default: $(LIB_DIR)\$(LIB_NAME)$(RTL).$(DLL) include

all: $(LIB_DIR)\$(LIB_NAME)$(RTL).$(DLL) include


$(LIB_DIR)\$(LIB_NAME)$(RTL).lib: $(OBJ_DIR) $(LIB_DIR) $(LIB_OBJ)  
	link /LIB /OUT:$@ $(LDFLAGS) $(LIB_OBJ)

$(LIB_DIR)\$(LIB_NAME)$(RTL).dll: $(OBJ_DIR) $(LIB_DIR) $(LIB_OBJ) $(LIB_DEF)
	link /DLL /OUT:$@ /IMPLIB:$*.lib /DEF:$(LIB_DEF) $(LDFLAGS) $(LIB_OBJ) $(EXT_LIB)
	

{$(SRC_DIR)}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

	
include: $(INCLUDE_DIR)
	if not exist $(INCLUDE_DIR)\*.h for /R $(SRC_DIR) %%f in (*.h) do xcopy "%%f" $(INCLUDE_DIR) /D /EXCLUDE:$(EXLUDED_INCS)
	
$(OBJ_DIR) $(LIB_DIR) $(INCLUDE_DIR):
	@if not exist $@ mkdir $@
	

