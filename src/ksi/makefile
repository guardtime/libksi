!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

!IF "$(NET_PROVIDER)" != "CURL" && "$(NET_PROVIDER)" != "WININET" && "$(NET_PROVIDER)" != "WINHTTP"
NET_PROVIDER = CURL
!ENDIF

!IF "$(OPENSSL_CA_FILE)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_FILE=\"$(OPENSSL_CA_FILE:\=\\)\"
!ENDIF

!IF "$(OPENSSL_CA_DIR)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_DIR=\"$(OPENSSL_CA_DIR:\=\\)\" 
!ENDIF

SRC_DIR = .
OBJ_DIR = ..\..\obj$(RTL)
LIB_DIR = ..\..\out\$(DLL)
INCLUDE_DIR = ..\..\out\include\ksi


LIB_NAME = libksiapi

LIB_OBJ = \
	$(OBJ_DIR)\base.obj \
	$(OBJ_DIR)\base32.obj \
	$(OBJ_DIR)\crc32.obj \
	$(OBJ_DIR)\hash.obj \
	$(OBJ_DIR)\hash_openssl.obj \
	$(OBJ_DIR)\hashchain.obj \
	$(OBJ_DIR)\io.obj \
	$(OBJ_DIR)\list.obj \
	$(OBJ_DIR)\log.obj \
	$(OBJ_DIR)\net.obj \
	$(OBJ_DIR)\pkitruststore_openssl.obj \
	$(OBJ_DIR)\publicationsfile.obj \
	$(OBJ_DIR)\signature.obj \
	$(OBJ_DIR)\tlv.obj \
	$(OBJ_DIR)\tlv_template.obj \
	$(OBJ_DIR)\types.obj \
	$(OBJ_DIR)\types_base.obj

!IF "$(NET_PROVIDER)" == "CURL"
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_curl.obj
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_CURL
!ELSE IF "$(NET_PROVIDER)" == "WININET"
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_wininet.obj
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_WININET
!ELSE IF "$(NET_PROVIDER)" == "WINHTTP" 
LIB_OBJ = $(LIB_OBJ) $(OBJ_DIR)\net_http_winhttp.obj
CCFLAGS = $(CCFLAGS) /DKSI_NET_HTTP_IMPL=KSI_IMPL_WINHTTP
!ENDIF

CCFLAGS = $(CCFLAGS) /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /DCURL_STATICLIB /I$(SRC_DIR)\ksi /I$(SRC_DIR)\example /I$(SRC_DIR)
LDFLAGS = /NOLOGO /LIBPATH:$(LIB_DIR) 

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include" /I"$(CURL_DIR)\include"

CCFLAGS = $(CCFLAGS) $(CCEXTRA) $(TRUSTSTORE_MACROS)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)

default: $(LIB_DIR)\$(LIB_NAME)$(RTL).$(DLL) include

all: $(LIB_DIR)\$(LIB_NAME)$(RTL).$(DLL) include




$(LIB_DIR)\$(LIB_NAME)$(RTL).lib: $(OBJ_DIR) $(LIB_DIR) $(LIB_OBJ)  
	link /LIB /OUT:$@ $(LDFLAGS) $(LIB_OBJ)


	

{$(SRC_DIR)}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

	
include: $(INCLUDE_DIR)
	for /R $(SRC_DIR) %%f in (*.h) do copy "%%f" $(INCLUDE_DIR)
	
$(OBJ_DIR) $(LIB_DIR) $(INCLUDE_DIR):
	@if not exist $@ mkdir $@
	

