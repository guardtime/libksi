!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF

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

SRC_DIR = .
INCLUDE_DIR = ..\..\out\include
OBJ_DIR = ..\..\obj\$(RTL)
LIB_DIR = ..\..\out\$(DLL)
BIN_DIR = ..\..\out\bin


LIB_NAME = libksiapi


#obj files for example exe files  
EXAMPLE_OBJ = \
	$(OBJ_DIR)\ksi_sign.obj \
	$(OBJ_DIR)\ksi_extend.obj \
	$(OBJ_DIR)\ksi_pubfiledump.obj \
	$(OBJ_DIR)\ksi_verify.obj

#Output exe files. Must have the same base name as corresponding obj file. 
EXAMPLE_BIN = \
	$(BIN_DIR)\ksi_sign.exe \
	$(BIN_DIR)\ksi_extend.exe \
	$(BIN_DIR)\ksi_pubfiledump.exe \
	$(BIN_DIR)\ksi_verify.exe 

	
#external libraries used for linking. 
EXT_LIB = $(LIB_NAME)$(RTL).$(DLL) \
	wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib

!IF "$(NET_PROVIDER)" == "CURL"
EXT_LIB = $(EXT_LIB) libcurl$(RTL).lib 
!ELSE IF "$(NET_PROVIDER)" == "WININET"
EXT_LIB = $(EXT_LIB) wininet.lib 
!ELSE IF "$(NET_PROVIDER)" == "WINHTTP" 
EXT_LIB = $(EXT_LIB) winhttp.lib 
!ENDIF

!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).$(DLL) advapi32.lib  
!ENDIF

!IF "$(HASH_PROVIDER)" == "CRYPTOAPI" || "$(TRUST_PROVIDER)" == "CRYPTOAPI"
EXT_LIB = $(EXT_LIB) Crypt32.lib advapi32.lib
!ENDIF


#/NODEFAULTLIB:libcmtd.lib	
CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /DCURL_STATICLIB /I$(INCLUDE_DIR) /I$(SRC_DIR)
LDFLAGS = /NOLOGO /LIBPATH:$(LIB_DIR) 

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include" /I"$(CURL_DIR)\include"
!IF "$(DLL)" == "lib"
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\lib" 
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(CURL_DIR)\lib"
!ELSE
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(OPENSSL_DIR)\dll" 
LDFLAGS = $(LDFLAGS) /LIBPATH:"$(CURL_DIR)\dll"
!ENDIF
CCFLAGS = $(CCFLAGS) $(CCEXTRA)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)





default: $(EXAMPLE_BIN) 

#Linking obj files to exe files
$(EXAMPLE_BIN): $(OBJ_DIR)\$(@B).obj $(OBJ_DIR) $(BIN_DIR)
	link $(LDFLAGS)  /OUT:$@ $(OBJ_DIR)\$(@B).obj  $(EXT_LIB)

	
#Compiling c files to obj files
{$(SRC_DIR)}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

#Dir factory
$(OBJ_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@

