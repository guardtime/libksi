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
OBJ_DIR = ..\obj\$(DLL)$(RTL)
INC_DIR = ..\out\include
LIB_DIR = ..\out\$(DLL)
BIN_DIR = ..\out\bin
CUTEST_DIR = cutest

LIB_NAME = libksiapi

#Objects used to make testing programs
ALLTESTS_OBJ = \
	$(OBJ_DIR)\all_tests.obj \
	$(OBJ_DIR)\ksi_ctx_test.obj \
	$(OBJ_DIR)\ksi_hash_test.obj \
	$(OBJ_DIR)\ksi_hashchain_test.obj \
	$(OBJ_DIR)\ksi_publicationsfile_test.obj \
	$(OBJ_DIR)\ksi_net_mock.obj \
	$(OBJ_DIR)\ksi_net_test.obj \
	$(OBJ_DIR)\ksi_rdr_test.obj \
	$(OBJ_DIR)\ksi_signature_test.obj \
	$(OBJ_DIR)\ksi_tlv_sample_test.obj \
	$(OBJ_DIR)\ksi_tlv_test.obj \
	$(OBJ_DIR)\ksi_truststore_test.obj \
	$(OBJ_DIR)\ksi_hmac_test.obj \
	$(OBJ_DIR)\CuTest.obj

	
#Compiler and linker configuration
#external libraries used for linking. 
EXT_LIB = $(LIB_NAME)$(RTL).lib \
	wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib

!IF "$(DLL)" == "lib"

!IF "$(NET_PROVIDER)" == "CURL"
EXT_LIB = $(EXT_LIB) libcurl$(RTL).lib
CCFLAGS = $(CCFLAGS) /LIBPATH:"$(CURL_DIR)\$(DLL)" 

!ELSE IF "$(NET_PROVIDER)" == "WININET"
EXT_LIB = $(EXT_LIB) wininet.lib
 
!ELSE IF "$(NET_PROVIDER)" == "WINHTTP" 
EXT_LIB = $(EXT_LIB) winhttp.lib 
!ENDIF

!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).lib advapi32.lib  
!ENDIF

!IF "$(HASH_PROVIDER)" == "CRYPTOAPI" || "$(TRUST_PROVIDER)" == "CRYPTOAPI"
EXT_LIB = $(EXT_LIB) Crypt32.lib advapi32.lib
!ENDIF

!ENDIF



#/NODEFAULTLIB:libcmtd.lib
CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) /I$(INC_DIR) /I$(CUTEST_DIR)
LDFLAGS = /NOLOGO /LIBPATH:$(LIB_DIR) 

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF

CCFLAGS = $(CCFLAGS) $(CCEXTRA) 
LDFLAGS = $(LDFLAGS) $(LDEXTRA)


 

default: $(BIN_DIR)\alltests.exe 


$(BIN_DIR)\alltests.exe: $(BIN_DIR) $(ALLTESTS_OBJ)
	link $(LDFLAGS) /OUT:$@ $(ALLTESTS_OBJ) $(EXT_LIB) 
!IF "$(DLL)" == "dll"
	xcopy "$(LIB_DIR)\libksiapi$(RTL).dll" "$(BIN_DIR)\" /Y /D
!ENDIF

	
	
#Creates OBJ_DIR for ALLTESTS_OBJ
$(ALLTESTS_OBJ): $(OBJ_DIR)

#C file compilation  	
{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

{$(CUTEST_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

#Folder factory	
$(OBJ_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@
