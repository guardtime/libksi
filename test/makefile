!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF


!IF "$(OPENSSL_CA_FILE)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_FILE=\"$(OPENSSL_CA_FILE:\=\\)\"
!ENDIF

!IF "$(OPENSSL_CA_DIR)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_DIR=\"$(OPENSSL_CA_DIR:\=\\)\" 
!ENDIF

SRC_DIR = .
OBJ_DIR = ..\obj
INC_DIR = ..\out\include
LIB_DIR = ..\out\$(DLL)
BIN_DIR = ..\out\bin
CUTEST_DIR = cutest


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
	$(OBJ_DIR)\CuTest.obj

	
#Compiler and linker configuration
EXT_LIB = libeay32$(RTL).lib \
	user32.lib gdi32.lib \
	libksiapi$(RTL).$(DLL) libcurl$(RTL).lib 
	


CCFLAGS = /nologo /W3 /D_CRT_SECURE_NO_DEPRECATE /DCURL_STATICLIB /I$(SRC_DIR) /I$(INC_DIR) /I$(CUTEST_DIR)
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
CCFLAGS = $(CCFLAGS) $(CCEXTRA) $(TRUSTSTORE_MACROS)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)


 

default: $(BIN_DIR)\alltests.exe 


$(BIN_DIR)\alltests.exe: $(BIN_DIR) $(ALLTESTS_OBJ)
	link $(LDFLAGS) /OUT:$@ $(ALLTESTS_OBJ) $(EXT_LIB) 

	
	
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
