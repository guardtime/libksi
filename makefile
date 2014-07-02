!IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
DLL = lib
!ENDIF
!IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
RTL = MT
!ENDIF


MODEL = DLL=$(DLL) RTL=$(RTL)
EXTRA = CCEXTRA="$(CCEXTRA)" LDEXTRA="$(LDEXTRA)" OPENSSL_CA_FILE="$(OPENSSL_CA_FILE)" OPENSSL_CA_DIR="$(OPENSSL_CA_DIR)" CURL_DIR="$(CURL_DIR)"

!IF "$(OPENSSL_CA_FILE)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_FILE=\"$(OPENSSL_CA_FILE:\=\\)\"
!ENDIF

!IF "$(OPENSSL_CA_DIR)" != ""
TRUSTSTORE_MACROS = $(TRUSTSTORE_MACROS) /DOPENSSL_CA_DIR=\"$(OPENSSL_CA_DIR:\=\\)\" 
!ENDIF

SRC_DIR = src
TEST_DIR = test
OBJ_DIR = obj
OUT_DIR = out
LIB_DIR = $(OUT_DIR)\$(DLL)
BIN_DIR = $(OUT_DIR)\bin



default:
	cd $(SRC_DIR)\ksi
	nmake $(MODEL) $(EXTRA)
	cd ..\..

all: librarys example tests

librarys: lib$(RTL)
	
	
libMT:
	nmake DLL=lib RTL=MT $(EXTRA)

libMTd:
	nmake DLL=lib RTL=MTd $(EXTRA)

	
example: lib$(RTL)
	cd $(SRC_DIR)\example
	nmake $(MODEL) $(EXTRA)
	cd ..\..
	
tests: lib$(RTL)
	cd $(TEST_DIR)
	nmake $(MODEL) $(EXTRA)
	cd ..	

test: tests
	$(BIN_DIR)\alltests.exe
	
clean:
	@for %i in ($(OBJ_DIR) $(OUT_DIR)) do @if exist .\%i rmdir /s /q .\%i
	@for %i in ($(SRC_DIR)\ksi $(SRC_DIR)\example $(TEST_DIR)) do @if exist .\%i\*.pdb del /q .\%i\*.pdb	
