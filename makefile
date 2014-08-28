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

MODEL = DLL=$(DLL) RTL=$(RTL) NET_PROVIDER=$(NET_PROVIDER) CRYPTO_PROVIDER=$(CRYPTO_PROVIDER) TRUST_PROVIDER="$(TRUST_PROVIDER)" HASH_PROVIDER="$(HASH_PROVIDER)"

EXTRA = CCEXTRA="$(CCEXTRA)" LDEXTRA="$(LDEXTRA)" OPENSSL_CA_FILE="$(OPENSSL_CA_FILE)" OPENSSL_CA_DIR="$(OPENSSL_CA_DIR)" CURL_DIR="$(CURL_DIR)"

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

librarys: libMT libMTd libMD libMDd
	
	
libMT:
	nmake DLL=lib RTL=MT $(EXTRA)

libMTd:
	nmake DLL=lib RTL=MTd $(EXTRA)

libMD:
	nmake DLL=lib RTL=MD $(EXTRA)

libMDd:
	nmake DLL=lib RTL=MDd $(EXTRA)
	
	
example: $(DLL)$(RTL)
	cd $(SRC_DIR)\example
	nmake $(MODEL) $(EXTRA)
	cd ..\..
	
tests: $(DLL)$(RTL)
	cd $(TEST_DIR)
	nmake $(MODEL) $(EXTRA)
	cd ..	

test: tests
	$(BIN_DIR)\alltests.exe
	
clean:
	@for %i in ($(OBJ_DIR)MT $(OBJ_DIR)MTd $(OBJ_DIR)MD $(OBJ_DIR)MDd $(OUT_DIR)) do @if exist .\%i rmdir /s /q .\%i
	@for %i in ($(SRC_DIR)\ksi $(SRC_DIR)\example $(TEST_DIR)) do @if exist .\%i\*.pdb del /q .\%i\*.pdb	
