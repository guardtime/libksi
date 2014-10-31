!IFNDEF DLL
DLL = lib
!ELSE IF "$(DLL)" != "lib" && "$(DLL)" != "dll"
!ERROR DLL can only have values "lib" or "dll" but it is "$(DLL)". Default value is "lib".
!ENDIF

!IFNDEF RTL
RTL = MT
!ELSE IF "$(RTL)" != "MT" && "$(RTL)" != "MTd" && "$(RTL)" != "MD" && "$(RTL)" != "MDd"
!ERROR RTL can only have one of the following values "MT", "MTd", "MD" or "MDd", but it is "$(RTL)". Default valu is "MT".
!ENDIF

!IFNDEF NET_PROVIDER
!MESSAGE NET_PROVIDER to default
NET_PROVIDER = CURL
!ELSE IF "$(NET_PROVIDER)" != "CURL" && "$(NET_PROVIDER)" != "WININET" && "$(NET_PROVIDER)" != "WINHTTP"
!ERROR NET_PROVIDER can only have one of the following values "CURL", "WININET" or "WINHTTP" but it is "$(NET_PROVIDER). Default value is "CURL".
!ENDIF

!IFDEF CRYPTO_PROVIDER
!MESSAGE CRYPTO_PROVIDER SET
TRUST_PROVIDER = $(CRYPTO_PROVIDER)
HASH_PROVIDER = $(CRYPTO_PROVIDER)
!ENDIF

!IFNDEF HASH_PROVIDER
!MESSAGE HASH_PROVIDER to default
HASH_PROVIDER = OPENSSL
!ELSE IF "$(HASH_PROVIDER)" != "OPENSSL" && "$(HASH_PROVIDER)" != "CRYPTOAPI"
!ERROR HASH_PROVIDER can only have values "OPENSSL" or "CRYPTOAPI" but it is "$(HASH_PROVIDER)". Default value is OPENSSL.
!ENDIF

!IFNDEF TRUST_PROVIDER
!MESSAGE TRUST_PROVIDER to default
TRUST_PROVIDER = OPENSSL
!ELSE IF "$(TRUST_PROVIDER)" != "OPENSSL" && "$(TRUST_PROVIDER)" != "CRYPTOAPI"
!ERROR TRUST_PROVIDER can only have values "OPENSSL" or "CRYPTOAPI" but it is "$(TRUST_PROVIDER)". Default value is OPENSSL.
!ENDIF

MODEL = DLL="$(DLL)" RTL="$(RTL)" NET_PROVIDER="$(NET_PROVIDER)" CRYPTO_PROVIDER="$(CRYPTO_PROVIDER)" TRUST_PROVIDER="$(TRUST_PROVIDER)" HASH_PROVIDER="$(HASH_PROVIDER)"
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

all: libraries example tests

libraries: libMT libMTd libMD libMDd dllMT dllMTd dllMD dllMDd
	
	
libMT:
	nmake DLL=lib RTL=MT $(EXTRA) 

libMTd:
	nmake DLL=lib RTL=MTd $(EXTRA)

libMD:
	nmake DLL=lib RTL=MD $(EXTRA)

libMDd:
	nmake DLL=lib RTL=MDd $(EXTRA)

	

dllMT:
	nmake DLL=dll RTL=MT $(EXTRA)

dllMTd:
	nmake DLL=dll RTL=MTd $(EXTRA)	

dllMD:
	nmake DLL=dll RTL=MD $(EXTRA)	

dllMDd:
	nmake DLL=dll RTL=MDd $(EXTRA)	

	
	
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
	@for %i in ($(OBJ_DIR) $(OUT_DIR)) do @if exist .\%i rmdir /s /q .\%i
	@for %i in ($(SRC_DIR)\ksi $(SRC_DIR)\example $(TEST_DIR)) do @if exist .\%i\*.pdb del /q .\%i\*.pdb	
