#
# Copyright 2013-2015 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.
#
#

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
EXTRA = CCEXTRA="$(CCEXTRA)" LDEXTRA="$(LDEXTRA)" OPENSSL_CA_FILE="$(OPENSSL_CA_FILE)" OPENSSL_CA_DIR="$(OPENSSL_CA_DIR)" CURL_DIR="$(CURL_DIR)" /S

SRC_DIR = src
TEST_DIR = test
OBJ_DIR = obj
OUT_DIR = out
LIB_DIR = $(OUT_DIR)\$(DLL)
BIN_DIR = $(OUT_DIR)\bin
VERSION_FILE = VERSION
VERSION_H = $(SRC_DIR)\ksi\version.h
COMM_ID_FILE = COMMIT_ID

VER = \
!INCLUDE <$(VERSION_FILE)>


!IF [git log -n1 --format="%H">$(COMM_ID_FILE)] == 0
COM_ID = \
!INCLUDE <$(COMM_ID_FILE)>
!MESSAGE Git OK. Include commit ID.
!IF [rm $(COMM_ID_FILE)] == 0
!MESSAGE File $(COMM_ID_FILE) deleted.
!ENDIF
!ELSE
!MESSAGE Git is not installed. 
!ENDIF 

default:
	cd $(SRC_DIR)\ksi
	nmake $(MODEL) $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)
	cd ..\..

all: version-h libraries example tests

libraries: libMT libMTd libMD libMDd dllMT dllMTd dllMD dllMDd


libMT:
	nmake DLL=lib RTL=MT $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

libMTd:
	nmake DLL=lib RTL=MTd $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

libMD:
	nmake DLL=lib RTL=MD $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

libMDd:
	nmake DLL=lib RTL=MDd $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

	

dllMT:
	nmake DLL=dll RTL=MT $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

dllMTd:
	nmake DLL=dll RTL=MTd $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

dllMD:
	nmake DLL=dll RTL=MD $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

dllMDd:
	nmake DLL=dll RTL=MDd $(EXTRA) VER=$(VER) COM_ID=$(COM_ID)

version-h:
	mkversion_h.bat $(VERSION_FILE) $(VERSION_H)

example: $(DLL)$(RTL)
	cd $(SRC_DIR)\example
	nmake $(MODEL) $(EXTRA)
	cd ..\..
	
tests: $(DLL)$(RTL)
	cd $(TEST_DIR)
	nmake $(MODEL) $(EXTRA)
	cd ..	

test: tests
	$(BIN_DIR)\alltests.exe test

resigner: $(DLL)$(RTL)
	cd $(TEST_DIR)
	nmake $(MODEL) $(EXTRA) resigner
	cd ..
	
clean:
	@for %i in ($(OBJ_DIR) $(OUT_DIR)) do @if exist .\%i rmdir /s /q .\%i
	@for %i in ($(SRC_DIR)\ksi $(SRC_DIR)\example $(TEST_DIR)) do @if exist .\%i\*.pdb del /q .\%i\*.pdb	
	@if exist .\$(VERSION_H) del /q .\$(VERSION_H)