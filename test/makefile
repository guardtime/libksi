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
KSI_INCLUDE_DIR = ../src

LIB_NAME = libksiapi

#Objects used to make testing programs
ALLTESTS_OBJ = \
	$(OBJ_DIR)\all_tests.obj \
	$(OBJ_DIR)\ksi_ctx_test.obj \
	$(OBJ_DIR)\ksi_hash_test.obj \
	$(OBJ_DIR)\ksi_hashchain_test.obj \
	$(OBJ_DIR)\ksi_publicationsfile_test.obj \
	$(OBJ_DIR)\ksi_net_test.obj \
	$(OBJ_DIR)\ksi_rdr_test.obj \
	$(OBJ_DIR)\ksi_signature_test.obj \
	$(OBJ_DIR)\ksi_signature_builder_test.obj \
	$(OBJ_DIR)\ksi_tlv_sample_test.obj \
	$(OBJ_DIR)\ksi_tlv_test.obj \
	$(OBJ_DIR)\ksi_truststore_test.obj \
	$(OBJ_DIR)\ksi_tree_builder_test.obj \
	$(OBJ_DIR)\ksi_hmac_test.obj \
	$(OBJ_DIR)\CuTest.obj \
	$(OBJ_DIR)\compatibility_test.obj \
	$(OBJ_DIR)\uri_client_test.obj \
	$(OBJ_DIR)\support_tests.obj \
	$(OBJ_DIR)\multi_signature_test.obj \
	$(OBJ_DIR)\verification_rule_tests.obj \
	$(OBJ_DIR)\ksi_policy_test.obj \
	$(OBJ_DIR)\ksi_sdk_version_test.obj \
	$(OBJ_DIR)\ksi_flags_test.obj \
	$(OBJ_DIR)\ksi_blocksigner_test.obj

INTTESTS_OBJ = \
	$(OBJ_DIR)\all_integration_tests.obj \
	$(OBJ_DIR)\aggre_integration_test.obj \
	$(OBJ_DIR)\ext_integration_tests.obj \
	$(OBJ_DIR)\pub_integration_tests.obj \
	$(OBJ_DIR)\support_tests.obj \
	$(OBJ_DIR)\CuTest.obj

RESIGNER_OBJ = \
	$(OBJ_DIR)\resigner.obj

#Compiler and linker configuration
#external libraries used for linking.
EXT_LIB = $(LIB_NAME)$(RTL).lib \
	wsock32.lib wldap32.lib winmm.lib user32.lib gdi32.lib

!IF "$(DLL)" == "lib"

!IF "$(NET_PROVIDER)" == "CURL"
EXT_LIB = $(EXT_LIB) libcurl$(RTL).lib
LDFLAGS = $(LDFLAGS) /LIBPATH:$(CURL_DIR)\$(DLL)

!ELSE IF "$(NET_PROVIDER)" == "WININET"
EXT_LIB = $(EXT_LIB) wininet.lib

!ELSE IF "$(NET_PROVIDER)" == "WINHTTP"
EXT_LIB = $(EXT_LIB) winhttp.lib
!ENDIF

!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
EXT_LIB = $(EXT_LIB) libeay32$(RTL).lib advapi32.lib
LDFLAGS = $(LDFLAGS) /LIBPATH:$(OPENSSL_DIR)\$(DLL)
CCFLAGS = $(CCFLAGS) /I"$(OPENSSL_DIR)\include"
!ENDIF

!IF "$(HASH_PROVIDER)" == "CRYPTOAPI" || "$(TRUST_PROVIDER)" == "CRYPTOAPI"
EXT_LIB = $(EXT_LIB) Crypt32.lib advapi32.lib
!ENDIF

!ENDIF

#/NODEFAULTLIB:libcmtd.lib
CCFLAGS = $(CCFLAGS) /nologo /D_CRT_SECURE_NO_DEPRECATE /I$(SRC_DIR) /I$(INC_DIR) /I$(CUTEST_DIR)
LDFLAGS = $(LDFLAGS) /NOLOGO /LIBPATH:$(LIB_DIR)

!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
CCFLAGS = $(CCFLAGS) /DNDEBUG /O2
LDFLAGS = $(LDFLAGS) /RELEASE
!ELSE
CCFLAGS = $(CCFLAGS) /D_DEBUG /Od /RTC1 /Zi
LDFLAGS = $(LDFLAGS) /DEBUG
!ENDIF

CCFLAGS = $(CCFLAGS) $(CCEXTRA)
LDFLAGS = $(LDFLAGS) $(LDEXTRA)




default: $(BIN_DIR)\alltests.exe $(BIN_DIR)\integrationtests.exe

resigner: $(BIN_DIR)\resigner.exe

$(BIN_DIR)\alltests.exe: $(BIN_DIR) $(ALLTESTS_OBJ)
	link $(LDFLAGS) /OUT:$@ $(ALLTESTS_OBJ) $(EXT_LIB)
!IF "$(DLL)" == "dll"
	copy "$(LIB_DIR)\libksiapi$(RTL).dll" "$(BIN_DIR)\" /Y /D
!IF "$(NET_PROVIDER)" == "CURL"
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl.dll" /Y
!ELSE
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl_debug.dll" /Y
!ENDIF
!ENDIF
!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
	copy "$(OPENSSL_DIR)\$(DLL)\libeay32$(RTL).dll" "$(BIN_DIR)\libeay32.dll" /Y
!ENDIF
!ENDIF


$(BIN_DIR)\integrationtests.exe: $(BIN_DIR) $(INTTESTS_OBJ)
	link $(LDFLAGS) /OUT:$@ $(INTTESTS_OBJ) $(EXT_LIB)
!IF "$(DLL)" == "dll"
	copy "$(LIB_DIR)\libksiapi$(RTL).dll" "$(BIN_DIR)\" /Y /D
!IF "$(NET_PROVIDER)" == "CURL"
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl.dll" /Y
!ELSE
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl_debug.dll" /Y
!ENDIF
!ENDIF
!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
	copy "$(OPENSSL_DIR)\$(DLL)\libeay32$(RTL).dll" "$(BIN_DIR)\libeay32.dll" /Y
!ENDIF
!ENDIF


$(BIN_DIR)\resigner.exe: $(BIN_DIR) $(RESIGNER_OBJ)
	link $(LDFLAGS) /OUT:$@ $(RESIGNER_OBJ) $(EXT_LIB)
!IF "$(DLL)" == "dll"
	copy "$(LIB_DIR)\libksiapi$(RTL).dll" "$(BIN_DIR)\" /Y /D
!IF "$(NET_PROVIDER)" == "CURL"
!IF "$(RTL)" == "MT" || "$(RTL)" == "MD"
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl.dll" /Y
!ELSE
	copy "$(CURL_DIR)\$(DLL)\libcurl$(RTL).dll" "$(BIN_DIR)\libcurl_debug.dll" /Y
!ENDIF
!ENDIF
!IF "$(HASH_PROVIDER)" == "OPENSSL" || "$(TRUST_PROVIDER)" == "OPENSSL"
	copy "$(OPENSSL_DIR)\$(DLL)\libeay32$(RTL).dll" "$(BIN_DIR)\libeay32.dll" /Y
!ENDIF
!ENDIF



#Creates OBJ_DIR for ALLTESTS_OBJ
$(ALLTESTS_OBJ): $(OBJ_DIR)

#Creates OBJ_DIR for RESIGNER_OBJ
$(RESIGNER_OBJ): $(OBJ_DIR)


#C file compilation
{$(SRC_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

{$(CUTEST_DIR)\}.c{$(OBJ_DIR)\}.obj:
	cl /c /$(RTL) $(CCFLAGS) /Fo$@ $<

#Folder factory
$(OBJ_DIR) $(BIN_DIR):
	@if not exist $@ mkdir $@
