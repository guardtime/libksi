@ECHO OFF

CALL "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x86

REM CURL_DIR and OPENSSL_DIR must contain include and lib directories. 
REM Runntime MT and MTd supported


SET CURL_DIR=C:\Users\Taavi\Documents\GuardTime\LIBS\libcurl-vc10-x86-debug-static-ipv6-sspi-spnego-winssl
SET OPENSSL_DIR=C:\Users\Taavi\Documents\GuardTime\LIBS\openssl-0.9.8g-win64
SET OPENSSL_CA_FILE=C:\Users\Taavi\Documents\GuardTime\ksi-c-api\test\resource\tlv\mock.crt



nmake clean
rem del out\bin\ksi_verify.exe
rem nmake RTL=MTd NET_PROVIDER=CURL CRYPTO_PROVIDER=CRYPTOAPI CURL_DIR="%CURL_DIR%" OPENSSL_CA_FILE="%OPENSSL_CA_FILE%" OPENSSL_DIR="%OPENSSL_DIR%" all
rem nmake RTL=MTd NET_PROVIDER=CURL TRUST_PROVIDER=OPENSSL HASH_PROVIDER=CRYPTOAPI CURL_DIR="%CURL_DIR%" OPENSSL_CA_FILE="%OPENSSL_CA_FILE%" OPENSSL_DIR="%OPENSSL_DIR%" test

nmake RTL=MTd NET_PROVIDER=WININET CRYPTO_PROVIDER=CRYPTOAPI OPENSSL_CA_FILE=C:\Users\Taavi\Documents\GuardTime\ksi-c-api\test\resource\tlv\mock.crt example
pause
