@ECHO OFF

CALL "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x86

nmake clean
nmake RTL=MTd DLL=lib NET_PROVIDER=WINHTTP CRYPTO_PROVIDER=CRYPTOAPI all test 

pause
