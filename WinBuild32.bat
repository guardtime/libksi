GOTO copyrightend

    GUARDTIME CONFIDENTIAL

    Copyright (C) [2015] Guardtime, Inc
    All Rights Reserved

    NOTICE:  All information contained herein is, and remains, the
    property of Guardtime Inc and its suppliers, if any.
    The intellectual and technical concepts contained herein are
    proprietary to Guardtime Inc and its suppliers and may be
    covered by U.S. and Foreign Patents and patents in process,
    and are protected by trade secret or copyright law.
    Dissemination of this information or reproduction of this
    material is strictly forbidden unless prior written permission
    is obtained from Guardtime Inc.
    "Guardtime" and "KSI" are trademarks or registered trademarks of
    Guardtime Inc.

:copyrightend

@ECHO OFF

CALL "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x86

nmake clean
nmake RTL=MTd DLL=lib NET_PROVIDER=WINHTTP CRYPTO_PROVIDER=CRYPTOAPI all test 

pause
