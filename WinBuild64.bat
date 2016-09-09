GOTO copyrightend

	Copyright 2013-2015 Guardtime, Inc.
	
	This file is part of the Guardtime client SDK.
	
	Licensed under the Apache License, Version 2.0 (the "License").
	You may not use this file except in compliance with the License.
	You may obtain a copy of the License at
	    http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
	express or implied. See the License for the specific language governing
	permissions and limitations under the License.
	"Guardtime" and "KSI" are trademarks or registered trademarks of
	Guardtime, Inc., and no license to trademarks is granted; Guardtime
	reserves and retains all trademark rights.

:copyrightend

@ECHO OFF

CALL "%ProgramW6432%\Microsoft SDKs\Windows\v7.1\Bin\SetEnv.cmd" /x64

REM Set the aggregation PDU version according to your aggregator.
SET KSI_AGGREGATION_PDU_VERSION=KSI_PDU_VERSION_1
REM Set the extending PDU version according to your extender.
SET KSI_EXTENDING_PDU_VERSION=KSI_PDU_VERSION_1

nmake clean
nmake RTL=MTd DLL=lib NET_PROVIDER=WINHTTP CRYPTO_PROVIDER=CRYPTOAPI all memtest 

pause
