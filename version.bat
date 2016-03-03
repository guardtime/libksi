@echo OFF
goto copyrightend

	Copyright 2013-2016 Guardtime, Inc.
	
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

:: Check if version file exists
if not exist %1 goto:noparam
:: Check if target file argument is included
if [%2]==[] goto:noparam

set /p VERSION_STR=<%1
set TARGET_FILE=%2
@echo KSI C SDK version: %VERSION_STR%
@echo Generating new version file to: %TARGET_FILE%

for /F "tokens=1,2,3 delims=." %%a in ("%VERSION_STR%") do (
	echo.#define KSI_SDK_VER_MAJOR %%a  > %TARGET_FILE%
	echo.#define KSI_SDK_VER_MINOR %%b >> %TARGET_FILE%
	echo.#define KSI_SDK_VER_BUILD %%c >> %TARGET_FILE%
)


goto:eof

:noparam
@echo Parameter list inconsistent
@echo Usage: %~0 version_file target_file
@echo Ex:    %~0 VERSION src\ksi\version.h
exit /B 1

:eof