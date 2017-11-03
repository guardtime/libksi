#!/bin/sh

#
# Copyright 2013-2017 Guardtime, Inc.
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

if [ $# -ne 1 ]; then
	echo "Usage:"
	echo "  $0 <path to test root>";
	exit 1;
fi;

if [ "z$CC" == "z" ]; then
	echo "Compiler variable CC not set.";
	exit 1;
fi;

testcount=0
failcount=0
logfile="include-test.log"

echo "Starting include tests." > $logfile;

for hfilefull in $(find "$1/../src/ksi/" -maxdepth 1 -name "*.h" | grep -v internal.h) 
do
	testcount=$((testcount+1));
	hfile="ksi/$(basename "$hfilefull")";
	echo -n "Testing autonomous include of $hfile... ";
	code=$(echo '#include "'$hfile'"'; echo 'int main() { return 0;}');
	echo >> $logfile;
	echo "Running code:" >> $logfile;
	echo "$code" >> $logfile;
	(echo "$code") | $CC -x c $CFLAGS - >> $logfile 2>&1; 
	if [ $? -eq 0 ]; 
	then
		echo " ok"; 
	else
		failcount=$((failcount + 1))
		echo " fail"; 
	fi;
done;

echo
echo "==== TEST RESULTS ===="
echo

if [ $failcount == 0 ]; then
	echo "OK ($testcount tests)";
	echo
else
	echo "!!!FAILURES!!!";
	echo "Runs: $testcount";
	echo "Passes: $(($testcount - $failcount))";
	echo "Fails: $failcount";
	echo
	exit 1
fi;

