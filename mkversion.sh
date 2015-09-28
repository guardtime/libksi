#!/bin/bash

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

old_version=$(cat VERSION)
VERSION=($(echo $old_version | tr "." " "))

echo "Old version: $old_version"

function inc {
	VERSION[$1]=$((${VERSION[$1]} + 1))
	i=$(($1 + 1))
	while [ $i -lt 3 ]; do
		VERSION[$i]=0
		i=$((i + 1))
	done;
}

if [ $# -ne 1 ]; then 
	echo "Usage $0 [major | minor | patch | build] ..."
	exit
fi

case "$1" in
	"major" )
		inc 0
		;;
	"minor" )
		inc 1
		;;
    "patch" )
		inc 2
		;;
	"build" )
		inc 3 
		;;
	*)
		echo "Unknown parameter"
		exit
		;;
esac

new_version=$(echo ${VERSION[@]} | tr " " ".")
echo "New version: $new_version"

tag="v$new_version"
echo "Tag: $tag"

git tag -a "$tag" -m "Auto-generated version $new_version"

echo $new_version  > VERSION
