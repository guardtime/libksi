#!/bin/bash

#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2015] Guardtime, Inc
# All Rights Reserved
#
# NOTICE:  All information contained herein is, and remains, the
# property of Guardtime Inc and its suppliers, if any.
# The intellectual and technical concepts contained herein are
# proprietary to Guardtime Inc and its suppliers and may be
# covered by U.S. and Foreign Patents and patents in process,
# and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this
# material is strictly forbidden unless prior written permission
# is obtained from Guardtime Inc.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime Inc.
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
