#!/bin/bash

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
	echo "Usage $0 [major | minor | build] ..."
	exit
fi

case "$1" in
	"major" )
		inc 0
		;;
	"minor" )
		inc 1
		;;
	"build" )
		inc 2 
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
