#!/bin/bash

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

set -e


 if [[ ( "$#" -gt 2 ) && ( "$#" -lt 5 ) ]]; then
    chlogpath="$1"
    controlpath="$2"
    outputpath="$3"
    distribution_quide=($4)
 else
    echo "Usage:"
    echo "  $0 <changelog path> <control file path> <output path> [<distribution guide>]"
    echo ""
    echo "Description:"
    echo "  This script takes a path to regular changelog and debian control files and"
    echo "  creates a debian changelog file that is written to the specified output."
    echo ""
    echo ""
    echo "Fields:"
    echo "  changelog path"
    echo "       - Path to changelog file that is used for debian changelog generation."
    echo ""
    echo "  control file path"
    echo "       - Path to debian control file."
    echo ""
    echo "  output path"
    echo "       - Output path for debian changelog. Will overwrite existing file!"
    echo ""
    echo "  distribution guide"
    echo "        - Array of distribution guides. As debian changelog needs a field for."
    echo "          distribution (e.g. stable, unstable). To change the default values"
    echo "          a list of release versions and distribution value pairs must be specified."
    echo "          When distribution value changes after a version X, it must only specified at"
    echo "          once as next releases uses the previous distribution value. Note that distribution"
    echo "          UNREALESED will never be included to the debian changelog."
    echo ""
    echo "          For example '0.1.0:UNRELEASED 1.2.1:unstable 1.2.11:stable' will create a"
    echo "          changelog where first releases were actually never released until 1.2.1 where"
    echo "          the package was distributed for unstable until version 1.2.11."
    echo ""
    echo ""
    echo "Example:"
    echo "  Rebuild changelog so that every release is marked as default distribution (unstable):"
    echo "    rebuild_changelog.sh changelog packaging/deb/control packaging/deb/changelog"
    echo ""
    echo "  Rebuild changelog so that some of the first releases are not included (as the release" 
    echo "  were never made under debian):"
    echo "    rebuild_changelog.sh changelog packaging/deb/control packaging/deb/changelog"
    echo "    '0.0.32:UNRELEASED 1.0.0:unstable'"
    exit
 fi






tmpdir=tmp_chlog
rm -fr $tmpdir

# Create a tmp directory as dch needs special directory structure to work with.
# It is not possible to specify control file from command-line.
mkdir -p $tmpdir/debian
cp $controlpath $tmpdir/debian
rela_changelog_path=$(realpath $chlogpath)
cd $tmpdir



is_first=true
is_unreleased=false
extra_release_commands=""
array=()

# Reverse the changelog file and begin with the oldest release (unreleased change are not included).
while read line; do
  # Look for the line that contains The Release.
  # If it's not release, it must be release content.
  if [[ $line =~ ([0-9]{1,4}[-][0-9]{1,2}[-][0-9]{1,2}).*release.*[(](.*)[)] ]] ; then
    time_string=$(date -R -d "${BASH_REMATCH[1]}")
    version_str="${BASH_REMATCH[2]}"

    # Check if distribution name has to be changed.
    for key in "${distribution_quide[@]}"; do
      if [[ $key == "$version_str:"* ]]; then
        dist=$(echo $key| cut -d':' -f 2)
        extra_release_commands="--force-distribution -D $dist"
        if [[ $dist == "UNRELEASED" ]]; then
            is_unreleased=true
        else
            is_unreleased=false
        fi
        
        echo "  * Changing distribution to: $dist."
      fi
    done;

    # If distribution is UNRELEASED, just give a warning and do nothing as the records will be ignored anyway.
    if $is_unreleased ; then
        echo "Warning: distribution is 'UNREALESED'. Version $version_str is not included to changelog."
    else
        echo "Appending new release: v$version_str $time_string"

        # If this is the first release, create empty changelog file.
        if $is_first ; then
          dch --create --package libksi --newversion "$version_str" --urgency low --controlmaint "${array[-1]}"
        else
          dch --controlmaint -v "$version_str" --urgency low "${array[-1]}"
        fi

        # Append release record.
        for ((i=${#array[@]}-2; i>=0; i--)); do
          dch -a --nomultimaint --controlmaint "${array[$i]}"
        done

        # Make a release, change time.
        dch --controlmaint --release $extra_release_commands ""
        sed -i "0,/>.*/s/>.*/>  $time_string/" debian/changelog

        is_first=false
    fi

    # Clean array.
    array=()
  elif [[ $line == \** ]] ; then
    array+=("${line:2}")
  fi
done <<< $(tac -r $rela_changelog_path)

cd ..
cp $tmpdir/debian/changelog $outputpath
