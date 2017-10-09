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


# Get version number.
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)
RELEASE_VERSION="$(lsb_release -is)$(lsb_release -rs | grep -Po "[0-9]{1,3}" | head -1)"
PKG_VERSION=1
DEB_DIR=packaging/deb

autoreconf -if
./configure $conf_args
make clean
make dist


# Rebuild debian changelog.
if command  -v dch > /dev/null; then
  echo "Generating debian changelog..."
  $DEB_DIR/rebuild_changelog.sh changelog $DEB_DIR/control libksi $DEB_DIR/changelog "3.2.1.0:UNRELEASED  3.15.2306:unstable"
else
  >&2 echo "Error: Unable to generate Debian changelog file as dch is not installed!"
  >&2 echo "Install devscripts 'apt-get install devscripts'"
  exit 1
fi

tar xvfz libksi-$VER.tar.gz
mv libksi-$VER.tar.gz libksi-$VER.orig.tar.gz
mkdir libksi-$VER/debian
cp $DEB_DIR/control $DEB_DIR/changelog $DEB_DIR/rules $DEB_DIR/copyright libksi-$VER/debian
chmod +x libksi-$VER/debian/rules
cd libksi-$VER
debuild -us -uc
cd ..

suffix=${VER}-${PKG_VERSION}.${RELEASE_VERSION}_${ARCH}
mv libksi_${VER}_${ARCH}.changes libksi_$suffix.changes
mv libksi_${VER}_${ARCH}.deb libksi_$suffix.deb
mv libksi-dev_${VER}_${ARCH}.deb libksi-dev_$suffix.deb

rm -rf libksi-$VER

