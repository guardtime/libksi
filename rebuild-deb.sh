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

set -e


#Get version number
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)
PKG_VERSION=1


# Source directories.
include_dir=src/ksi
lib_dir=src/ksi/.libs
deb_dir=packaging/deb


# Destination directories where the runtime library is installed.
lib_install_dir=usr/lib
lib_doc_install_dir=usr/share/doc/libksi-$VER
dev_inc_install_dir=usr/include/ksi
dev_doc_install_dir=usr/share/doc/libksi-$VER
pconf_install_dir=usr/lib/pkgconfig


# Temporary directories for deb package build.
tmp_dir_lib=$deb_dir/tmp_lib
tmp_dir_dev=$deb_dir/tmp_dev
tmp_dir_src=$deb_dir/tmp_src


# File list for libksi installion:
#   libksi_libs - shared library for runtime, installed with libksi package.
#   libksi_changelog_license - changelog and license, installed with libksi (dependency for libksi-dev) package.
#   libksi_dev_libs - static libraries, installed with libksi-dev package.
#   libksi_dev_doc - doxygen documentation, installed with libksi-dev package.
#   libksi_pckg_config - package configuration file, installed with libksi-dev package.
#   libksi_dev_includes - include files, installed with libksi-dev package.


libksi_libs="\
	$lib_dir/libksi.so \
	$lib_dir/libksi.so.*"

libksi_changelog_license="\
	changelog \
	license.txt"

libksi_dev_libs="\
	$lib_dir/libksi.a \
	$lib_dir/../libksi.la"

libksi_dev_doc="\
	doc/html/"

libksi_pckg_config="\
	libksi.pc"

libksi_dev_includes="\
	$include_dir/base32.h \
	$include_dir/blocksigner.h \
	$include_dir/crc32.h \
	$include_dir/common.h \
	$include_dir/err.h \
	$include_dir/fast_tlv.h \
	$include_dir/hash.h \
	$include_dir/hashchain.h \
	$include_dir/hmac.h \
	$include_dir/io.h \
	$include_dir/ksi.h \
	$include_dir/list.h \
	$include_dir/log.h \
	$include_dir/net.h \
	$include_dir/net_http.h \
	$include_dir/net_tcp.h \
	$include_dir/net_file.h \
	$include_dir/net_uri.h\
	$include_dir/pkitruststore.h \
	$include_dir/publicationsfile.h \
	$include_dir/signature.h \
	$include_dir/signature_builder.h \
	$include_dir/signature_helper.h \
	$include_dir/tlv.h \
	$include_dir/tlv_template.h \
	$include_dir/tlv_element.h \
	$include_dir/tree_builder.h \
	$include_dir/types.h \
	$include_dir/types_base.h \
	$include_dir/verification.h \
	$include_dir/verification_rule.h \
	$include_dir/policy.h \
	$include_dir/compatibility.h \
	$include_dir/version.h \
	$include_dir/verify_deprecated.h"


# Rebuild API.
./rebuild.sh
make dist


# Create temporary directory structure.
mkdir -p $tmp_dir_lib/libksi/$lib_install_dir
mkdir -p $tmp_dir_lib/libksi/$lib_doc_install_dir

mkdir -p $tmp_dir_dev/libksi-dev/$lib_install_dir
mkdir -p $tmp_dir_dev/libksi-dev/$pconf_install_dir
mkdir -p $tmp_dir_dev/libksi-dev/$dev_inc_install_dir
mkdir -p $tmp_dir_dev/libksi-dev/$dev_doc_install_dir

mkdir -p $tmp_dir_lib/libksi/DEBIAN
mkdir -p $tmp_dir_dev/libksi-dev/DEBIAN
mkdir -p $tmp_dir_src/libksi/debian

chmod -Rf 755 $tmp_dir_lib
chmod -Rf 755 $tmp_dir_dev
chmod -Rf 755 $tmp_dir_src


# Copy control files and changelog.
cp  $deb_dir/libksi/DEBIAN/control $tmp_dir_lib/libksi/DEBIAN/control
cp  $deb_dir/libksi/DEBIAN/control-dev $tmp_dir_dev/libksi-dev/DEBIAN/control
cp  $deb_dir/libksi/DEBIAN/control-source $tmp_dir_src/libksi/debian/control


# As the target architecture do not match with the one provided by autotools,
# replace the variable by the one provided by dpkg.
sed -i s/@DPKG_VERSION_REPLACED_WITH_SED@/$ARCH/g "$tmp_dir_lib/libksi/DEBIAN/control"
sed -i s/@DPKG_VERSION_REPLACED_WITH_SED@/$ARCH/g "$tmp_dir_dev/libksi-dev/DEBIAN/control"

# Copy libksi shared library with its changelog to target directories.
cp -fP $libksi_libs $tmp_dir_lib/libksi/$lib_install_dir/
cp -f $libksi_changelog_license $tmp_dir_lib/libksi/$lib_doc_install_dir/

# Copy libksi static libraries, include files, (docygen documentation if is
# built) and package configuration file.
cp -fP $libksi_dev_libs $tmp_dir_dev/libksi-dev/$lib_install_dir/
cp -f $libksi_dev_includes $tmp_dir_dev/libksi-dev/$dev_inc_install_dir/
cp -f $libksi_pckg_config $tmp_dir_dev/libksi-dev/$pconf_install_dir/

# Rebuild doxygen documentation and copy files.
# Check if doxygen with supported version (>=1.8.0) is installed.
if (doxygen -v | grep -q -P -e '((^1\.([8-9]|[1-9][0-9]+))|(^[2-9]\.[0-9]+)|(^[0-9]{2,}\.[0-9]+))\.[0-9]+$') > /dev/null 2>&1 ; then
	make doc
	cp -f $libksi_dev_doc $tmp_dir_dev/libksi-dev/$dev_doc_install_dir/
else
	echo "Doxygen documentation not included into package!"
fi

cp -f libksi-${VER}.tar.gz $tmp_dir_src/libksi_${VER}.orig.tar.gz
cp  $deb_dir/libksi/DEBIAN/changelog $tmp_dir_src/libksi/debian/
tar -xvzf libksi-${VER}.tar.gz -C $tmp_dir_src/
cp -r $tmp_dir_src/libksi/debian $tmp_dir_src/libksi-${VER}


#Build packages
dpkg-deb --build $tmp_dir_lib/libksi
mv $tmp_dir_lib/libksi.deb libksi_${VER}-${PKG_VERSION}_${ARCH}.deb

dpkg-deb --build $tmp_dir_dev/libksi-dev
mv $tmp_dir_dev/libksi-dev.deb libksi-dev_${VER}-${PKG_VERSION}_${ARCH}.deb

dpkg-source -b -sn $tmp_dir_src/libksi-${VER} ""


#Cleanup

rm -rf $tmp_dir_lib
rm -rf $tmp_dir_dev
rm -rf $tmp_dir_src
rm libksi-${VER}.tar.gz
