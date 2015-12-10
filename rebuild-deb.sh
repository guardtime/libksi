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

deb_dir=packaging/deb

#Temporary directories for deb package build.
tmp_dir_lib=$deb_dir/tmp_lib
tmp_dir_devel=$deb_dir/tmp_devel
tmp_dir_src=$deb_dir/tmp_src

#Destination dirs used for installion.
lib_install_dir=usr/local/lib
inc_install_dir=usr/local/include/ksi
doc_install_dir=usr/share/doc/ksi
src_install_dir=usr/local/src

#Source directories for files.
include_dir=src/ksi
lib_dir=src/ksi/.libs


#File list for libksi installion 
libksi_libs="$lib_dir/libksi.so \
    $lib_dir/libksi.so."

libksi_doc="changelog \
    license.txt"


#File list for libksi-devel installion
libksi_devel_includes="\
    $include_dir/base32.h \
    $include_dir/crc32.h \
    $include_dir/common.h \
    $include_dir/err.h \
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
    $include_dir/net_uri.h\
    $include_dir/pkitruststore.h \
    $include_dir/publicationsfile.h \
    $include_dir/signature.h \
    $include_dir/tlv.h \
    $include_dir/tlv_template.h \
    $include_dir/types.h \
    $include_dir/types_base.h \
    $include_dir/verification.h \
    $include_dir/compatibility.h"

    
libksi_devel_libs="\
    $lib_dir/libksi.a \
    $lib_dir/libksi.la \
    libksi.pc"



#Rebuild API
./rebuild.sh
make dist



#Create directory structure 
mkdir -p $tmp_dir_lib
mkdir -p $tmp_dir_lib/libksi/$lib_install_dir/pkgconfig
mkdir -p $tmp_dir_lib/libksi/$inc_install_dir
mkdir -p $tmp_dir_lib/libksi/$doc_install_dir

mkdir -p $tmp_dir_devel
mkdir -p $tmp_dir_devel/libksi-devel/$lib_install_dir/pkgconfig
mkdir -p $tmp_dir_devel/libksi-devel/$inc_install_dir
mkdir -p $tmp_dir_devel/libksi-devel/$doc_install_dir

mkdir -p $tmp_dir_src

mkdir -p $tmp_dir_lib/libksi/DEBIAN
mkdir -p $tmp_dir_devel/libksi-devel/DEBIAN
mkdir -p $tmp_dir_src/libksi/debian

#Get version number 
VER=$(tr -d [:space:] < VERSION)
ARCH=$(dpkg --print-architecture)


#Copy files
cp  $deb_dir/libksi/DEBIAN/control $tmp_dir_lib/libksi/DEBIAN/control
cp  $deb_dir/libksi/DEBIAN/control-devel $tmp_dir_devel/libksi-devel/DEBIAN/control
cp  $deb_dir/libksi/DEBIAN/control-source $tmp_dir_src/libksi/debian/control
cp  $deb_dir/libksi/DEBIAN/changelog $tmp_dir_src/libksi/debian/


sed -i s/@VER@/$VER/g "$tmp_dir_lib/libksi/DEBIAN/control" 
sed -i s/@ARCH@/$ARCH/g "$tmp_dir_lib/libksi/DEBIAN/control" 

sed -i s/@VER@/$VER/g $tmp_dir_devel/libksi-devel/DEBIAN/control 
sed -i s/@ARCH@/$ARCH/g $tmp_dir_devel/libksi-devel/DEBIAN/control 

sed -i s/@ARCH@/$ARCH/g "$tmp_dir_src/libksi/debian/control" 
sed -i s/@VER@/$VER/g "$tmp_dir_src/libksi/debian/control" 

#copy data

cp -f $libksi_libs $tmp_dir_lib/libksi/$lib_install_dir/
cp -f $libksi_doc $tmp_dir_lib/libksi/$doc_install_dir/

cp -f $libksi_devel_includes $tmp_dir_devel/libksi-devel/$inc_install_dir/
cp -f $libksi_devel_libs $tmp_dir_devel/libksi-devel/$lib_install_dir/

#cp -f libksi-${VER}.tar.gz $tmp_dir_src/libksi_${VER}.orig.tar.gz
tar -xvzf libksi-${VER}.tar.gz -C $tmp_dir_src/
cp -r $tmp_dir_src/libksi/debian $tmp_dir_src/libksi-${VER}


#Build packages
dpkg-deb --build $tmp_dir_lib/libksi
mv $tmp_dir_lib/libksi.deb libksi_${VER}_${ARCH}.deb 

dpkg-deb --build $tmp_dir_devel/libksi-devel
mv $tmp_dir_devel/libksi-devel.deb libksi-devel_${VER}_${ARCH}.deb 

dpkg-source -b -sn $tmp_dir_src/libksi-${VER} ""
                                                                          

#Cleanup
rm -rf $deb_dir/libksi/usr

rm -rf $tmp_dir_lib
rm -rf $tmp_dir_devel
rm -rf $tmp_dir_src
rm libksi-${VER}.tar.gz
