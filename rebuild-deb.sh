#!/bin/bash

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
    $lib_dir/libksi.so.0 \
    $lib_dir/libksi.so.0.0.0"
    

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
