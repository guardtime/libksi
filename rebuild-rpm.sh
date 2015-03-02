#!/bin/sh

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

BUILD_DIR=~/rpmbuild

autoreconf -if && \
./configure $* && \
make clean && \
make dist && \
mkdir -p $BUILD_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp} && \
cp redhat/libksi.spec $BUILD_DIR/SPECS/ && \
cp libksi-*.tar.gz $BUILD_DIR/SOURCES/ && \
rpmbuild -ba $BUILD_DIR/SPECS/libksi.spec && \
cp $BUILD_DIR/RPMS/*/libksi-*.rpm . && \
cp $BUILD_DIR/SRPMS/libksi-*.rpm .
