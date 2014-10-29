#!/bin/sh

BUILD_DIR=~/rpmbuild

autoreconf -i && \
./configure $* && \
make clean && \
make dist && \
mkdir -p $BUILD_DIR/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp} && \
cp redhat/libksi.spec $BUILD_DIR/SPECS/ && \
cp libksi-*.tar.gz $BUILD_DIR/SOURCES/ && \
rpmbuild -ba $BUILD_DIR/SPECS/libksi.spec && \
cp ~/rpmbuild/RPMS/*/libksi-*.rpm . && \
cp $BUILD_DIR/SRPMS/libksi-*.rpm .
