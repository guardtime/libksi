#!/bin/sh

autoreconf -i && \
./configure $* && \
make clean && \
make dist && \ 
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS,tmp} && \
cp redhat/libksi.spec ~/rpmbuild/SPECS/ && \
cp libksi-*.tar.gz ~/rpmbuild/SOURCES/ && \
rpmbuild -ba ~/rpmbuild/SPECS/libksi.spec && \
cp ~/rpmbuild/RPMS/*/libksi-*.rpm . && \
cp ~/rpmbuild/SRPMS/libksi-*.rpm .
