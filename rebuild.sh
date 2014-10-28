#!/bin/sh

PRF=libksi-$(tr -d [:space:] < VERSION)

rm -f ${PRF}*.tar.gz && \
rm -fr .deps && \
mkdir -p config m4 && \
echo Running autoreconf... && \
autoreconf -i && \
echo Running configure script... && \
./configure $* && \
echo Running make... && \
make clean && \
make && \
make check && \
make test \
#make doc && \
#echo Packaging sources... && \
#make dist && \
#echo Packaging binaries... && \
#rm -rf ./${PRF} && \
#make install prefix=$(pwd)/${PRF} && \
#tar -czvf ${PRF}-bin.tar.gz ./${PRF} && \
#echo Packaging documentation... && \
#rm -rf ./${PRF} && \
#mkdir -p ./${PRF}/doc && \
#cp -r ./doc/html ./doc/latex/refman.pdf ./${PRF}/doc && \
#tar -czvf ${PRF}-doc.tar.gz ./${PRF}
