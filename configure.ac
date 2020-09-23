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

AC_INIT([libksi], m4_esyscmd([tr -d [:space:] <VERSION]), [support@guardtime.com])
AC_CONFIG_FILES([libksi.pc])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/ksi/config.h])
AC_CANONICAL_TARGET
AM_MAINTAINER_MODE

# Before making a release, the LTVER string should be modified. The
# string is of the form c:r:a. Follow these instructions sequentially:
#   1. If the library source code has changed at all since the last update, then
#      increment revision ('c:r:a' becomes 'c:r+1:a').
#   2. If any interfaces have been added, removed, or changed since the last
#      update, increment current, and set revision to 0 ('c:r:a' becomes 'c+1:0:a').
#   3. If any interfaces have been added since the last public release, then
#      increment age ('c:r:a' becomes 'c:r:a+1').
#   4. If any interfaces have been removed or changed since the last public
#      release, then set age to 0 ('c:r:a' becomes 'c:r:0').
LTVER=m4_esyscmd([head -n 1 ABI_VERSION | tr -d [:space:]])
AC_SUBST(LTVER)

AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror tar-ustar])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL
AC_CHECK_PROG(git_installed,git,"yes", "no")

# Define the git hash of the current version.
AC_MSG_CHECKING([for commit id])
commit_id=""
if test "$git_installed" = "yes" -a -x ".git"; then
	commit_id=$(git log -n 1 --format="%H")
	AC_MSG_RESULT([$commit_id])
	AC_DEFINE_UNQUOTED(COMMIT_ID, "$commit_id", [Commit id])
else
	AC_MSG_RESULT([no])
fi

# Define configuration variables for the SDK

# Bitfield for setting disabled network providers (for possible values see src/ksi/internal.h under section
# "Network client providers.")
without_net=0
AC_ARG_WITH([net_tcp],
	[AS_HELP_STRING([--without-net-tcp], [build without TCP network provider.])],
	[AC_MSG_NOTICE([Building without TCP network provider.])]
		[without_net=$(( without_net | 0x01 ))
		KSI_PACKAGING_CONFIGURE_FLAGS="$KSI_PACKAGING_CONFIGURE_FLAGS --without-net-tcp"
		],
	[:])
AC_ARG_WITH([net_http],
	[AS_HELP_STRING([--without-net-http], [build without HTTP network provider.])],
	[AC_MSG_NOTICE([Building without HTTP network provider.])]
		[without_net=$(( without_net | 0x02 ))
		KSI_PACKAGING_CONFIGURE_FLAGS="$KSI_PACKAGING_CONFIGURE_FLAGS --without-net-http"
		],
	[:])
AC_ARG_WITH([net_file],
	[AS_HELP_STRING([--without-net-file], [build without FILE network provider (needed for reading test resources).])],
	[AC_MSG_NOTICE([Building without FILE network provider.])]
		[without_net=$(( without_net | 0x04 ))
		KSI_PACKAGING_CONFIGURE_FLAGS="$KSI_PACKAGING_CONFIGURE_FLAGS --without-net-file"],
	[:])
AC_DEFINE_UNQUOTED([KSI_DISABLE_NET_PROVIDER], [$without_net], [Build without net provider (bitfield).])
AC_SUBST(KSI_PACKAGING_CONFIGURE_FLAGS)

AC_MSG_NOTICE([Disabling strict HTTP parsing])
AC_DEFINE(HTTP_PARSER_STRICT, 0, [Disabling strict HTTP parsing to allow underscores in host names.])

AC_ARG_WITH(default_pdu_version,
[  --with-default-pdu-version=version Use the given PDU version by default.],
[], [with_default_pdu_version=])

if test ! -z "$with_default_pdu_version"; then
	AC_MSG_NOTICE([Using default PDU version=$with_default_pdu_version])
	case "$with_default_pdu_version" in
		1)	pdu_version=KSI_PDU_VERSION_1
			AC_MSG_WARN([*** PDU version is deprecated.])
			;;
		2)	pdu_version=KSI_PDU_VERSION_2
			;;
		*)	AC_MSG_ERROR([*** Invalid PDU version.]);
			;;
	esac;
	AC_DEFINE_UNQUOTED(KSI_AGGREGATION_PDU_VERSION, $pdu_version, [Default aggregation PDU version.])
	AC_DEFINE_UNQUOTED(KSI_EXTENDING_PDU_VERSION,   $pdu_version, [Default extending PDU version.])
fi

# Checks for libraries.

AC_ARG_WITH(openssl,
[  --with-openssl=path       build with OpenSSL installed at specified location],
:, with_openssl=)
if test ! -z "$with_openssl" ; then
	CFLAGS="-I$with_openssl/include $CFLAGS"
	LDFLAGS="-L$with_openssl/lib $LDFLAGS"
fi

AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([Could not find OpenSSL 0.9.8+ libraries.])])

AC_ARG_WITH(hash-provider,
[  --with-hash-provider=<openssl|commoncrypto>       build using library for hash functions (default: openssl)],
:, with_hash_provider=openssl)
if test "x$with_hash_provider" = "xcommoncrypto" ; then
	AC_DEFINE_UNQUOTED(KSI_HASH_IMPL, KSI_IMPL_COMMONCRYPTO, [Use CommonCrypto.])
	AC_CHECK_HEADER([CommonCrypto/CommonCrypto.h])
elif test "x$with_hash_provider" = "xopenssl" ; then
	AC_DEFINE_UNQUOTED(KSI_HASH_IMPL, KSI_IMPL_OPENSSL, [Use OpenSSL.])
    AC_CHECK_FUNCS([EVP_sha3_256 EVP_sha3_384 EVP_sha3_512 EVP_sm3])
else
	AC_MSG_ERROR([*** Unknown hash provider.])
fi

AC_CHECK_LIB([curl], [curl_easy_init], [], [AC_MSG_FAILURE([Could nod find Curl libraries.])])

AC_ARG_WITH(cafile,
[  --with-cafile=file        build with trusted CA certificate bundle file at specified location],
:, with_cafile=)
if test -z "$with_cafile" ; then
	for cafile in \
			/etc/ssl/certs/ca-certificates.crt \
			/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt \
			/etc/pki/tls/certs/ca-bundle.trust.crt \
			/usr/share/ssl/certs/ca-bundle.trust.crt \
			/usr/local/share/certs/ca-root.trust.crt \
			/usr/local/etc/openssl/cert.pem \
			/etc/ssl/cert.pem ; do
		if test -f "$cafile" ; then
			with_cafile="$cafile"
			break
		fi
	done
fi

AC_MSG_CHECKING([for location of trusted CA certificate bundle file])
if test ! -z "$with_cafile" ; then
	AC_MSG_RESULT([$with_cafile])
	AC_DEFINE_UNQUOTED(OPENSSL_CA_FILE, "$with_cafile", [Location of the trusted CA certificate bundle file])
else
	AC_MSG_RESULT([no])
fi

AC_ARG_WITH(cadir,
[  --with-cadir=dir          build with trusted CA certificate directory at specified path],
:, with_cadir=)
if test -z "$with_cadir" ; then
	for cadir in \
			/etc/ssl/certs/ \
			/opt/local/etc/openssl/certs/ ; do
		if test -d "$cadir" && ls "$cadir"/[[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]].0 >/dev/null 2>/dev/null ; then
			with_cadir="$cadir"
			break
		fi
	done
fi

AC_MSG_CHECKING([for path to trusted CA certificate directory])
if test ! -z "$with_cadir" ; then
	AC_MSG_RESULT([$with_cadir])
	AC_DEFINE_UNQUOTED(OPENSSL_CA_DIR, "$with_cadir", [Path to the trusted CA certificate directory])
else
	AC_MSG_RESULT([no])
fi

# Check for CA file
if test -z "$with_cafile" -a -z "$with_cadir"; then
	# Check for OSX Trust Evaluation Engine.
	AC_CHECK_LIB([crypto], [X509_TEA_is_enabled], [], [AC_MSG_FAILURE([*** CA certificate bundle file or directory must be specified.])])
	AC_MSG_CHECKING([if trust evaluation engine is enabled])
	# Fall back to TEA if not disabled.
	if test -z "$OPENSSL_X509_TEA_DISABLE" -o "$OPENSSL_X509_TEA_DISABLE" == "0" ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([*** Neither CA certificate bundle file nor directory is specified and also Trust Evaluation Engine is disabled.]);
	fi
fi

# To ensure compatibility with Microsoft compiler.
CFLAGS+=" -Wdeclaration-after-statement"
# Add more warnings.
CFLAGS+=" -Wall"
# Optimize for debugging.
#CFLAGS+=" -Og"

AC_ARG_WITH(unit-test-xml,
[  --with-unit-test-xml=file		Specifies the target xml of unit tests.],
:, with_unit_test_xml=testsuite-xunit.xml)

AC_DEFINE_UNQUOTED(UNIT_TEST_OUTPUT_XML, "$with_unit_test_xml", [Location of the unit test xml results.])

AC_MSG_NOTICE([Update version.h])
rm -f src/ksi/version.h
VER=($(echo $PACKAGE_VERSION | tr "." " "))
VER_MAJOR=${VER[[0]]}
VER_MINOR=${VER[[1]]}
VER_BUILD=${VER[[2]]}
AC_SUBST(VER_MAJOR)
AC_SUBST(VER_MINOR)
AC_SUBST(VER_BUILD)
AC_CONFIG_FILES([src/ksi/version.h])

AC_CONFIG_FILES([GNUmakefile src/ksi/GNUmakefile test/GNUmakefile doc/GNUmakefile src/example/GNUmakefile packaging/redhat/libksi.spec packaging/deb/control packaging/deb/rules])
AC_OUTPUT
