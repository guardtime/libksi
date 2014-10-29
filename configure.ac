AC_INIT([libksi], m4_esyscmd([tr -d [:space:] <VERSION]), [support@guardtime.com])
AC_CONFIG_FILES([libksi.pc])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([src/ksi/config.h])
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([subdir-objects foreign -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL

# Checks for libraries.

AC_ARG_WITH(openssl,
[  --with-openssl=path       build with OpenSSL installed at specified location],
:, with_openssl=)
if test ! -z "$with_openssl" ; then
    CFLAGS="-I$with_openssl/include $CFLAGS"
    LDFLAGS="-L$with_openssl/lib $LDFLAGS"
fi

AC_CHECK_LIB([crypto], [SHA256_Init], [], [AC_MSG_FAILURE([Could not find OpenSSL 0.9.8+ libraries.])])
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

case "${target_os}" in
    darwin*)
        CFLAGS="$CFLAGS -mmacosx-version-min=10.5"
        LDFLAGS="$LDFALGS -mmacosx-version-min=10.5"
        ;;
esac

# To ensure compatibility with Microsoft compiler.
CFLAGS="$CFLAGS -Wdeclaration-after-statement"

AC_ARG_WITH(unit-test-xml,
[  --with-unit-test-xml=file		Specifies the target xml of unit tests.],
:, with_unit_test_xml=testsuite-xunit.xml)

AC_DEFINE_UNQUOTED(UNIT_TEST_OUTPUT_XML, "$with_unit_test_xml", [Location of the unit test xml results.])

AC_CONFIG_FILES(GNUmakefile src/ksi/GNUmakefile test/GNUmakefile doc/GNUmakefile src/example/GNUmakefile redhat/libksi.spec)
AC_OUTPUT
