AC_INIT([ksi-c-api], [0.0.1], [support@guardtime.com])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])
# Checks for programs.
AC_PROG_CC

AC_CONFIG_HEADERS([src/config.h])
# Checks for libraries.

# Checks for header files.
#AC_CHECK_HEADER([stdint.h stdlib.h string.h gt_base.h gt_http.h])

AC_ARG_WITH(unit-test-xml,
[  --with-unit-test-xml=file		Specifies the target xml of unit tests.],
:, with_unit_test_xml=testsuite-xunit.xml)

AC_DEFINE_UNQUOTED(UNIT_TEST_OUTPUT_XML, "$with_unit_test_xml", [Location of the unit test xml results.])

AC_CONFIG_FILES(GNUmakefile src/GNUmakefile test/GNUmakefile)
AC_OUTPUT
