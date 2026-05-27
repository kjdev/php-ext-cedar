dnl config.m4 for extension cedar

PHP_ARG_ENABLE([cedar],
  [whether to enable cedar support],
  [AS_HELP_STRING([--enable-cedar],
    [Enable cedar (local Cedar evaluator) support])])

if test "$PHP_CEDAR" != "no"; then

  AC_DEFINE(HAVE_CEDAR, 1, [ Have cedar support ])
  AC_DEFINE(PHP_CEDAR_USE_ZEND_MM, 1,
    [ Use Zend Memory Manager for cedar evaluator allocations ])

  CEDAR_SOURCES="cedar.c \
    src/cedar/php_cedar_compat.c \
    src/cedar/php_cedar_lexer.c \
    src/cedar/php_cedar_parser.c \
    src/cedar/php_cedar_expr.c \
    src/cedar/php_cedar_eval.c"

  PHP_NEW_EXTENSION(cedar, $CEDAR_SOURCES, $ext_shared,,
    [-DZEND_ENABLE_STATIC_TSRMLS_CACHE=1])

  PHP_ADD_BUILD_DIR([$ext_builddir/src/cedar], 1)
  PHP_ADD_INCLUDE([$ext_srcdir/src/cedar])

  ifdef([PHP_INSTALL_HEADERS], [
    PHP_INSTALL_HEADERS([ext/cedar], [php_cedar.h])
  ])
fi
