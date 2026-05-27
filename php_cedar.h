/*
 * php-ext-cedar — Local Cedar policy evaluator (AVP-compatible API)
 */

#ifndef PHP_CEDAR_H
#define PHP_CEDAR_H

#include "php.h"

#define PHP_CEDAR_VERSION "0.1.0-dev"
#define PHP_CEDAR_NS "Cedar"

extern zend_module_entry cedar_module_entry;
#define phpext_cedar_ptr &cedar_module_entry

#ifdef PHP_WIN32
#  define PHP_CEDAR_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#  define PHP_CEDAR_API __attribute__((visibility("default")))
#else
#  define PHP_CEDAR_API
#endif

#ifdef ZTS
#  include "TSRM.h"
#endif

#endif /* PHP_CEDAR_H */
