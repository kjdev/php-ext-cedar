/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_parser.h - Cedar policy text recursive descent parser
 */

#ifndef PHP_CEDAR_PARSER_H
#define PHP_CEDAR_PARSER_H

#include "php_cedar_types.h"


/*
 * Parse a Cedar policy-set text into an AST.
 *
 * All three arguments are required: pool / log / text must be non-NULL.
 * Passing NULL for any of them returns NULL without dereferencing it
 * (defensive guard against caller mistakes; the implementation also
 * relies on these being non-NULL once it starts allocating).
 *
 * Returns NULL on parse error or allocation failure as well; details
 * are logged to `log`.
 */
php_cedar_policy_set_t *php_cedar_parse(php_cedar_pool_t *pool,
    php_cedar_log_t *log, const php_cedar_str_t *text);


#endif /* PHP_CEDAR_PARSER_H */
