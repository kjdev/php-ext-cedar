/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_util.h - Common utility helpers shared across layers
 *
 * Header for small, dependency-free helpers used by both the parser
 * and the evaluator. Keeping them here lets the parser avoid pulling
 * in evaluator-only headers solely for tiny utilities.
 */

#ifndef PHP_CEDAR_UTIL_H
#define PHP_CEDAR_UTIL_H

#include "php_cedar_types.h"


/* string equality (shared across parser/expr/eval layers) */
static inline php_cedar_int_t
php_cedar_str_eq(const php_cedar_str_t *a, const php_cedar_str_t *b)
{
    return (a->len == b->len
            && (a->len == 0
                || php_cedar_memcmp(a->data, b->data, a->len) == 0));
}


#endif /* PHP_CEDAR_UTIL_H */
