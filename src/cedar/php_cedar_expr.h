/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_expr.h - Cedar expression evaluator
 *
 * Recursively evaluates AST nodes and returns runtime values.
 * Internal interface between eval.c and expr.c.
 */

#ifndef PHP_CEDAR_EXPR_H
#define PHP_CEDAR_EXPR_H

#include "php_cedar_types.h"
#include "php_cedar_util.h"


php_cedar_value_t php_cedar_expr_eval(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool,
    php_cedar_log_t *log);


/*
 * Parse an IP literal string (v4 / v6, with optional CIDR) into a
 * runtime value. Returns an RVAL_ERROR value on invalid input.
 * Shared with eval.c so the injection API can eagerly materialize
 * IP attribute values at insertion time.
 */
php_cedar_value_t php_cedar_make_ip(const php_cedar_str_t *s);


/*
 * Parse a Cedar decimal string ("[-]?d+\.d{1,4}") into a fixed-point
 * i64 runtime value with implicit scale 10^4. Returns an RVAL_ERROR
 * value when the input is malformed or the scaled magnitude does not
 * fit in int64_t. Shared with eval.c so the injection API can eagerly
 * materialize decimal attribute values at insertion time.
 */
php_cedar_value_t php_cedar_make_decimal(const php_cedar_str_t *s);


/*
 * Parse a Cedar datetime string ("YYYY-MM-DD" or
 * "YYYY-MM-DDThh:mm:ss(.SSS)?(Z|±hhmm)") into UTC epoch milliseconds.
 * Returns an RVAL_ERROR value when the input is malformed, denotes a
 * non-existent date, or carries a time without a timezone designator.
 * Shared with eval.c so the injection API can eagerly materialize
 * datetime attribute values at insertion time.
 */
php_cedar_value_t php_cedar_make_datetime(const php_cedar_str_t *s);


/*
 * Parse a Cedar duration string ("[-]?(\d+d)?(\d+h)?(\d+m)?(\d+s)?
 * (\d+ms)?", at least one unit) into a signed millisecond count.
 * Returns an RVAL_ERROR value on malformed input, an out-of-order or
 * repeated unit, or i64 overflow. Shared with eval.c so the injection
 * API can eagerly materialize duration attribute values at insertion
 * time.
 */
php_cedar_value_t php_cedar_make_duration(const php_cedar_str_t *s);


#endif /* PHP_CEDAR_EXPR_H */
