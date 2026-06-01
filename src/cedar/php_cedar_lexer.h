/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_lexer.h - Cedar policy text tokenizer
 */

#ifndef PHP_CEDAR_LEXER_H
#define PHP_CEDAR_LEXER_H

#include "php_cedar_types.h"


typedef struct {
    php_cedar_str_t   input;
    size_t      pos;
    php_cedar_pool_t *pool;
    php_cedar_log_t  *log;
} php_cedar_lexer_t;

void php_cedar_lexer_init(php_cedar_lexer_t *lexer,
    php_cedar_pool_t *pool, php_cedar_log_t *log, const php_cedar_str_t *input);
php_cedar_token_t php_cedar_lexer_next(php_cedar_lexer_t *lexer);

/* shared escape decoder (also used by like pattern compiler) */
php_cedar_int_t php_cedar_decode_escape(unsigned char **src, unsigned char *src_end,
    unsigned char **dst, php_cedar_flag_t reject_xff);


#endif /* PHP_CEDAR_LEXER_H */
