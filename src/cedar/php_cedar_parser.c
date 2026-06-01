/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_parser.c - Cedar policy text recursive descent parser
 *
 * Converts token stream to AST and builds policy set.
 */

#include "php_cedar_compat.h"
#include "php_cedar_lexer.h"
#include "php_cedar_parser.h"
#include "php_cedar_util.h"     /* php_cedar_str_eq */


#define PHP_CEDAR_MAX_PARSE_DEPTH   64
#define PHP_CEDAR_MAX_POLICIES     256
#define PHP_CEDAR_MAX_CONDITIONS    16
#define PHP_CEDAR_MAX_SET_ELEMENTS 256
#define PHP_CEDAR_MAX_ANNOTATIONS   16
#define PHP_CEDAR_MAX_TYPE_PARTS    16
#define PHP_CEDAR_MAX_RECORD_ENTRIES 64
/* PHP_CEDAR_MAX_MEMBER_CHAIN is defined in php_cedar_types.h so it can
 * be shared with PHP_CEDAR_MAX_RECORD_DEPTH. */
#define PHP_CEDAR_MAX_BINOP_CHAIN  256


/* parser context (file-local) */
typedef struct {
    php_cedar_lexer_t  lexer;
    php_cedar_token_t  current;
    php_cedar_pool_t        *pool;
    php_cedar_log_t         *log;
    php_cedar_uint_t         depth;
    php_cedar_uint_t         record_depth;
    unsigned           error:1;
} php_cedar_parser_ctx_t;


/* forward declarations */
static php_cedar_node_t *php_cedar_parse_expr(
    php_cedar_parser_ctx_t *ctx);
static php_cedar_node_t *php_cedar_parse_entity_ref_with_ident(
    php_cedar_parser_ctx_t *ctx, php_cedar_str_t first_ident);
static php_cedar_node_t *php_cedar_parse_unary_expr(
    php_cedar_parser_ctx_t *ctx);


/*
 * Check if a token type can be used as an identifier (attribute name).
 * Extension function keywords like 'ip' and 'decimal' are valid
 * attribute names in Cedar (e.g. context.ip, principal has decimal).
 * Add new extension keywords here as they are introduced.
 */
static php_cedar_int_t
php_cedar_token_is_ident(php_cedar_token_type_t type)
{
    return (type == PHP_CEDAR_TOKEN_IDENT
            || type == PHP_CEDAR_TOKEN_IP
            || type == PHP_CEDAR_TOKEN_DECIMAL
            || type == PHP_CEDAR_TOKEN_DATETIME
            || type == PHP_CEDAR_TOKEN_DURATION);
}


static void
php_cedar_parser_advance(php_cedar_parser_ctx_t *ctx)
{
    ctx->current = php_cedar_lexer_next(&ctx->lexer);

    if (ctx->current.type == PHP_CEDAR_TOKEN_ERROR) {
        ctx->error = 1;
    }
}


static php_cedar_int_t
php_cedar_parser_expect(php_cedar_parser_ctx_t *ctx,
    php_cedar_token_type_t type)
{
    if (ctx->current.type != type) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expected token %d, got %d", type,
                      ctx->current.type);
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    php_cedar_parser_advance(ctx);
    return PHP_CEDAR_OK;
}


static php_cedar_node_t *
php_cedar_parser_alloc_node(php_cedar_parser_ctx_t *ctx,
    php_cedar_node_type_t type)
{
    php_cedar_node_t *node;

    node = php_cedar_pcalloc(ctx->pool, sizeof(php_cedar_node_t));
    if (node == NULL) {
        ctx->error = 1;
        return NULL;
    }

    node->type = type;
    return node;
}


/*
 * Consume a STRING token where like-style wildcards are not allowed
 * (bracket access key, `has` operator string branch, record literal
 * string key, annotation value, etc.). Rejects non-STRING tokens and
 * strings containing the `\*` escape (only valid in `like` patterns).
 * On success, copies the string value to *out and advances.
 */
static php_cedar_int_t
php_cedar_parser_consume_attr_name_string(php_cedar_parser_ctx_t *ctx,
    php_cedar_str_t *out)
{
    if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expected string literal");
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    if (ctx->current.has_star_escape) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: "
                      "invalid escape sequence \\*: "
                      "only valid in like patterns");
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    *out = ctx->current.value;
    php_cedar_parser_advance(ctx);
    return PHP_CEDAR_OK;
}


/*
 * Compile a like pattern from raw source bytes (between quotes).
 * Unescaped '*' becomes 0xFF (wildcard marker).
 * '\*' is the only escape that produces a literal '*'.
 * Other escapes that decode to '*' (e.g. \x2A, \u{2A}) become
 * wildcards, matching Cedar's official semantics.
 * Returns PHP_CEDAR_ERROR on invalid escape (sets ctx->error).
 */
static php_cedar_int_t
php_cedar_parser_compile_pattern(php_cedar_parser_ctx_t *ctx,
    php_cedar_str_t *raw, php_cedar_str_t *out)
{
    unsigned char *src, *dst, *end;

    dst = php_cedar_palloc(ctx->pool, raw->len);
    if (dst == NULL) {
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    out->data = dst;
    src = raw->data;
    end = src + raw->len;

    while (src < end) {
        /* reject raw 0xFF: reserved as wildcard sentinel */
        if (*src == 0xFF) {
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        if (*src == '*') {
            *dst++ = 0xFF;
            src++;
            continue;
        }

        if (*src == '\\') {
            if (src + 1 >= end) {
                ctx->error = 1;
                return PHP_CEDAR_ERROR;
            }

            src++;  /* skip backslash */

            /* \* is the only escape producing literal '*' */
            if (*src == '*') {
                *dst++ = '*';
                src++;
                continue;
            }

            {
                unsigned char *dst_before;

                dst_before = dst;

                if (php_cedar_decode_escape(&src, end, &dst, 1)
                    != PHP_CEDAR_OK)
                {
                    ctx->error = 1;
                    return PHP_CEDAR_ERROR;
                }

                /*
                 * If an escape like \x2A or \u{2A} produced '*',
                 * treat it as a wildcard (Cedar semantics).
                 */
                if (dst == dst_before + 1 && *dst_before == '*') {
                    *dst_before = 0xFF;
                }
            }

            continue;
        }

        *dst++ = *src++;
    }

    out->len = dst - out->data;

    /* compress consecutive wildcards: "**" → single 0xFF */
    {
        unsigned char *r, *w, *oend;

        r = out->data;
        w = out->data;
        oend = r + out->len;

        while (r < oend) {
            *w++ = *r++;

            if (*(r - 1) == 0xFF) {
                while (r < oend && *r == 0xFF) {
                    r++;
                }
            }
        }

        out->len = w - out->data;
    }

    return PHP_CEDAR_OK;
}


/*
 * parse integer from php_cedar_str_t (Cedar i64 domain)
 * returns PHP_CEDAR_ERROR on overflow (sets *result to 0)
 */
static php_cedar_int_t
php_cedar_parse_long(php_cedar_str_t *s, int64_t *result)
{
    int64_t val, digit;
    size_t i;

    val = 0;

    for (i = 0; i < s->len; i++) {
        digit = s->data[i] - '0';

        /* overflow check: val * 10 + digit > INT64_MAX */
        if (val > (INT64_MAX - digit) / 10) {
            *result = 0;
            return PHP_CEDAR_ERROR;
        }

        val = val * 10 + digit;
    }

    *result = val;
    return PHP_CEDAR_OK;
}


/*
 * parse negative integer from php_cedar_str_t (Cedar i64 domain)
 * accumulates in negative domain to handle INT64_MIN correctly
 * returns PHP_CEDAR_ERROR on underflow (sets *result to 0)
 */
static php_cedar_int_t
php_cedar_parse_neg_long(php_cedar_str_t *s, int64_t *result)
{
    int64_t val, digit;
    size_t i;

    val = 0;

    for (i = 0; i < s->len; i++) {
        digit = s->data[i] - '0';

        /* underflow check: val * 10 - digit < INT64_MIN */
        if (val < (INT64_MIN + digit) / 10) {
            *result = 0;
            return PHP_CEDAR_ERROR;
        }

        val = val * 10 - digit;
    }

    *result = val;
    return PHP_CEDAR_OK;
}


/*
 * Append "::"IDENT to type_name, advancing the parser past the IDENT.
 * The current token must already be IDENT (caller checks).
 * Allocates a new buffer from ctx->pool and returns it in *type_name.
 */
static php_cedar_int_t
php_cedar_parser_append_type_segment(php_cedar_parser_ctx_t *ctx,
    php_cedar_str_t *type_name, php_cedar_uint_t *parts)
{
    unsigned char *p;
    size_t new_len;

    if (++(*parts) > PHP_CEDAR_MAX_TYPE_PARTS) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: too many type name segments");
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    new_len = type_name->len + 2 + ctx->current.value.len;
    if (new_len < type_name->len) {
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    p = php_cedar_palloc(ctx->pool, new_len);
    if (p == NULL) {
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memcpy(p, type_name->data, type_name->len);
    p[type_name->len] = ':';
    p[type_name->len + 1] = ':';
    php_cedar_memcpy(p + type_name->len + 2,
               ctx->current.value.data, ctx->current.value.len);

    type_name->data = p;
    type_name->len = new_len;
    php_cedar_parser_advance(ctx);

    return PHP_CEDAR_OK;
}


/*
 * parse type name: IDENT { "::" IDENT }
 * Consumes the type name tokens and writes the joined name into *out.
 * Differs from entity_ref in that there is no trailing "::"id part.
 */
static php_cedar_int_t
php_cedar_parse_type_name(php_cedar_parser_ctx_t *ctx, php_cedar_str_t *out)
{
    php_cedar_str_t type_name;
    php_cedar_uint_t parts;

    if (ctx->current.type != PHP_CEDAR_TOKEN_IDENT) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expected type name after 'is'");
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    type_name = ctx->current.value;
    php_cedar_parser_advance(ctx);
    parts = 1;

    while (ctx->current.type == PHP_CEDAR_TOKEN_COLONCOLON) {
        php_cedar_parser_advance(ctx);

        if (ctx->current.type != PHP_CEDAR_TOKEN_IDENT) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "expected identifier after '::' in type name");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        if (php_cedar_parser_append_type_segment(ctx, &type_name, &parts)
            != PHP_CEDAR_OK)
        {
            return PHP_CEDAR_ERROR;
        }
    }

    *out = type_name;
    return PHP_CEDAR_OK;
}


/*
 * parse_entity_ref_with_ident: IDENT already consumed, parse rest
 * Format: Type { :: Type } :: "id"
 */
static php_cedar_node_t *
php_cedar_parse_entity_ref_with_ident(php_cedar_parser_ctx_t *ctx,
    php_cedar_str_t first_ident)
{
    php_cedar_node_t *node;
    php_cedar_str_t type_name;
    php_cedar_uint_t parts;

    type_name = first_ident;
    parts = 1;

    /* consume :: segments */
    while (ctx->current.type == PHP_CEDAR_TOKEN_COLONCOLON) {
        php_cedar_parser_advance(ctx);  /* skip :: */

        if (ctx->current.type == PHP_CEDAR_TOKEN_STRING) {
            if (ctx->current.has_star_escape) {
                php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                              "php_cedar_parse: "
                              "invalid escape sequence \\*: "
                              "only valid in like patterns");
                ctx->error = 1;
                return NULL;
            }

            /* Type::"id" - this is the entity id */
            node = php_cedar_parser_alloc_node(ctx,
                                               PHP_CEDAR_NODE_ENTITY_REF);
            if (node == NULL) {
                return NULL;
            }

            node->u.entity_ref.entity_type = type_name;
            node->u.entity_ref.entity_id = ctx->current.value;
            php_cedar_parser_advance(ctx);  /* consume string */
            return node;
        }

        if (ctx->current.type == PHP_CEDAR_TOKEN_IDENT) {
            /* Type::SubType - concatenate */
            if (php_cedar_parser_append_type_segment(ctx, &type_name,
                                                     &parts)
                != PHP_CEDAR_OK)
            {
                return NULL;
            }
            continue;
        }

        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expected string or ident after ::");
        ctx->error = 1;
        return NULL;
    }

    php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                  "php_cedar_parse: expected :: after type name");
    ctx->error = 1;
    return NULL;
}


/* parse set literal: [ expr, ... ] */
static php_cedar_node_t *
php_cedar_parse_set_literal(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node, *elem, **slot;
    php_cedar_uint_t count;

    php_cedar_parser_advance(ctx);  /* skip [ */

    node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_SET);
    if (node == NULL) {
        return NULL;
    }

    node->u.set_elts = php_cedar_array_create(ctx->pool, 4,
                                        sizeof(php_cedar_node_t *));
    if (node->u.set_elts == NULL) {
        ctx->error = 1;
        return NULL;
    }

    count = 0;

    if (ctx->current.type != PHP_CEDAR_TOKEN_RBRACKET) {
        elem = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            return NULL;
        }

        slot = php_cedar_array_push(node->u.set_elts);
        if (slot == NULL) {
            ctx->error = 1;
            return NULL;
        }
        *slot = elem;
        count++;

        while (ctx->current.type == PHP_CEDAR_TOKEN_COMMA) {
            if (++count > PHP_CEDAR_MAX_SET_ELEMENTS) {
                php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                              "php_cedar_parse: too many set elements");
                ctx->error = 1;
                return NULL;
            }

            php_cedar_parser_advance(ctx);

            elem = php_cedar_parse_expr(ctx);
            if (ctx->error) {
                return NULL;
            }

            slot = php_cedar_array_push(node->u.set_elts);
            if (slot == NULL) {
                ctx->error = 1;
                return NULL;
            }
            *slot = elem;
        }
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RBRACKET)
        != PHP_CEDAR_OK)
    {
        return NULL;
    }

    return node;
}


/*
 * Parse a record literal: "{" [ entry { "," entry } ] "}"
 *   entry := (IDENT | STRING) ":" expr
 *
 * - Empty record `{}` is allowed.
 * - Trailing comma after the last entry IS allowed (matches the Cedar
 *   reference parser for record literals).
 * - Duplicate keys are rejected at parse time.
 * - IDENT and STRING keys are stored as-is; equality uses byte match.
 *
 * Disambiguation from policy-body `when { ... }`: the outer `{` after
 * `when` / `unless` is consumed directly by php_cedar_parse_condition
 * before the expression parser runs, so any `{` reaching
 * php_cedar_parse_primary is a record literal.
 */
static php_cedar_node_t *
php_cedar_parse_record_literal(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node = NULL;
    php_cedar_record_entry_t *entry, *existing;
    php_cedar_str_t key;
    php_cedar_uint_t count, i;

    /*
     * Cap record-literal nesting at PHP_CEDAR_MAX_RECORD_DEPTH so the
     * parser cannot construct values deeper than the attribute-injection
     * API allows. Matches the member-chain reachability invariant in
     * php_cedar_types.h (writable depth == readable depth).
     */
    if (++ctx->record_depth > PHP_CEDAR_MAX_RECORD_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: "
                      "record literal too deeply nested (max %d)",
                      PHP_CEDAR_MAX_RECORD_DEPTH);
        ctx->error = 1;
        goto out;
    }

    php_cedar_parser_advance(ctx);  /* skip { */

    node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_RECORD);
    if (node == NULL) {
        goto out;
    }

    node->u.record_entries = php_cedar_array_create(ctx->pool, 4,
                                              sizeof(php_cedar_record_entry_t));
    if (node->u.record_entries == NULL) {
        ctx->error = 1;
        node = NULL;
        goto out;
    }

    /* empty record `{}` */
    if (ctx->current.type == PHP_CEDAR_TOKEN_RBRACE) {
        php_cedar_parser_advance(ctx);
        goto out;
    }

    count = 0;

    for ( ;; ) {
        if (++count > PHP_CEDAR_MAX_RECORD_ENTRIES) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many record entries");
            ctx->error = 1;
            node = NULL;
            goto out;
        }

        /* key: IDENT (incl. context-keyword idents) or STRING */
        if (php_cedar_token_is_ident(ctx->current.type)) {
            key = ctx->current.value;
            php_cedar_parser_advance(ctx);

        } else if (ctx->current.type == PHP_CEDAR_TOKEN_STRING) {
            if (php_cedar_parser_consume_attr_name_string(ctx, &key)
                != PHP_CEDAR_OK)
            {
                node = NULL;
                goto out;
            }

        } else {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "expected identifier or string as record key");
            ctx->error = 1;
            node = NULL;
            goto out;
        }

        /* reject duplicate keys at parse time */
        existing = node->u.record_entries->elts;
        for (i = 0; i < node->u.record_entries->nelts; i++) {
            if (php_cedar_str_eq(&existing[i].key, &key)) {
                php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                              "php_cedar_parse: "
                              "duplicate record key");
                ctx->error = 1;
                node = NULL;
                goto out;
            }
        }

        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_COLON)
            != PHP_CEDAR_OK)
        {
            node = NULL;
            goto out;
        }

        entry = php_cedar_array_push(node->u.record_entries);
        if (entry == NULL) {
            ctx->error = 1;
            node = NULL;
            goto out;
        }

        entry->key = key;
        entry->value = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            node = NULL;
            goto out;
        }

        if (ctx->current.type == PHP_CEDAR_TOKEN_COMMA) {
            php_cedar_parser_advance(ctx);
            /* trailing comma: stop if next token is `}` */
            if (ctx->current.type == PHP_CEDAR_TOKEN_RBRACE) {
                break;
            }
            continue;
        }

        break;
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RBRACE)
        != PHP_CEDAR_OK)
    {
        node = NULL;
        goto out;
    }

out:
    ctx->record_depth--;
    return node;
}


/* parse primary expression */
static php_cedar_node_t *
php_cedar_parse_primary(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node;
    php_cedar_str_t ident;

    switch (ctx->current.type) {

    case PHP_CEDAR_TOKEN_TRUE:
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_BOOL_LIT);
        if (node == NULL) {
            return NULL;
        }
        node->u.bool_val = 1;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_FALSE:
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_BOOL_LIT);
        if (node == NULL) {
            return NULL;
        }
        node->u.bool_val = 0;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_NUMBER:
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_LONG_LIT);
        if (node == NULL) {
            return NULL;
        }
        if (php_cedar_parse_long(&ctx->current.value,
                                 &node->u.long_val) != PHP_CEDAR_OK)
        {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: integer overflow");
            ctx->error = 1;
            return NULL;
        }
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_STRING:
        if (ctx->current.has_star_escape) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid escape sequence \\*: "
                          "only valid in like patterns");
            ctx->error = 1;
            return NULL;
        }
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_STRING_LIT);
        if (node == NULL) {
            return NULL;
        }
        node->u.string_val = ctx->current.value;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_PRINCIPAL:
        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_VAR);
        if (node == NULL) {
            return NULL;
        }
        node->u.var_type = PHP_CEDAR_VAR_PRINCIPAL;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_ACTION:
        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_VAR);
        if (node == NULL) {
            return NULL;
        }
        node->u.var_type = PHP_CEDAR_VAR_ACTION;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_RESOURCE:
        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_VAR);
        if (node == NULL) {
            return NULL;
        }
        node->u.var_type = PHP_CEDAR_VAR_RESOURCE;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_CONTEXT:
        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_VAR);
        if (node == NULL) {
            return NULL;
        }
        node->u.var_type = PHP_CEDAR_VAR_CONTEXT;
        php_cedar_parser_advance(ctx);
        return node;

    case PHP_CEDAR_TOKEN_IP:
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "ip() requires a string argument");
            ctx->error = 1;
            return NULL;
        }
        if (ctx->current.has_star_escape) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid escape sequence \\*: "
                          "only valid in like patterns");
            ctx->error = 1;
            return NULL;
        }
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_IP_LITERAL);
        if (node == NULL) {
            return NULL;
        }
        node->u.ip_literal.addr = ctx->current.value;
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        return node;

    case PHP_CEDAR_TOKEN_DECIMAL:
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "decimal() requires a string argument");
            ctx->error = 1;
            return NULL;
        }
        if (ctx->current.has_star_escape) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid escape sequence \\*: "
                          "only valid in like patterns");
            ctx->error = 1;
            return NULL;
        }
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_DECIMAL_LITERAL);
        if (node == NULL) {
            return NULL;
        }
        node->u.decimal_literal.text = ctx->current.value;
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        return node;

    case PHP_CEDAR_TOKEN_DATETIME:
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "datetime() requires a string argument");
            ctx->error = 1;
            return NULL;
        }
        if (ctx->current.has_star_escape) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid escape sequence \\*: "
                          "only valid in like patterns");
            ctx->error = 1;
            return NULL;
        }
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_DATETIME_LITERAL);
        if (node == NULL) {
            return NULL;
        }
        node->u.datetime_literal.text = ctx->current.value;
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        return node;

    case PHP_CEDAR_TOKEN_DURATION:
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "duration() requires a string argument");
            ctx->error = 1;
            return NULL;
        }
        if (ctx->current.has_star_escape) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid escape sequence \\*: "
                          "only valid in like patterns");
            ctx->error = 1;
            return NULL;
        }
        node = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_DURATION_LITERAL);
        if (node == NULL) {
            return NULL;
        }
        node->u.duration_literal.text = ctx->current.value;
        php_cedar_parser_advance(ctx);
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        return node;

    case PHP_CEDAR_TOKEN_IDENT:
        ident = ctx->current.value;
        php_cedar_parser_advance(ctx);
        return php_cedar_parse_entity_ref_with_ident(ctx, ident);

    case PHP_CEDAR_TOKEN_LPAREN:
        php_cedar_parser_advance(ctx);
        node = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            return NULL;
        }
        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }
        return node;

    case PHP_CEDAR_TOKEN_LBRACKET:
        return php_cedar_parse_set_literal(ctx);

    case PHP_CEDAR_TOKEN_LBRACE:
        return php_cedar_parse_record_literal(ctx);

    default:
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: unexpected token %d in expression",
                      ctx->current.type);
        ctx->error = 1;
        return NULL;
    }
}


/*
 * Parse one bracket-access step: `[ STRING ]`.
 * Called with `[` as the current token; returns a new
 * PHP_CEDAR_NODE_ATTR_ACCESS node wrapping `object` on success,
 * or NULL with ctx->error set on failure.
 */
static php_cedar_node_t *
php_cedar_parse_bracket_step(php_cedar_parser_ctx_t *ctx,
    php_cedar_node_t *object)
{
    php_cedar_node_t *access;
    php_cedar_str_t attr;

    php_cedar_parser_advance(ctx);  /* consume '[' */

    if (php_cedar_parser_consume_attr_name_string(ctx, &attr) != PHP_CEDAR_OK) {
        return NULL;
    }

    /*
     * Reject empty-string keys at parse time so the failure location
     * is reported by the parser rather than deferred to attribute
     * lookup during evaluation.
     */
    if (attr.len == 0) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: "
                      "bracket access key must be non-empty");
        ctx->error = 1;
        return NULL;
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RBRACKET) != PHP_CEDAR_OK) {
        return NULL;
    }

    access = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_ATTR_ACCESS);
    if (access == NULL) {
        return NULL;
    }

    access->u.attr_access.object = object;
    access->u.attr_access.attr = attr;

    return access;
}


/*
 * Parse one dot-access step: `.ident` (attribute access) or
 * `.ident(args)` (method call). Called with `.` as the current token;
 * returns a new node wrapping `object` on success, or NULL with
 * ctx->error set on failure.
 */
static php_cedar_node_t *
php_cedar_parse_dot_step(php_cedar_parser_ctx_t *ctx,
    php_cedar_node_t *object)
{
    php_cedar_node_t *access;
    php_cedar_str_t ident;

    php_cedar_parser_advance(ctx);  /* consume '.' */

    if (!php_cedar_token_is_ident(ctx->current.type)) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expected identifier after '.'");
        ctx->error = 1;
        return NULL;
    }

    ident = ctx->current.value;
    php_cedar_parser_advance(ctx);

    /* method call: expr.method(arg) or expr.method() */
    if (ctx->current.type == PHP_CEDAR_TOKEN_LPAREN) {
        php_cedar_node_t *call;

        php_cedar_parser_advance(ctx);

        call = php_cedar_parser_alloc_node(ctx,
                                           PHP_CEDAR_NODE_METHOD_CALL);
        if (call == NULL) {
            return NULL;
        }

        call->u.method_call.object = object;
        call->u.method_call.method = ident;

        if (ctx->current.type == PHP_CEDAR_TOKEN_RPAREN) {
            call->u.method_call.arg = NULL;

        } else {
            call->u.method_call.arg = php_cedar_parse_expr(ctx);
            if (ctx->error) {
                return NULL;
            }
        }

        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN) != PHP_CEDAR_OK) {
            return NULL;
        }

        return call;
    }

    /* attribute access: expr.ident */
    access = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_ATTR_ACCESS);
    if (access == NULL) {
        return NULL;
    }

    access->u.attr_access.object = object;
    access->u.attr_access.attr = ident;

    return access;
}


/*
 * parse member expression:
 *   primary { .ident | .ident(args) | [ STRING ] }
 *
 * Bracket access `expr["key"]` is semantically equivalent to `expr.key`;
 * both produce an PHP_CEDAR_NODE_ATTR_ACCESS node. Bracket access
 * supports attribute names that are not valid identifiers
 * (e.g. hyphenated "X-Request-Id") or that collide with keywords.
 */
static php_cedar_node_t *
php_cedar_parse_member_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node;
    php_cedar_uint_t chain;

    node = php_cedar_parse_primary(ctx);
    if (ctx->error) {
        return NULL;
    }

    chain = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_DOT
           || ctx->current.type == PHP_CEDAR_TOKEN_LBRACKET)
    {
        if (++chain > PHP_CEDAR_MAX_MEMBER_CHAIN) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many member access levels");
            ctx->error = 1;
            return NULL;
        }

        if (ctx->current.type == PHP_CEDAR_TOKEN_LBRACKET) {
            node = php_cedar_parse_bracket_step(ctx, node);
        } else {
            node = php_cedar_parse_dot_step(ctx, node);
        }

        if (node == NULL) {
            return NULL;
        }
    }

    return node;
}


/* parse mult expression: unary { * unary } */
static php_cedar_node_t *
php_cedar_parse_mult_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *left, *right, *binop;
    php_cedar_uint_t chain;

    left = php_cedar_parse_unary_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    chain = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_STAR) {
        if (++chain > PHP_CEDAR_MAX_BINOP_CHAIN) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many chained * operators");
            ctx->error = 1;
            return NULL;
        }

        php_cedar_parser_advance(ctx);

        right = php_cedar_parse_unary_expr(ctx);
        if (ctx->error) {
            return NULL;
        }

        binop = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_BINOP);
        if (binop == NULL) {
            return NULL;
        }

        binop->u.binop.op = PHP_CEDAR_OP_MUL;
        binop->u.binop.left = left;
        binop->u.binop.right = right;
        left = binop;
    }

    return left;
}


/* parse add expression: mult { (+ | -) mult } */
static php_cedar_node_t *
php_cedar_parse_add_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *left, *right, *binop;
    php_cedar_uint_t op, chain;

    left = php_cedar_parse_mult_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    chain = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_PLUS
           || ctx->current.type == PHP_CEDAR_TOKEN_MINUS)
    {
        if (++chain > PHP_CEDAR_MAX_BINOP_CHAIN) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "too many chained + or - operators");
            ctx->error = 1;
            return NULL;
        }

        op = (ctx->current.type == PHP_CEDAR_TOKEN_PLUS)
             ? PHP_CEDAR_OP_PLUS : PHP_CEDAR_OP_MINUS;
        php_cedar_parser_advance(ctx);

        right = php_cedar_parse_mult_expr(ctx);
        if (ctx->error) {
            return NULL;
        }

        binop = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_BINOP);
        if (binop == NULL) {
            return NULL;
        }

        binop->u.binop.op = op;
        binop->u.binop.left = left;
        binop->u.binop.right = right;
        left = binop;
    }

    return left;
}


/* parse relation expression: add [ relop add | has | like | is ] */
static php_cedar_node_t *
php_cedar_parse_relation_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *left, *right, *binop, *has_node;
    php_cedar_uint_t op;

    left = php_cedar_parse_add_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    /* has operator: expr has (IDENT | STRING) */
    if (ctx->current.type == PHP_CEDAR_TOKEN_HAS) {
        php_cedar_str_t attr;

        php_cedar_parser_advance(ctx);

        if (ctx->current.type == PHP_CEDAR_TOKEN_STRING) {
            if (php_cedar_parser_consume_attr_name_string(ctx, &attr)
                != PHP_CEDAR_OK)
            {
                return NULL;
            }

        } else if (php_cedar_token_is_ident(ctx->current.type)) {
            attr = ctx->current.value;
            php_cedar_parser_advance(ctx);

        } else {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "expected identifier or string after 'has'");
            ctx->error = 1;
            return NULL;
        }

        has_node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_HAS);
        if (has_node == NULL) {
            return NULL;
        }

        has_node->u.has.object = left;
        has_node->u.has.attr = attr;

        return has_node;
    }

    /* is operator: expr is type_name [in expr] */
    if (ctx->current.type == PHP_CEDAR_TOKEN_IS) {
        php_cedar_node_t *is_node;

        php_cedar_parser_advance(ctx);  /* consume is */

        is_node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_IS);
        if (is_node == NULL) {
            return NULL;
        }

        is_node->u.is_check.object = left;
        is_node->u.is_check.in_entity = NULL;

        if (php_cedar_parse_type_name(ctx,
                                      &is_node->u.is_check.entity_type)
            != PHP_CEDAR_OK)
        {
            return NULL;
        }

        if (ctx->current.type == PHP_CEDAR_TOKEN_IN) {
            php_cedar_parser_advance(ctx);

            is_node->u.is_check.in_entity =
                php_cedar_parse_add_expr(ctx);
            if (ctx->error) {
                return NULL;
            }
        }

        return is_node;
    }

    /* like operator: expr like STRING */
    if (ctx->current.type == PHP_CEDAR_TOKEN_LIKE) {
        php_cedar_node_t *like_node;

        php_cedar_parser_advance(ctx);

        if (ctx->current.type != PHP_CEDAR_TOKEN_STRING) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "expected string pattern after 'like'");
            ctx->error = 1;
            return NULL;
        }

        like_node = php_cedar_parser_alloc_node(ctx,
                                                PHP_CEDAR_NODE_LIKE);
        if (like_node == NULL) {
            return NULL;
        }

        like_node->u.like.object = left;

        if (php_cedar_parser_compile_pattern(ctx,
                                             &ctx->current.raw,
                                             &like_node->u.like.pattern)
            != PHP_CEDAR_OK)
        {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "invalid like pattern");
            return NULL;
        }

        php_cedar_parser_advance(ctx);

        return like_node;
    }

    if (ctx->current.type == PHP_CEDAR_TOKEN_EQ) {
        op = PHP_CEDAR_OP_EQ;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_NE) {
        op = PHP_CEDAR_OP_NE;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_IN) {
        op = PHP_CEDAR_OP_IN;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_LT) {
        op = PHP_CEDAR_OP_LT;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_GT) {
        op = PHP_CEDAR_OP_GT;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_LE) {
        op = PHP_CEDAR_OP_LE;
    } else if (ctx->current.type == PHP_CEDAR_TOKEN_GE) {
        op = PHP_CEDAR_OP_GE;
    } else {
        return left;
    }

    php_cedar_parser_advance(ctx);

    right = php_cedar_parse_add_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    binop = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_BINOP);
    if (binop == NULL) {
        return NULL;
    }

    binop->u.binop.op = op;
    binop->u.binop.left = left;
    binop->u.binop.right = right;

    return binop;
}


/* parse unary expression: [! | -] unary | relation */
static php_cedar_node_t *
php_cedar_parse_unary_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node, *operand;

    if (ctx->current.type == PHP_CEDAR_TOKEN_MINUS) {
        php_cedar_parser_advance(ctx);

        /* fold -literal into single negative LONG_LIT */
        if (ctx->current.type == PHP_CEDAR_TOKEN_NUMBER) {
            node = php_cedar_parser_alloc_node(ctx,
                                               PHP_CEDAR_NODE_LONG_LIT);
            if (node == NULL) {
                return NULL;
            }

            if (php_cedar_parse_neg_long(&ctx->current.value,
                                         &node->u.long_val) != PHP_CEDAR_OK)
            {
                php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                              "php_cedar_parse: integer overflow");
                ctx->error = 1;
                return NULL;
            }

            php_cedar_parser_advance(ctx);
            return node;
        }

        /* non-literal operand: wrap in NEGATE node */
        ctx->depth++;

        if (ctx->depth > PHP_CEDAR_MAX_PARSE_DEPTH) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: expression too deeply nested");
            ctx->error = 1;
            ctx->depth--;
            return NULL;
        }

        operand = php_cedar_parse_unary_expr(ctx);
        ctx->depth--;

        if (ctx->error) {
            return NULL;
        }

        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_NEGATE);
        if (node == NULL) {
            return NULL;
        }

        node->u.unop.operand = operand;
        return node;
    }

    if (ctx->current.type == PHP_CEDAR_TOKEN_NOT) {
        php_cedar_parser_advance(ctx);

        ctx->depth++;

        if (ctx->depth > PHP_CEDAR_MAX_PARSE_DEPTH) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: expression too deeply nested");
            ctx->error = 1;
            ctx->depth--;
            return NULL;
        }

        operand = php_cedar_parse_unary_expr(ctx);
        ctx->depth--;

        if (ctx->error) {
            return NULL;
        }

        node = php_cedar_parser_alloc_node(ctx, PHP_CEDAR_NODE_UNOP);
        if (node == NULL) {
            return NULL;
        }

        node->u.unop.operand = operand;
        return node;
    }

    return php_cedar_parse_member_expr(ctx);
}


/* parse and expression: relation { && relation } */
static php_cedar_node_t *
php_cedar_parse_and_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *left, *right, *binop;
    php_cedar_uint_t chain;

    left = php_cedar_parse_relation_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    chain = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_AND) {
        if (++chain > PHP_CEDAR_MAX_BINOP_CHAIN) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many chained && operators");
            ctx->error = 1;
            return NULL;
        }

        php_cedar_parser_advance(ctx);

        right = php_cedar_parse_relation_expr(ctx);
        if (ctx->error) {
            return NULL;
        }

        binop = php_cedar_parser_alloc_node(ctx,
                                            PHP_CEDAR_NODE_BINOP);
        if (binop == NULL) {
            return NULL;
        }

        binop->u.binop.op = PHP_CEDAR_OP_AND;
        binop->u.binop.left = left;
        binop->u.binop.right = right;
        left = binop;
    }

    return left;
}


/* parse or expression: and { || and } */
static php_cedar_node_t *
php_cedar_parse_or_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *left, *right, *binop;
    php_cedar_uint_t chain;

    left = php_cedar_parse_and_expr(ctx);
    if (ctx->error) {
        return NULL;
    }

    chain = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_OR) {
        if (++chain > PHP_CEDAR_MAX_BINOP_CHAIN) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many chained || operators");
            ctx->error = 1;
            return NULL;
        }

        php_cedar_parser_advance(ctx);

        right = php_cedar_parse_and_expr(ctx);
        if (ctx->error) {
            return NULL;
        }

        binop = php_cedar_parser_alloc_node(ctx,
                                            PHP_CEDAR_NODE_BINOP);
        if (binop == NULL) {
            return NULL;
        }

        binop->u.binop.op = PHP_CEDAR_OP_OR;
        binop->u.binop.left = left;
        binop->u.binop.right = right;
        left = binop;
    }

    return left;
}


/* parse expression (top-level): if-then-else | or_expr */
static php_cedar_node_t *
php_cedar_parse_expr(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_node_t *node;

    ctx->depth++;

    if (ctx->depth > PHP_CEDAR_MAX_PARSE_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                      "php_cedar_parse: expression too deeply nested");
        ctx->error = 1;
        ctx->depth--;
        return NULL;
    }

    /* if-then-else expression */
    if (ctx->current.type == PHP_CEDAR_TOKEN_IF) {
        php_cedar_node_t *ite;

        php_cedar_parser_advance(ctx);

        ite = php_cedar_parser_alloc_node(ctx,
                                          PHP_CEDAR_NODE_IF_THEN_ELSE);
        if (ite == NULL) {
            ctx->depth--;
            return NULL;
        }

        ite->u.if_then_else.cond = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            ctx->depth--;
            return NULL;
        }

        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_THEN)
            != PHP_CEDAR_OK)
        {
            ctx->depth--;
            return NULL;
        }

        ite->u.if_then_else.then_expr = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            ctx->depth--;
            return NULL;
        }

        if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_ELSE)
            != PHP_CEDAR_OK)
        {
            ctx->depth--;
            return NULL;
        }

        ite->u.if_then_else.else_expr = php_cedar_parse_expr(ctx);
        if (ctx->error) {
            ctx->depth--;
            return NULL;
        }

        ctx->depth--;
        return ite;
    }

    node = php_cedar_parse_or_expr(ctx);
    ctx->depth--;

    return node;
}


/* validate that all elements in a scope set are entity refs */
static php_cedar_int_t
php_cedar_parser_validate_scope_set(php_cedar_parser_ctx_t *ctx,
    php_cedar_node_t *node)
{
    php_cedar_node_t **elts;
    php_cedar_uint_t i;

    if (node->type != PHP_CEDAR_NODE_SET) {
        return PHP_CEDAR_OK;
    }

    if (node->u.set_elts == NULL) {
        return PHP_CEDAR_OK;
    }

    elts = node->u.set_elts->elts;

    for (i = 0; i < node->u.set_elts->nelts; i++) {
        if (elts[i]->type != PHP_CEDAR_NODE_ENTITY_REF) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: scope set must contain"
                          " only entity references");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }
    }

    return PHP_CEDAR_OK;
}


/* parse entity_ref or set literal for scope targets */
static php_cedar_node_t *
php_cedar_parse_entity_or_set(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_str_t ident;

    if (ctx->current.type == PHP_CEDAR_TOKEN_LBRACKET) {
        return php_cedar_parse_set_literal(ctx);
    }

    if (ctx->current.type == PHP_CEDAR_TOKEN_IDENT) {
        ident = ctx->current.value;
        php_cedar_parser_advance(ctx);
        return php_cedar_parse_entity_ref_with_ident(ctx, ident);
    }

    php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                  "php_cedar_parse: expected entity ref or set in scope");
    ctx->error = 1;
    return NULL;
}


/* parse entity_ref only (no set literal) */
static php_cedar_node_t *
php_cedar_parse_entity_ref_target(php_cedar_parser_ctx_t *ctx)
{
    php_cedar_str_t ident;

    if (ctx->current.type == PHP_CEDAR_TOKEN_IDENT) {
        ident = ctx->current.value;
        php_cedar_parser_advance(ctx);
        return php_cedar_parse_entity_ref_with_ident(ctx, ident);
    }

    php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                  "php_cedar_parse: expected entity ref in scope");
    ctx->error = 1;
    return NULL;
}


/*
 * parse scope: keyword [ (== | in) target | is type_name [in entity_ref] ]
 *
 * Cedar spec:
 *   == always takes entity_ref.
 *   in takes entity_ref (all scopes) or set_literal (action only).
 *   is/is-in is only allowed on principal and resource (not action).
 */
static php_cedar_int_t
php_cedar_parse_scope(php_cedar_parser_ctx_t *ctx,
    php_cedar_token_type_t var_token, php_cedar_scope_t *scope)
{
    if (php_cedar_parser_expect(ctx, var_token) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }

    if (ctx->current.type == PHP_CEDAR_TOKEN_EQ) {
        scope->constraint = PHP_CEDAR_SCOPE_EQ;
        php_cedar_parser_advance(ctx);

        /* == always takes entity_ref only */
        scope->target = php_cedar_parse_entity_ref_target(ctx);
        if (ctx->error) {
            return PHP_CEDAR_ERROR;
        }

    } else if (ctx->current.type == PHP_CEDAR_TOKEN_IN) {
        scope->constraint = PHP_CEDAR_SCOPE_IN;
        php_cedar_parser_advance(ctx);

        if (var_token == PHP_CEDAR_TOKEN_ACTION) {
            /* action: entity_ref or set_literal */
            scope->target = php_cedar_parse_entity_or_set(ctx);

            if (ctx->error) {
                return PHP_CEDAR_ERROR;
            }

            if (php_cedar_parser_validate_scope_set(ctx,
                                                    scope->target)
                != PHP_CEDAR_OK)
            {
                return PHP_CEDAR_ERROR;
            }
        } else {
            /* principal/resource: entity_ref only */
            scope->target = php_cedar_parse_entity_ref_target(ctx);

            if (ctx->error) {
                return PHP_CEDAR_ERROR;
            }
        }

    } else if (ctx->current.type == PHP_CEDAR_TOKEN_IS) {
        if (var_token == PHP_CEDAR_TOKEN_ACTION) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "'is' is not allowed in action scope");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        php_cedar_parser_advance(ctx);  /* consume is */

        if (php_cedar_parse_type_name(ctx, &scope->entity_type)
            != PHP_CEDAR_OK)
        {
            return PHP_CEDAR_ERROR;
        }

        if (ctx->current.type == PHP_CEDAR_TOKEN_IN) {
            scope->constraint = PHP_CEDAR_SCOPE_IS_IN;
            php_cedar_parser_advance(ctx);

            scope->target = php_cedar_parse_entity_ref_target(ctx);
            if (ctx->error) {
                return PHP_CEDAR_ERROR;
            }

        } else {
            scope->constraint = PHP_CEDAR_SCOPE_IS;
            scope->target = NULL;
        }

    } else {
        scope->constraint = PHP_CEDAR_SCOPE_NONE;
        scope->target = NULL;
    }

    return PHP_CEDAR_OK;
}


/* parse condition: (when | unless) { expr } */
static php_cedar_int_t
php_cedar_parse_condition(php_cedar_parser_ctx_t *ctx,
    php_cedar_condition_t *cond)
{
    if (ctx->current.type == PHP_CEDAR_TOKEN_UNLESS) {
        cond->is_unless = 1;
    } else {
        cond->is_unless = 0;
    }

    php_cedar_parser_advance(ctx);

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LBRACE)
        != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    cond->expr = php_cedar_parse_expr(ctx);
    if (ctx->error) {
        return PHP_CEDAR_ERROR;
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RBRACE)
        != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    return PHP_CEDAR_OK;
}


/* parse annotations: { "@" IDENT [ "(" STRING ")" ] } */
static php_cedar_int_t
php_cedar_parse_annotations(php_cedar_parser_ctx_t *ctx,
    php_cedar_policy_t *policy)
{
    php_cedar_annotation_t *ann;
    php_cedar_annotation_t *elts;
    php_cedar_uint_t i, count;

    policy->annotations = NULL;
    count = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_AT) {

        if (++count > PHP_CEDAR_MAX_ANNOTATIONS) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many annotations");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        php_cedar_parser_advance(ctx);  /* consume @ */

        /* expect identifier for annotation key */
        if (!php_cedar_token_is_ident(ctx->current.type)) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: "
                          "expected identifier after '@'");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        /* lazy-create annotations array */
        if (policy->annotations == NULL) {
            policy->annotations = php_cedar_array_create(ctx->pool, 4,
                                                   sizeof(php_cedar_annotation_t));
            if (policy->annotations == NULL) {
                ctx->error = 1;
                return PHP_CEDAR_ERROR;
            }
        }

        ann = php_cedar_array_push(policy->annotations);
        if (ann == NULL) {
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        ann->key = ctx->current.value;
        ann->value.data = NULL;
        ann->value.len = 0;

        php_cedar_parser_advance(ctx);  /* consume IDENT */

        /* optional value: "(" STRING ")" */
        if (ctx->current.type == PHP_CEDAR_TOKEN_LPAREN) {
            php_cedar_parser_advance(ctx);  /* consume ( */

            if (php_cedar_parser_consume_attr_name_string(ctx, &ann->value)
                != PHP_CEDAR_OK)
            {
                return PHP_CEDAR_ERROR;
            }

            if (php_cedar_parser_expect(ctx,
                                        PHP_CEDAR_TOKEN_RPAREN) != PHP_CEDAR_OK)
            {
                return PHP_CEDAR_ERROR;
            }
        }

        /* duplicate key check */
        if (policy->annotations->nelts > 1) {
            elts = policy->annotations->elts;

            for (i = 0; i < policy->annotations->nelts - 1; i++) {
                if (elts[i].key.len == ann->key.len
                    && php_cedar_memcmp(elts[i].key.data,
                                  ann->key.data,
                                  ann->key.len) == 0)
                {
                    php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                                  "php_cedar_parse: "
                                  "duplicate annotation key");
                    ctx->error = 1;
                    return PHP_CEDAR_ERROR;
                }
            }
        }
    }

    return PHP_CEDAR_OK;
}


/* parse a single policy */
static php_cedar_int_t
php_cedar_parse_policy(php_cedar_parser_ctx_t *ctx,
    php_cedar_policy_t *policy)
{
    php_cedar_condition_t *cond;
    php_cedar_uint_t nconds;

    /* effect */
    if (ctx->current.type == PHP_CEDAR_TOKEN_FORBID) {
        policy->is_forbid = 1;
    } else {
        policy->is_forbid = 0;
    }

    php_cedar_parser_advance(ctx);

    /* ( */
    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_LPAREN)
        != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    /* principal */
    if (php_cedar_parse_scope(ctx, PHP_CEDAR_TOKEN_PRINCIPAL,
                              &policy->principal) != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_COMMA) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }

    /* action */
    if (php_cedar_parse_scope(ctx, PHP_CEDAR_TOKEN_ACTION,
                              &policy->action) != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_COMMA) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }

    /* resource */
    if (php_cedar_parse_scope(ctx, PHP_CEDAR_TOKEN_RESOURCE,
                              &policy->resource) != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    /* ) */
    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_RPAREN)
        != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    /* conditions */
    policy->conditions = php_cedar_array_create(ctx->pool, 2,
                                          sizeof(php_cedar_condition_t));
    if (policy->conditions == NULL) {
        ctx->error = 1;
        return PHP_CEDAR_ERROR;
    }

    nconds = 0;

    while (ctx->current.type == PHP_CEDAR_TOKEN_WHEN
           || ctx->current.type == PHP_CEDAR_TOKEN_UNLESS)
    {
        if (++nconds > PHP_CEDAR_MAX_CONDITIONS) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, ctx->log, 0,
                          "php_cedar_parse: too many conditions per policy");
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        cond = php_cedar_array_push(policy->conditions);
        if (cond == NULL) {
            ctx->error = 1;
            return PHP_CEDAR_ERROR;
        }

        if (php_cedar_parse_condition(ctx, cond) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
    }

    /* ; */
    if (php_cedar_parser_expect(ctx, PHP_CEDAR_TOKEN_SEMICOLON)
        != PHP_CEDAR_OK)
    {
        return PHP_CEDAR_ERROR;
    }

    return PHP_CEDAR_OK;
}


php_cedar_policy_set_t *
php_cedar_parse(php_cedar_pool_t *pool, php_cedar_log_t *log, const php_cedar_str_t *text)
{
    php_cedar_parser_ctx_t ctx;
    php_cedar_policy_set_t *ps;
    php_cedar_policy_t *policy;

    if (pool == NULL || log == NULL || text == NULL) {
        return NULL;
    }

    php_cedar_memzero(&ctx, sizeof(php_cedar_parser_ctx_t));
    ctx.pool = pool;
    ctx.log = log;

    php_cedar_lexer_init(&ctx.lexer, pool, log, text);
    php_cedar_parser_advance(&ctx);

    ps = php_cedar_pcalloc(pool, sizeof(php_cedar_policy_set_t));
    if (ps == NULL) {
        return NULL;
    }

    ps->policies = php_cedar_array_create(pool, 4,
                                    sizeof(php_cedar_policy_t));
    if (ps->policies == NULL) {
        return NULL;
    }

    while (ctx.current.type == PHP_CEDAR_TOKEN_PERMIT
           || ctx.current.type == PHP_CEDAR_TOKEN_FORBID
           || ctx.current.type == PHP_CEDAR_TOKEN_AT)
    {
        if (ps->policies->nelts >= PHP_CEDAR_MAX_POLICIES) {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, log, 0,
                          "php_cedar_parse: too many policies (max %d)",
                          PHP_CEDAR_MAX_POLICIES);
            return NULL;
        }

        policy = php_cedar_array_push(ps->policies);
        if (policy == NULL) {
            return NULL;
        }

        php_cedar_memzero(policy, sizeof(php_cedar_policy_t));

        /* parse annotations before effect */
        if (php_cedar_parse_annotations(&ctx, policy) != PHP_CEDAR_OK) {
            return NULL;
        }

        if (ctx.current.type != PHP_CEDAR_TOKEN_PERMIT
            && ctx.current.type != PHP_CEDAR_TOKEN_FORBID)
        {
            php_cedar_log_error(PHP_CEDAR_LOG_ERR, log, 0,
                          "php_cedar_parse: "
                          "expected permit or forbid after annotations");
            return NULL;
        }

        if (php_cedar_parse_policy(&ctx, policy) != PHP_CEDAR_OK) {
            return NULL;
        }
    }

    if (ctx.current.type != PHP_CEDAR_TOKEN_EOF) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, log, 0,
                      "php_cedar_parse: unexpected token after policies");
        return NULL;
    }

    return ps;
}
