/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_expr.c - Cedar expression evaluator
 *
 * Recursively evaluates AST nodes.
 * Returns ERROR on missing attributes or type mismatch, making the policy
 * not applicable.
 */

#include "php_cedar_compat.h"
#include "php_cedar_expr.h"
#include "php_cedar_eval.h"


/* forward declaration: real evaluator body, wrapped by
 * php_cedar_expr_eval() to manage ctx->eval_depth. */
static php_cedar_value_t php_cedar_expr_eval_body(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool, php_cedar_log_t *log);


/*
 * Upper bound on the element count of a single record / set passed to
 * php_cedar_value_equals(). The bijective match uses a stack bitmap
 * sized for this limit; larger containers are rejected with PHP_CEDAR_ERROR
 * rather than risking incorrect equality on a degraded match. The
 * parser caps record literals at PHP_CEDAR_MAX_RECORD_ENTRIES (64) and
 * set literals at PHP_CEDAR_MAX_SET_ELEMENTS (256), so 1024 covers
 * those plus considerable headroom for injection-API growth.
 */
#define PHP_CEDAR_VALUE_EQUALS_MAX_ELTS  1024
#define PHP_CEDAR_VALUE_EQUALS_BITMAP_WORDS \
        ((PHP_CEDAR_VALUE_EQUALS_MAX_ELTS + 63) / 64)


/* value constructors */

static php_cedar_value_t
php_cedar_make_error(void)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_ERROR;
    return val;
}


static php_cedar_value_t
php_cedar_make_bool(php_cedar_flag_t b)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_BOOL;
    val.v.bool_val = b;
    return val;
}


static php_cedar_value_t
php_cedar_make_string(php_cedar_str_t s)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_STRING;
    val.v.str_val = s;
    return val;
}


static php_cedar_value_t
php_cedar_make_long(int64_t n)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_LONG;
    val.v.long_val = n;
    return val;
}


static php_cedar_value_t
php_cedar_make_entity(php_cedar_str_t type, php_cedar_str_t id)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_ENTITY;
    val.v.entity.type = type;
    val.v.entity.id = id;
    return val;
}


static php_cedar_value_t
php_cedar_make_record(php_cedar_array_t *attrs)
{
    php_cedar_value_t val;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_RECORD;
    val.v.record_attrs = attrs;
    return val;
}


/* parse bounded decimal: overflow-safe with leading-zero rejection */
static php_cedar_int_t
php_cedar_parse_bounded_dec(unsigned char **pp, unsigned char *end, php_cedar_uint_t max,
    php_cedar_uint_t *out)
{
    unsigned char *p, *start;
    php_cedar_uint_t val, digit;

    p = *pp;
    start = p;
    val = 0;

    if (p >= end || *p < '0' || *p > '9') {
        return PHP_CEDAR_ERROR;
    }

    while (p < end && *p >= '0' && *p <= '9') {
        digit = *p - '0';
        if (val > (max - digit) / 10) {
            return PHP_CEDAR_ERROR;
        }
        val = val * 10 + digit;
        p++;
    }

    /* reject leading zeros (e.g. "08", "010") */
    if (p - start > 1 && *start == '0') {
        return PHP_CEDAR_ERROR;
    }

    *out = val;
    *pp = p;

    return PHP_CEDAR_OK;
}


/* parse CIDR prefix length: digits after '/' with leading-zero rejection */
static php_cedar_int_t
php_cedar_parse_cidr_prefix(unsigned char **pp, unsigned char *end,
    php_cedar_uint_t max_prefix, php_cedar_uint_t *prefix_len)
{
    return php_cedar_parse_bounded_dec(pp, end, max_prefix, prefix_len);
}


/* parse IPv4 address: "a.b.c.d" with optional "/prefix" */
static php_cedar_int_t
php_cedar_parse_ipv4(unsigned char *data, size_t len,
    unsigned char *addr, php_cedar_uint_t *prefix_len)
{
    unsigned char *p, *end;
    php_cedar_uint_t octet, i;

    p = data;
    end = data + len;

    for (i = 0; i < 4; i++) {

        if (php_cedar_parse_bounded_dec(&p, end, 255, &octet) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }

        addr[i] = (unsigned char) octet;

        if (i < 3) {
            if (p >= end || *p != '.') {
                return PHP_CEDAR_ERROR;
            }
            p++;
        }
    }

    if (p < end && *p == '/') {
        p++;

        if (php_cedar_parse_cidr_prefix(&p, end, 32, prefix_len)
            != PHP_CEDAR_OK)
        {
            return PHP_CEDAR_ERROR;
        }

    } else {
        *prefix_len = 32;
    }

    if (p != end) {
        return PHP_CEDAR_ERROR;
    }

    return PHP_CEDAR_OK;
}


/* parse IPv6 address with optional "/prefix" */
static php_cedar_int_t
php_cedar_parse_ipv6(unsigned char *data, size_t len,
    unsigned char *addr, php_cedar_uint_t *prefix_len)
{
    unsigned char *p, *end, *slash;
    php_cedar_uint_t groups[8], n_groups, gap_pos, i, val;
    size_t addr_len;

    p = data;

    /* split off /prefix if present */
    slash = memchr(data, '/', len);

    if (slash != NULL) {
        addr_len = slash - data;
    } else {
        addr_len = len;
    }

    end = data + addr_len;
    php_cedar_memzero(groups, sizeof(groups));
    n_groups = 0;
    gap_pos = 8; /* sentinel: no gap */

    /* handle leading "::" */
    if (addr_len >= 2 && p[0] == ':' && p[1] == ':') {
        gap_pos = 0;
        p += 2;

        if (p == end) {
            /* just "::" */
            goto done_groups;
        }
    }

    while (p < end) {
        php_cedar_uint_t digits;

        if (n_groups >= 8) {
            return PHP_CEDAR_ERROR;
        }

        val = 0;
        digits = 0;

        if (*p < '0'
            || (*p > '9' && *p < 'A')
            || (*p > 'F' && *p < 'a')
            || *p > 'f')
        {
            return PHP_CEDAR_ERROR;
        }

        while (p < end && *p != ':') {
            if (++digits > 4) {
                return PHP_CEDAR_ERROR;
            }

            if (*p >= '0' && *p <= '9') {
                val = (val << 4) + (*p - '0');
            } else if (*p >= 'a' && *p <= 'f') {
                val = (val << 4) + (*p - 'a' + 10);
            } else if (*p >= 'A' && *p <= 'F') {
                val = (val << 4) + (*p - 'A' + 10);
            } else {
                return PHP_CEDAR_ERROR;
            }

            p++;
        }

        groups[n_groups++] = val;

        if (p < end && *p == ':') {
            p++;

            if (p < end && *p == ':') {
                if (gap_pos != 8) {
                    return PHP_CEDAR_ERROR; /* double :: */
                }
                gap_pos = n_groups;
                p++;

                if (p == end) {
                    break;
                }

            } else if (p >= end) {
                return PHP_CEDAR_ERROR; /* trailing single colon */
            }
        }
    }

done_groups:

    /* expand :: gap into 16-byte addr */
    php_cedar_memzero(addr, 16);

    if (gap_pos == 8) {
        /* no gap: must have exactly 8 groups */
        if (n_groups != 8) {
            return PHP_CEDAR_ERROR;
        }

        for (i = 0; i < 8; i++) {
            addr[i * 2] = (unsigned char) (groups[i] >> 8);
            addr[i * 2 + 1] = (unsigned char) (groups[i] & 0xFF);
        }

    } else {
        php_cedar_uint_t tail;

        if (n_groups < gap_pos) {
            return PHP_CEDAR_ERROR;
        }

        tail = n_groups - gap_pos;

        /* :: must expand to at least one zero group */
        if (gap_pos + tail >= 8) {
            return PHP_CEDAR_ERROR;
        }

        for (i = 0; i < gap_pos; i++) {
            addr[i * 2] = (unsigned char) (groups[i] >> 8);
            addr[i * 2 + 1] = (unsigned char) (groups[i] & 0xFF);
        }

        for (i = 0; i < tail; i++) {
            php_cedar_uint_t pos = 8 - tail + i;
            addr[pos * 2] =
                (unsigned char) (groups[gap_pos + i] >> 8);
            addr[pos * 2 + 1] =
                (unsigned char) (groups[gap_pos + i] & 0xFF);
        }
    }

    /* parse prefix */
    if (slash != NULL) {
        p = slash + 1;
        end = data + len;

        if (php_cedar_parse_cidr_prefix(&p, end, 128, prefix_len)
            != PHP_CEDAR_OK)
        {
            return PHP_CEDAR_ERROR;
        }

        if (p != end) {
            return PHP_CEDAR_ERROR;
        }

    } else {
        *prefix_len = 128;
    }

    return PHP_CEDAR_OK;
}


/*
 * Parse a Cedar decimal literal "[-]?d+\.d{1,4}" into an i64 with an
 * implicit scale of 10^4. The Cedar grammar requires at least one
 * digit on each side of the decimal point and at most four fractional
 * digits; anything else (missing integer part, missing fractional
 * digits, trailing garbage, scaled magnitude beyond int64_t) is
 * rejected as RVAL_ERROR. Leading zeros are tolerated to match the
 * reference parser.
 */
php_cedar_value_t
php_cedar_make_decimal(php_cedar_str_t *s)
{
    php_cedar_value_t val;
    unsigned char *p, *end;
    php_cedar_flag_t negative;
    int64_t int_part, frac_part, scaled;
    php_cedar_uint_t frac_digits;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_ERROR;

    if (s == NULL || s->len == 0) {
        return val;
    }

    p = s->data;
    end = p + s->len;

    negative = 0;
    if (*p == '-') {
        negative = 1;
        p++;
        if (p == end) {
            return val;
        }
    }

    if (p >= end || *p < '0' || *p > '9') {
        return val;
    }

    int_part = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        int64_t d = *p - '0';
        if (int_part > (INT64_MAX - d) / 10) {
            return val;
        }
        int_part = int_part * 10 + d;
        p++;
    }

    if (p >= end || *p != '.') {
        return val;
    }
    p++;

    frac_part = 0;
    frac_digits = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        if (frac_digits >= 4) {
            return val;
        }
        frac_part = frac_part * 10 + (*p - '0');
        frac_digits++;
        p++;
    }

    if (frac_digits == 0 || p != end) {
        return val;
    }

    while (frac_digits < 4) {
        frac_part *= 10;
        frac_digits++;
    }

    /*
     * Combine int_part and frac_part into the scaled i64 representation.
     * Sign is applied at the multiplication step so that the negative
     * range can reach INT64_MIN (-922337203685477.5808): if we negated
     * after assembly, the positive intermediate would overflow at
     * |INT64_MIN| and we would reject the value, diverging from the
     * Cedar reference parser whose range is symmetric only up to
     * 922337203685477.5807 / -922337203685477.5808.
     */
    if (negative) {
        if (__builtin_mul_overflow(int_part, (int64_t) -10000, &scaled)) {
            return val;
        }
        if (__builtin_sub_overflow(scaled, frac_part, &scaled)) {
            return val;
        }
    } else {
        if (__builtin_mul_overflow(int_part, (int64_t) 10000, &scaled)) {
            return val;
        }
        if (__builtin_add_overflow(scaled, frac_part, &scaled)) {
            return val;
        }
    }

    val.type = PHP_CEDAR_RVAL_DECIMAL;
    val.v.decimal_val = scaled;
    return val;
}


/* parse IP string to binary runtime value */
php_cedar_value_t
php_cedar_make_ip(php_cedar_str_t *s)
{
    php_cedar_value_t val;

    /*
     * Fast-path reject for obviously-too-long input. The longest valid
     * form is "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/128" (43 chars);
     * actual OOB protection lives in parse_ipv4 / parse_ipv6 which
     * clamp to data + len.
     */
    if (s->len == 0 || s->len > 43) {
        return php_cedar_make_error();
    }

    /*
     * zero the entire value including addr[4..15] so IPv4
     * (which only writes addr[0..3]) leaves no uninitialised bytes
     */
    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_IP;

    /* try IPv4 first (contains dots, no colons) */
    if (memchr(s->data, ':', s->len) == NULL) {
        if (php_cedar_parse_ipv4(s->data, s->len,
                                 val.v.ip_addr.addr,
                                 &val.v.ip_addr.prefix_len)
            != PHP_CEDAR_OK)
        {
            return php_cedar_make_error();
        }

        val.v.ip_addr.is_ipv6 = 0;
        return val;
    }

    /* IPv6 */
    if (php_cedar_parse_ipv6(s->data, s->len,
                             val.v.ip_addr.addr,
                             &val.v.ip_addr.prefix_len)
        != PHP_CEDAR_OK)
    {
        return php_cedar_make_error();
    }

    val.v.ip_addr.is_ipv6 = 1;
    return val;
}


/*
 * Strip the principal / action / resource slot tag from an entity
 * value before it crosses a composite-expression or container
 * boundary (set element, record value, if-then-else result).
 *
 * The slot is set in PHP_CEDAR_NODE_VAR so `in` can pick the matching
 * parents array on (type, id) collisions, but the tag is meaningful
 * only while the value is still syntactically the principal / action /
 * resource keyword. Once it is buried inside a composite, the derived
 * value must be treated as an arbitrary entity and match reflexively
 * only in `in` checks.
 */
static void
php_cedar_clear_entity_slot(php_cedar_value_t *val)
{
    if (val->type == PHP_CEDAR_RVAL_ENTITY) {
        val->v.entity.slot = PHP_CEDAR_ENTITY_SLOT_NONE;
    }
}


/* overflow-checked Long arithmetic (Cedar i64::checked_{add,sub,mul}).
 * Accepts any result representable in int64_t (including INT64_MIN);
 * rejects true overflow. */
static php_cedar_int_t
php_cedar_long_arith(php_cedar_op_t op, int64_t a, int64_t b, int64_t *out)
{
    switch (op) {
    case PHP_CEDAR_OP_PLUS:
        return __builtin_add_overflow(a, b, out) ? PHP_CEDAR_ERROR : PHP_CEDAR_OK;
    case PHP_CEDAR_OP_MINUS:
        return __builtin_sub_overflow(a, b, out) ? PHP_CEDAR_ERROR : PHP_CEDAR_OK;
    case PHP_CEDAR_OP_MUL:
        return __builtin_mul_overflow(a, b, out) ? PHP_CEDAR_ERROR : PHP_CEDAR_OK;
    default:
        return PHP_CEDAR_ERROR;
    }
}


/*
 * Tri-state value equality: returns 1 (equal), 0 (not equal), or
 * PHP_CEDAR_ERROR when either operand is RVAL_ERROR, when the recursion
 * exceeds PHP_CEDAR_MAX_VALUE_EQUALS_DEPTH, or when a set/record bitmap
 * cannot accommodate the comparand. Defense in depth: the normal
 * evaluation paths reject RVAL_ERROR before storing it in
 * record_attrs / set_elts, and the depth ceiling is well above what
 * MAX_RECORD_DEPTH / MAX_SET_DEPTH allow injected values to reach.
 * Callers must propagate PHP_CEDAR_ERROR as php_cedar_make_error() instead of
 * treating it as "not equal".
 *
 * `depth` is the number of value_equals frames already on the stack;
 * top-level callers pass 0, recursive calls pass depth + 1.
 */
static php_cedar_int_t
php_cedar_value_equals(php_cedar_value_t *a, php_cedar_value_t *b,
    php_cedar_uint_t depth)
{
    if (depth > PHP_CEDAR_MAX_VALUE_EQUALS_DEPTH) {
        return PHP_CEDAR_ERROR;
    }

    if (a->type == PHP_CEDAR_RVAL_ERROR
        || b->type == PHP_CEDAR_RVAL_ERROR)
    {
        return PHP_CEDAR_ERROR;
    }

    if (a->type != b->type) {
        return 0;
    }

    switch (a->type) {

    case PHP_CEDAR_RVAL_STRING:
        return php_cedar_str_eq(&a->v.str_val, &b->v.str_val);

    case PHP_CEDAR_RVAL_LONG:
        return (a->v.long_val == b->v.long_val);

    case PHP_CEDAR_RVAL_BOOL:
        return (a->v.bool_val == b->v.bool_val);

    case PHP_CEDAR_RVAL_ENTITY:
        return (php_cedar_str_eq(&a->v.entity.type, &b->v.entity.type)
                && php_cedar_str_eq(&a->v.entity.id, &b->v.entity.id));

    case PHP_CEDAR_RVAL_IP:
        return (a->v.ip_addr.is_ipv6 == b->v.ip_addr.is_ipv6
                && a->v.ip_addr.prefix_len == b->v.ip_addr.prefix_len
                && php_cedar_memcmp(a->v.ip_addr.addr, b->v.ip_addr.addr,
                              a->v.ip_addr.is_ipv6 ? 16 : 4) == 0);

    case PHP_CEDAR_RVAL_DECIMAL:
        return (a->v.decimal_val == b->v.decimal_val);

    case PHP_CEDAR_RVAL_SET:
        if (a->v.set_elts == NULL || b->v.set_elts == NULL) {
            return 0;
        }
        if (a->v.set_elts->nelts != b->v.set_elts->nelts) {
            return 0;
        }
        {
            php_cedar_value_t *a_elts = a->v.set_elts->elts;
            php_cedar_value_t *b_elts = b->v.set_elts->elts;
            php_cedar_uint_t i, j;
            uint64_t matched[PHP_CEDAR_VALUE_EQUALS_BITMAP_WORDS];

            if (a->v.set_elts->nelts > PHP_CEDAR_VALUE_EQUALS_MAX_ELTS) {
                return PHP_CEDAR_ERROR;
            }

            php_cedar_memzero(matched, sizeof(matched));

            for (i = 0; i < a->v.set_elts->nelts; i++) {
                php_cedar_flag_t found = 0;
                for (j = 0; j < b->v.set_elts->nelts; j++) {
                    php_cedar_int_t r;

                    if (matched[j >> 6] & ((uint64_t) 1 << (j & 63))) {
                        continue;
                    }

                    r = php_cedar_value_equals(&a_elts[i], &b_elts[j],
                                               depth + 1);
                    if (r == PHP_CEDAR_ERROR) {
                        return PHP_CEDAR_ERROR;
                    }
                    if (r) {
                        matched[j >> 6] |= (uint64_t) 1 << (j & 63);
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    return 0;
                }
            }
            return 1;
        }

    case PHP_CEDAR_RVAL_RECORD:
        if (a->v.record_attrs == NULL || b->v.record_attrs == NULL) {
            return 0;
        }
        if (a->v.record_attrs->nelts != b->v.record_attrs->nelts) {
            return 0;
        }
        {
            php_cedar_attr_t *a_attrs = a->v.record_attrs->elts;
            php_cedar_attr_t *b_attrs = b->v.record_attrs->elts;
            php_cedar_uint_t i, j;
            uint64_t matched[PHP_CEDAR_VALUE_EQUALS_BITMAP_WORDS];

            if (a->v.record_attrs->nelts
                > PHP_CEDAR_VALUE_EQUALS_MAX_ELTS)
            {
                return PHP_CEDAR_ERROR;
            }

            php_cedar_memzero(matched, sizeof(matched));

            for (i = 0; i < a->v.record_attrs->nelts; i++) {
                php_cedar_flag_t found = 0;
                for (j = 0; j < b->v.record_attrs->nelts; j++) {
                    php_cedar_int_t r;

                    if (matched[j >> 6] & ((uint64_t) 1 << (j & 63))) {
                        continue;
                    }
                    if (!php_cedar_str_eq(&a_attrs[i].name,
                                          &b_attrs[j].name))
                    {
                        continue;
                    }

                    r = php_cedar_value_equals(&a_attrs[i].value,
                                               &b_attrs[j].value,
                                               depth + 1);
                    if (r == PHP_CEDAR_ERROR) {
                        return PHP_CEDAR_ERROR;
                    }
                    if (r) {
                        matched[j >> 6] |= (uint64_t) 1 << (j & 63);
                        found = 1;
                        break;
                    }
                    /*
                     * Name matched but values differ. With unique keys
                     * (parser and injection API both enforce this on a
                     * and b independently) there is no other b[j] with
                     * the same name, so the records cannot be equal.
                     * Short-circuit the entire equality.
                     */
                    return 0;
                }
                if (!found) {
                    return 0;
                }
            }
            return 1;
        }

    default:
        return 0;
    }
}


/* find attribute by name in attr array */
static php_cedar_attr_t *
php_cedar_find_attr(php_cedar_array_t *attrs, php_cedar_str_t *name)
{
    php_cedar_attr_t *attr;
    php_cedar_uint_t i;

    if (attrs == NULL) {
        return NULL;
    }

    attr = attrs->elts;

    for (i = 0; i < attrs->nelts; i++) {
        if (php_cedar_str_eq(&attr[i].name, name)) {
            return &attr[i];
        }
    }

    return NULL;
}


/* resolve variable type to its attribute array */
static php_cedar_array_t *
php_cedar_resolve_var_attrs(php_cedar_var_type_t var_type,
    php_cedar_eval_ctx_t *ctx)
{
    switch (var_type) {

    case PHP_CEDAR_VAR_PRINCIPAL:
        return ctx->principal_attrs;

    case PHP_CEDAR_VAR_ACTION:
        return ctx->action_attrs;

    case PHP_CEDAR_VAR_RESOURCE:
        return ctx->resource_attrs;

    case PHP_CEDAR_VAR_CONTEXT:
        return ctx->context_attrs;

    default:
        return NULL;
    }
}


/*
 * Evaluate attribute access expr.attr.
 *
 * Fast path: object is a VAR (principal/action/resource/context) — look
 * up the attribute directly from the corresponding eval_ctx array.
 *
 * Slow path: object is any other expression (nested ATTR_ACCESS, etc.) —
 * evaluate it recursively. If the result is a record, look up the
 * attribute from the record's attr array; otherwise return error.
 */
static php_cedar_value_t
php_cedar_eval_attr_access(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool, php_cedar_log_t *log)
{
    php_cedar_node_t *object;
    php_cedar_array_t *attrs;
    php_cedar_attr_t *attr;
    php_cedar_value_t obj_val;

    object = node->u.attr_access.object;

    /* fast path: direct variable access */
    if (object->type == PHP_CEDAR_NODE_VAR) {
        attrs = php_cedar_resolve_var_attrs(object->u.var_type, ctx);
        if (attrs == NULL) {
            return php_cedar_make_error();
        }

        attr = php_cedar_find_attr(attrs, &node->u.attr_access.attr);
        if (attr == NULL) {
            return php_cedar_make_error();
        }

        return attr->value;
    }

    /* slow path: evaluate object and descend into record */
    obj_val = php_cedar_expr_eval(object, ctx, pool, log);
    if (obj_val.type == PHP_CEDAR_RVAL_ERROR) {
        return obj_val;
    }
    if (obj_val.type != PHP_CEDAR_RVAL_RECORD) {
        return php_cedar_make_error();
    }

    attr = php_cedar_find_attr(obj_val.v.record_attrs,
                               &node->u.attr_access.attr);
    if (attr == NULL) {
        return php_cedar_make_error();
    }

    return attr->value;
}


/*
 * Evaluate has expression.
 *
 * Fast path: object is a VAR — check the corresponding eval_ctx array.
 *
 * Slow path: object is any other expression — evaluate it. If the
 * result is a record, return whether the attribute exists. If the
 * object evaluation fails or produces a non-record, `has` is an error
 * per Cedar semantics (the expression is not applicable to the object).
 */
static php_cedar_value_t
php_cedar_eval_has(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool, php_cedar_log_t *log)
{
    php_cedar_node_t *object;
    php_cedar_array_t *attrs;
    php_cedar_value_t obj_val;

    object = node->u.has.object;

    if (object->type == PHP_CEDAR_NODE_VAR) {
        attrs = php_cedar_resolve_var_attrs(object->u.var_type, ctx);
        if (attrs == NULL) {
            return php_cedar_make_bool(0);
        }

        return php_cedar_make_bool(
            php_cedar_find_attr(attrs, &node->u.has.attr) != NULL);
    }

    obj_val = php_cedar_expr_eval(object, ctx, pool, log);
    if (obj_val.type == PHP_CEDAR_RVAL_ERROR) {
        return obj_val;
    }
    if (obj_val.type != PHP_CEDAR_RVAL_RECORD) {
        return php_cedar_make_error();
    }

    return php_cedar_make_bool(
        php_cedar_find_attr(obj_val.v.record_attrs,
                            &node->u.has.attr) != NULL);
}


/*
 * Wildcard pattern matching for like operator.
 * Pattern bytes: 0xFF = wildcard (matches 0+ chars), all others = literal.
 * Uses a greedy/backtracking approach.
 *
 * Invariant: patterns are always produced by
 * php_cedar_parser_compile_pattern(), which guarantees that 0xFF bytes
 * in the pattern are exclusively wildcard markers.  Subject strings may
 * contain arbitrary bytes (including 0xFF in non-UTF-8 input), but this
 * is safe: pattern-side 0xFF is always consumed first by the wildcard
 * branch (line *p == 0xFF), so it never reaches the literal comparison.
 */
static php_cedar_flag_t
php_cedar_like_match(php_cedar_str_t *subject, php_cedar_str_t *pattern)
{
    unsigned char *s, *p, *s_end, *p_end;
    unsigned char *star_p, *star_s;

    s = subject->data;
    s_end = s + subject->len;
    p = pattern->data;
    p_end = p + pattern->len;
    star_p = NULL;
    star_s = NULL;

    while (s < s_end) {
        if (p < p_end && *p == 0xFF) {
            /* wildcard: record position for backtracking */
            star_p = ++p;
            star_s = s;
            continue;
        }

        if (p < p_end && *p == *s) {
            p++;
            s++;
            continue;
        }

        /* mismatch: backtrack to last wildcard */
        if (star_p != NULL) {
            p = star_p;
            s = ++star_s;
            continue;
        }

        return 0;
    }

    /* consume trailing wildcards in pattern */
    while (p < p_end && *p == 0xFF) {
        p++;
    }

    return (p == p_end);
}


/* CIDR containment: true if obj (host or range) is entirely within range */
static php_cedar_flag_t
php_cedar_ip_cidr_contains(php_cedar_value_t *obj,
    php_cedar_value_t *range)
{
    php_cedar_uint_t addr_len, full_bytes, remaining_bits;
    unsigned char mask;

    if (obj->v.ip_addr.is_ipv6 != range->v.ip_addr.is_ipv6) {
        return 0;
    }

    if (obj->v.ip_addr.prefix_len < range->v.ip_addr.prefix_len) {
        return 0;
    }

    addr_len = obj->v.ip_addr.is_ipv6 ? 16 : 4;
    full_bytes = range->v.ip_addr.prefix_len / 8;
    remaining_bits = range->v.ip_addr.prefix_len % 8;

    if (full_bytes > 0
        && php_cedar_memcmp(obj->v.ip_addr.addr,
                      range->v.ip_addr.addr, full_bytes) != 0)
    {
        return 0;
    }

    if (remaining_bits > 0 && full_bytes < addr_len) {
        mask = (unsigned char) (0xFF << (8 - remaining_bits));

        if ((obj->v.ip_addr.addr[full_bytes] & mask)
            != (range->v.ip_addr.addr[full_bytes] & mask))
        {
            return 0;
        }
    }

    return 1;
}


/* build well-known IP CIDR range from a fixed prefix byte sequence */
static php_cedar_value_t
php_cedar_make_ip_range(php_cedar_flag_t is_ipv6,
    const unsigned char *prefix_bytes, php_cedar_uint_t prefix_len)
{
    php_cedar_value_t val;
    php_cedar_uint_t addr_len;

    php_cedar_memzero(&val, sizeof(php_cedar_value_t));
    val.type = PHP_CEDAR_RVAL_IP;
    val.v.ip_addr.is_ipv6 = is_ipv6;
    val.v.ip_addr.prefix_len = prefix_len;
    addr_len = is_ipv6 ? 16 : 4;
    php_cedar_memcpy(val.v.ip_addr.addr, prefix_bytes, addr_len);
    return val;
}


/* evaluate method call: expr.method(arg) or expr.method() */
static php_cedar_value_t
php_cedar_eval_method_call(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool,
    php_cedar_log_t *log)
{
    php_cedar_value_t obj, arg;
    php_cedar_str_t *method;
    php_cedar_value_t *obj_elts, *arg_elts;
    php_cedar_uint_t i, j;

    obj = php_cedar_expr_eval(node->u.method_call.object, ctx,
                              pool, log);
    if (obj.type == PHP_CEDAR_RVAL_ERROR) {
        return obj;
    }

    method = &node->u.method_call.method;

    /* zero-argument methods */
    if (node->u.method_call.arg == NULL) {
        /* isEmpty: receiver must be a Set */
        if (method->len == 7
            && php_cedar_memcmp(method->data, "isEmpty", 7) == 0)
        {
            if (obj.type != PHP_CEDAR_RVAL_SET) {
                return php_cedar_make_error();
            }

            if (obj.v.set_elts == NULL) {
                return php_cedar_make_error();
            }

            return php_cedar_make_bool(obj.v.set_elts->nelts == 0);
        }

        /* IP inspection methods: receiver must be IP */
        if (obj.type != PHP_CEDAR_RVAL_IP) {
            return php_cedar_make_error();
        }

        /* isIpv4 */
        if (method->len == 6
            && php_cedar_memcmp(method->data, "isIpv4", 6) == 0)
        {
            return php_cedar_make_bool(!obj.v.ip_addr.is_ipv6);
        }

        /* isIpv6 */
        if (method->len == 6
            && php_cedar_memcmp(method->data, "isIpv6", 6) == 0)
        {
            return php_cedar_make_bool(obj.v.ip_addr.is_ipv6);
        }

        /* isLoopback: IPv4 127.0.0.0/8, IPv6 ::1/128 */
        if (method->len == 10
            && php_cedar_memcmp(method->data, "isLoopback", 10) == 0)
        {
            static const unsigned char loopback_v4[4] = { 127, 0, 0, 0 };
            static const unsigned char loopback_v6[16] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1
            };
            php_cedar_value_t range;

            if (obj.v.ip_addr.is_ipv6) {
                range = php_cedar_make_ip_range(1, loopback_v6, 128);

            } else {
                range = php_cedar_make_ip_range(0, loopback_v4, 8);
            }

            return php_cedar_make_bool(
                php_cedar_ip_cidr_contains(&obj, &range));
        }

        /* isMulticast: IPv4 224.0.0.0/4, IPv6 ff00::/8 */
        if (method->len == 11
            && php_cedar_memcmp(method->data, "isMulticast", 11) == 0)
        {
            static const unsigned char multicast_v4[4] = { 224, 0, 0, 0 };
            static const unsigned char multicast_v6[16] = {
                0xff, 0, 0, 0, 0, 0, 0, 0,
                0,    0, 0, 0, 0, 0, 0, 0
            };
            php_cedar_value_t range;

            if (obj.v.ip_addr.is_ipv6) {
                range = php_cedar_make_ip_range(1, multicast_v6, 8);

            } else {
                range = php_cedar_make_ip_range(0, multicast_v4, 4);
            }

            return php_cedar_make_bool(
                php_cedar_ip_cidr_contains(&obj, &range));
        }

        /* unknown zero-arg method */
        return php_cedar_make_error();
    }

    arg = php_cedar_expr_eval(node->u.method_call.arg, ctx,
                              pool, log);
    if (arg.type == PHP_CEDAR_RVAL_ERROR) {
        return arg;
    }

    /* containsAll */
    if (method->len == 11
        && php_cedar_memcmp(method->data, "containsAll", 11) == 0)
    {
        if (obj.type != PHP_CEDAR_RVAL_SET
            || arg.type != PHP_CEDAR_RVAL_SET)
        {
            return php_cedar_make_error();
        }

        if (obj.v.set_elts == NULL || arg.v.set_elts == NULL) {
            return php_cedar_make_error();
        }

        obj_elts = obj.v.set_elts->elts;
        arg_elts = arg.v.set_elts->elts;

        /* every element in arg must exist in obj */
        for (i = 0; i < arg.v.set_elts->nelts; i++) {
            php_cedar_flag_t found = 0;

            for (j = 0; j < obj.v.set_elts->nelts; j++) {
                php_cedar_int_t r = php_cedar_value_equals(&arg_elts[i],
                                                     &obj_elts[j], 0);
                if (r == PHP_CEDAR_ERROR) {
                    return php_cedar_make_error();
                }
                if (r) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                return php_cedar_make_bool(0);
            }
        }

        return php_cedar_make_bool(1);
    }

    /* containsAny */
    if (method->len == 11
        && php_cedar_memcmp(method->data, "containsAny", 11) == 0)
    {
        if (obj.type != PHP_CEDAR_RVAL_SET
            || arg.type != PHP_CEDAR_RVAL_SET)
        {
            return php_cedar_make_error();
        }

        if (obj.v.set_elts == NULL || arg.v.set_elts == NULL) {
            return php_cedar_make_error();
        }

        obj_elts = obj.v.set_elts->elts;
        arg_elts = arg.v.set_elts->elts;

        /* at least one element in arg must exist in obj */
        for (i = 0; i < arg.v.set_elts->nelts; i++) {
            for (j = 0; j < obj.v.set_elts->nelts; j++) {
                php_cedar_int_t r = php_cedar_value_equals(&arg_elts[i],
                                                     &obj_elts[j], 0);
                if (r == PHP_CEDAR_ERROR) {
                    return php_cedar_make_error();
                }
                if (r) {
                    return php_cedar_make_bool(1);
                }
            }
        }

        return php_cedar_make_bool(0);
    }

    /* contains (single element membership) */
    if (method->len == 8
        && php_cedar_memcmp(method->data, "contains", 8) == 0)
    {
        if (obj.type != PHP_CEDAR_RVAL_SET) {
            return php_cedar_make_error();
        }

        if (obj.v.set_elts == NULL) {
            return php_cedar_make_error();
        }

        obj_elts = obj.v.set_elts->elts;

        for (i = 0; i < obj.v.set_elts->nelts; i++) {
            php_cedar_int_t r = php_cedar_value_equals(&obj_elts[i], &arg, 0);
            if (r == PHP_CEDAR_ERROR) {
                return php_cedar_make_error();
            }
            if (r) {
                return php_cedar_make_bool(1);
            }
        }

        return php_cedar_make_bool(0);
    }

    /* isInRange (IP address range membership) */
    if (method->len == 9
        && php_cedar_memcmp(method->data, "isInRange", 9) == 0)
    {
        if (obj.type != PHP_CEDAR_RVAL_IP
            || arg.type != PHP_CEDAR_RVAL_IP)
        {
            return php_cedar_make_error();
        }

        return php_cedar_make_bool(
            php_cedar_ip_cidr_contains(&obj, &arg));
    }

    /*
     * Decimal comparison methods. Cedar exposes ordering on decimals
     * only via these four methods; the binary <, <=, >, >= operators
     * remain reserved for Long. Both receiver and argument must be
     * RVAL_DECIMAL, otherwise the method is not applicable and the
     * containing policy is treated as a non-match.
     */
    if (obj.type == PHP_CEDAR_RVAL_DECIMAL
        || arg.type == PHP_CEDAR_RVAL_DECIMAL)
    {
        if (obj.type != PHP_CEDAR_RVAL_DECIMAL
            || arg.type != PHP_CEDAR_RVAL_DECIMAL)
        {
            return php_cedar_make_error();
        }

        if (method->len == 8
            && php_cedar_memcmp(method->data, "lessThan", 8) == 0)
        {
            return php_cedar_make_bool(
                obj.v.decimal_val < arg.v.decimal_val);
        }

        if (method->len == 15
            && php_cedar_memcmp(method->data, "lessThanOrEqual", 15) == 0)
        {
            return php_cedar_make_bool(
                obj.v.decimal_val <= arg.v.decimal_val);
        }

        if (method->len == 11
            && php_cedar_memcmp(method->data, "greaterThan", 11) == 0)
        {
            return php_cedar_make_bool(
                obj.v.decimal_val > arg.v.decimal_val);
        }

        if (method->len == 18
            && php_cedar_memcmp(method->data, "greaterThanOrEqual", 18) == 0)
        {
            return php_cedar_make_bool(
                obj.v.decimal_val >= arg.v.decimal_val);
        }

        return php_cedar_make_error();
    }

    /* unknown method */
    return php_cedar_make_error();
}


/* entity in entity-or-set check, reflexive-transitive over parents */
static php_cedar_value_t
php_cedar_eval_in(php_cedar_value_t *left, php_cedar_value_t *right,
    php_cedar_eval_ctx_t *ctx)
{
    php_cedar_value_t *elts;
    php_cedar_array_t *parents;
    php_cedar_uint_t i;

    if (left->type != PHP_CEDAR_RVAL_ENTITY) {
        return php_cedar_make_error();
    }

    parents = php_cedar_eval_ctx_lookup_parents(ctx, left->v.entity.slot);

    /* entity in entity */
    if (right->type == PHP_CEDAR_RVAL_ENTITY) {
        return php_cedar_make_bool(php_cedar_entity_in_target(
                                       &left->v.entity.type, &left->v.entity.id,
                                       parents,
                                       &right->v.entity.type,
                                       &right->v.entity.id));
    }

    /*
     * entity in set: every element must be an entity (Cedar requires
     * the right-hand side of `in` to be homogeneous), then any single
     * entity matching reflexively or via parents wins. Scanning the
     * full set before returning keeps the result order-independent —
     * `[matching, 1]` and `[1, matching]` both surface the type error.
     */
    if (right->type == PHP_CEDAR_RVAL_SET) {
        php_cedar_flag_t found;

        if (right->v.set_elts == NULL) {
            return php_cedar_make_bool(0);
        }

        elts = right->v.set_elts->elts;
        found = 0;

        for (i = 0; i < right->v.set_elts->nelts; i++) {
            if (elts[i].type != PHP_CEDAR_RVAL_ENTITY) {
                return php_cedar_make_error();
            }
            if (php_cedar_entity_in_target(
                    &left->v.entity.type, &left->v.entity.id, parents,
                    &elts[i].v.entity.type, &elts[i].v.entity.id))
            {
                found = 1;
            }
        }

        return php_cedar_make_bool(found);
    }

    return php_cedar_make_error();
}


/* evaluate entity type check: expr is Type [in expr] */
static php_cedar_value_t
php_cedar_eval_is_check(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool,
    php_cedar_log_t *log)
{
    php_cedar_value_t left, right;

    left = php_cedar_expr_eval(node->u.is_check.object, ctx, pool, log);
    if (left.type == PHP_CEDAR_RVAL_ERROR) {
        return left;
    }
    if (left.type != PHP_CEDAR_RVAL_ENTITY) {
        return php_cedar_make_error();
    }

    if (!php_cedar_str_eq(&left.v.entity.type,
                          &node->u.is_check.entity_type))
    {
        return php_cedar_make_bool(0);
    }

    if (node->u.is_check.in_entity == NULL) {
        return php_cedar_make_bool(1);
    }

    right = php_cedar_expr_eval(node->u.is_check.in_entity, ctx,
                                pool, log);
    if (right.type == PHP_CEDAR_RVAL_ERROR) {
        return right;
    }

    return php_cedar_eval_in(&left, &right, ctx);
}


static php_cedar_value_t
php_cedar_expr_eval_body(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool,
    php_cedar_log_t *log)
{
    php_cedar_value_t left, right, val;
    php_cedar_node_t **node_elts;
    php_cedar_value_t *val_slot;
    php_cedar_uint_t i;

    if (node == NULL) {
        return php_cedar_make_error();
    }

    switch (node->type) {

    case PHP_CEDAR_NODE_BOOL_LIT:
        return php_cedar_make_bool(node->u.bool_val);

    case PHP_CEDAR_NODE_STRING_LIT:
        return php_cedar_make_string(node->u.string_val);

    case PHP_CEDAR_NODE_LONG_LIT:
        return php_cedar_make_long(node->u.long_val);

    case PHP_CEDAR_NODE_IP_LITERAL:
        return php_cedar_make_ip(&node->u.ip_literal.addr);

    case PHP_CEDAR_NODE_DECIMAL_LITERAL:
        return php_cedar_make_decimal(&node->u.decimal_literal.text);

    case PHP_CEDAR_NODE_ENTITY_REF:
        return php_cedar_make_entity(node->u.entity_ref.entity_type,
                                     node->u.entity_ref.entity_id);

    case PHP_CEDAR_NODE_VAR:
        switch (node->u.var_type) {
        case PHP_CEDAR_VAR_PRINCIPAL:
            val = php_cedar_make_entity(ctx->principal_type,
                                        ctx->principal_id);
            val.v.entity.slot = PHP_CEDAR_ENTITY_SLOT_PRINCIPAL;
            return val;
        case PHP_CEDAR_VAR_ACTION:
            val = php_cedar_make_entity(ctx->action_type,
                                        ctx->action_id);
            val.v.entity.slot = PHP_CEDAR_ENTITY_SLOT_ACTION;
            return val;
        case PHP_CEDAR_VAR_RESOURCE:
            val = php_cedar_make_entity(ctx->resource_type,
                                        ctx->resource_id);
            val.v.entity.slot = PHP_CEDAR_ENTITY_SLOT_RESOURCE;
            return val;
        case PHP_CEDAR_VAR_CONTEXT:
            /* context alone is not a value; only context.attr */
            return php_cedar_make_error();
        default:
            return php_cedar_make_error();
        }

    case PHP_CEDAR_NODE_ATTR_ACCESS:
        return php_cedar_eval_attr_access(node, ctx, pool, log);

    case PHP_CEDAR_NODE_SET:
        if (node->u.set_elts == NULL) {
            return php_cedar_make_error();
        }

        php_cedar_memzero(&val, sizeof(php_cedar_value_t));
        val.type = PHP_CEDAR_RVAL_SET;
        val.v.set_elts = php_cedar_array_create(pool,
                                          node->u.set_elts->nelts,
                                          sizeof(php_cedar_value_t));
        if (val.v.set_elts == NULL) {
            return php_cedar_make_error();
        }

        node_elts = node->u.set_elts->elts;

        for (i = 0; i < node->u.set_elts->nelts; i++) {
            left = php_cedar_expr_eval(node_elts[i], ctx, pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return php_cedar_make_error();
            }

            val_slot = php_cedar_array_push(val.v.set_elts);
            if (val_slot == NULL) {
                return php_cedar_make_error();
            }
            php_cedar_clear_entity_slot(&left);
            *val_slot = left;
        }

        return val;

    case PHP_CEDAR_NODE_RECORD: {
        php_cedar_record_entry_t *entries;
        php_cedar_attr_t *attr_slot;
        php_cedar_array_t *attrs;

        if (node->u.record_entries == NULL) {
            return php_cedar_make_error();
        }

        /* avoid php_cedar_palloc(pool, 0) for empty record `{}` */
        attrs = php_cedar_array_create(pool,
                                 node->u.record_entries->nelts > 0
                                 ? node->u.record_entries->nelts : 1,
                                 sizeof(php_cedar_attr_t));
        if (attrs == NULL) {
            return php_cedar_make_error();
        }

        entries = node->u.record_entries->elts;

        for (i = 0; i < node->u.record_entries->nelts; i++) {
            left = php_cedar_expr_eval(entries[i].value, ctx, pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return php_cedar_make_error();
            }

            attr_slot = php_cedar_array_push(attrs);
            if (attr_slot == NULL) {
                return php_cedar_make_error();
            }

            php_cedar_clear_entity_slot(&left);
            attr_slot->name = entries[i].key;
            attr_slot->value = left;
        }

        return php_cedar_make_record(attrs);
    }

    case PHP_CEDAR_NODE_BINOP:
        switch (node->u.binop.op) {

        case PHP_CEDAR_OP_AND:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            if (left.type != PHP_CEDAR_RVAL_BOOL) {
                return php_cedar_make_error();
            }
            if (!left.v.bool_val) {
                return php_cedar_make_bool(0);
            }

            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (right.type != PHP_CEDAR_RVAL_BOOL) {
                return php_cedar_make_error();
            }
            return right;

        case PHP_CEDAR_OP_OR:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            if (left.type != PHP_CEDAR_RVAL_BOOL) {
                return php_cedar_make_error();
            }
            if (left.v.bool_val) {
                return php_cedar_make_bool(1);
            }

            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (right.type != PHP_CEDAR_RVAL_BOOL) {
                return php_cedar_make_error();
            }
            return right;

        case PHP_CEDAR_OP_EQ:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (left.type != right.type) {
                return php_cedar_make_error();
            }
            {
                php_cedar_int_t r = php_cedar_value_equals(&left, &right, 0);
                if (r == PHP_CEDAR_ERROR) {
                    return php_cedar_make_error();
                }
                return php_cedar_make_bool(r);
            }

        case PHP_CEDAR_OP_NE:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (left.type != right.type) {
                return php_cedar_make_error();
            }
            {
                php_cedar_int_t r = php_cedar_value_equals(&left, &right, 0);
                if (r == PHP_CEDAR_ERROR) {
                    return php_cedar_make_error();
                }
                return php_cedar_make_bool(!r);
            }

        case PHP_CEDAR_OP_IN:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            return php_cedar_eval_in(&left, &right, ctx);

        case PHP_CEDAR_OP_LT:
        case PHP_CEDAR_OP_GT:
        case PHP_CEDAR_OP_LE:
        case PHP_CEDAR_OP_GE:
            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (left.type != PHP_CEDAR_RVAL_LONG
                || right.type != PHP_CEDAR_RVAL_LONG)
            {
                return php_cedar_make_error();
            }

            switch (node->u.binop.op) {
            case PHP_CEDAR_OP_LT:
                return php_cedar_make_bool(
                    left.v.long_val < right.v.long_val);
            case PHP_CEDAR_OP_GT:
                return php_cedar_make_bool(
                    left.v.long_val > right.v.long_val);
            case PHP_CEDAR_OP_LE:
                return php_cedar_make_bool(
                    left.v.long_val <= right.v.long_val);
            case PHP_CEDAR_OP_GE:
                return php_cedar_make_bool(
                    left.v.long_val >= right.v.long_val);
            default:
                return php_cedar_make_error();
            }

        case PHP_CEDAR_OP_PLUS:
        case PHP_CEDAR_OP_MINUS:
        case PHP_CEDAR_OP_MUL: {
            int64_t result;

            left = php_cedar_expr_eval(node->u.binop.left, ctx,
                                       pool, log);
            if (left.type == PHP_CEDAR_RVAL_ERROR) {
                return left;
            }
            right = php_cedar_expr_eval(node->u.binop.right, ctx,
                                        pool, log);
            if (right.type == PHP_CEDAR_RVAL_ERROR) {
                return right;
            }
            if (left.type != PHP_CEDAR_RVAL_LONG
                || right.type != PHP_CEDAR_RVAL_LONG)
            {
                return php_cedar_make_error();
            }
            if (php_cedar_long_arith(node->u.binop.op,
                                     left.v.long_val, right.v.long_val,
                                     &result) != PHP_CEDAR_OK)
            {
                return php_cedar_make_error();
            }
            return php_cedar_make_long(result);
        }

        default:
            return php_cedar_make_error();
        }

    case PHP_CEDAR_NODE_UNOP:
        left = php_cedar_expr_eval(node->u.unop.operand, ctx,
                                   pool, log);
        if (left.type == PHP_CEDAR_RVAL_ERROR) {
            return left;
        }
        if (left.type != PHP_CEDAR_RVAL_BOOL) {
            return php_cedar_make_error();
        }
        return php_cedar_make_bool(!left.v.bool_val);

    case PHP_CEDAR_NODE_NEGATE:
        left = php_cedar_expr_eval(node->u.unop.operand, ctx,
                                   pool, log);
        if (left.type == PHP_CEDAR_RVAL_ERROR) {
            return left;
        }
        if (left.type != PHP_CEDAR_RVAL_LONG) {
            return php_cedar_make_error();
        }
        /* -INT64_MIN is undefined; reject it */
        if (left.v.long_val == INT64_MIN) {
            return php_cedar_make_error();
        }
        return php_cedar_make_long(-left.v.long_val);

    /* Phase 2 */
    case PHP_CEDAR_NODE_HAS:
        return php_cedar_eval_has(node, ctx, pool, log);

    case PHP_CEDAR_NODE_LIKE:
        left = php_cedar_expr_eval(node->u.like.object, ctx,
                                   pool, log);
        if (left.type == PHP_CEDAR_RVAL_ERROR) {
            return left;
        }
        if (left.type != PHP_CEDAR_RVAL_STRING) {
            return php_cedar_make_error();
        }
        return php_cedar_make_bool(
            php_cedar_like_match(&left.v.str_val,
                                 &node->u.like.pattern));

    case PHP_CEDAR_NODE_METHOD_CALL:
        return php_cedar_eval_method_call(node, ctx, pool, log);

    case PHP_CEDAR_NODE_IS:
        return php_cedar_eval_is_check(node, ctx, pool, log);

    case PHP_CEDAR_NODE_IF_THEN_ELSE:
        left = php_cedar_expr_eval(node->u.if_then_else.cond, ctx,
                                   pool, log);
        if (left.type == PHP_CEDAR_RVAL_ERROR) {
            return left;
        }
        if (left.type != PHP_CEDAR_RVAL_BOOL) {
            return php_cedar_make_error();
        }
        if (left.v.bool_val) {
            val = php_cedar_expr_eval(
                node->u.if_then_else.then_expr, ctx, pool, log);

        } else {
            val = php_cedar_expr_eval(
                node->u.if_then_else.else_expr, ctx, pool, log);
        }
        php_cedar_clear_entity_slot(&val);
        return val;

    default:
        return php_cedar_make_error();
    }
}


/*
 * Public expression evaluator. Manages ctx->eval_depth as a recursion
 * guard so deeply nested AST or value walks (record / set values
 * injected at runtime) cannot blow the C stack: when ctx->eval_depth
 * would exceed PHP_CEDAR_MAX_EVAL_DEPTH the call short-circuits to an
 * RVAL_ERROR, which propagates to the policy as deny.
 */
php_cedar_value_t
php_cedar_expr_eval(php_cedar_node_t *node,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool,
    php_cedar_log_t *log)
{
    php_cedar_value_t val;

    if (ctx == NULL) {
        return php_cedar_make_error();
    }

    if (ctx->eval_depth >= PHP_CEDAR_MAX_EVAL_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, log, 0,
                      "php_cedar_expr_eval: "
                      "recursion depth exceeded (max %d)",
                      PHP_CEDAR_MAX_EVAL_DEPTH);
        return php_cedar_make_error();
    }

    ctx->eval_depth++;
    val = php_cedar_expr_eval_body(node, ctx, pool, log);
    ctx->eval_depth--;

    return val;
}
