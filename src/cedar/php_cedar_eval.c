/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_eval.c - Cedar policy set evaluator
 *
 * Forbid-priority evaluation model:
 * 1. Evaluate all policies
 * 2. If any forbid matches -> DENY
 * 3. If any permit matches -> ALLOW
 * 4. If none match -> DENY (default deny)
 */

#include "php_cedar_compat.h"
#include "php_cedar_eval.h"


/* --- scope matching --- */

/*
 * Reflexive-transitive entity membership check used by `in` scope
 * constraints and the `in` expression operator. `parents` is the
 * pre-computed transitive closure supplied through
 * php_cedar_eval_ctx_add_*_parent(); the reflexive case (X in X) is
 * handled inline without registration.
 */
php_cedar_int_t
php_cedar_entity_in_target(const php_cedar_str_t *entity_type,
    const php_cedar_str_t *entity_id, php_cedar_array_t *parents,
    const php_cedar_str_t *target_type, const php_cedar_str_t *target_id)
{
    php_cedar_entity_ref_t *elts;
    php_cedar_uint_t i;

    if (php_cedar_str_eq(entity_type, target_type)
        && php_cedar_str_eq(entity_id, target_id))
    {
        return 1;
    }

    if (parents == NULL) {
        return 0;
    }

    elts = parents->elts;
    for (i = 0; i < parents->nelts; i++) {
        if (php_cedar_str_eq(&elts[i].type, target_type)
            && php_cedar_str_eq(&elts[i].id, target_id))
        {
            return 1;
        }
    }

    return 0;
}


/*
 * Resolve the parents array for an entity value by its origin slot.
 * The slot is stamped on the value when PHP_CEDAR_NODE_VAR evaluation
 * produces the principal / action / resource entity. Returns NULL for
 * PHP_CEDAR_ENTITY_SLOT_NONE (literals, attribute lookups, set
 * elements) so `in` evaluation falls back to reflexive comparison only,
 * which matches Cedar semantics: derived entities have no ancestor
 * information attached.
 *
 * The previous (type, id) lookup collapsed on collisions and silently
 * returned principal_parents whenever principal / action / resource
 * shared the same identity, flipping `in` decisions.
 */
php_cedar_array_t *
php_cedar_eval_ctx_lookup_parents(php_cedar_eval_ctx_t *ctx,
    php_cedar_uint_t slot)
{
    if (ctx == NULL) {
        return NULL;
    }

    switch (slot) {
    case PHP_CEDAR_ENTITY_SLOT_PRINCIPAL:
        return ctx->principal_parents;
    case PHP_CEDAR_ENTITY_SLOT_ACTION:
        return ctx->action_parents;
    case PHP_CEDAR_ENTITY_SLOT_RESOURCE:
        return ctx->resource_parents;
    default:
        return NULL;
    }
}


static php_cedar_int_t
php_cedar_scope_matches(php_cedar_scope_t *scope,
    const php_cedar_str_t *entity_type, const php_cedar_str_t *entity_id,
    php_cedar_array_t *parents)
{
    php_cedar_node_t *target, **elts;
    php_cedar_uint_t i;

    if (scope->constraint == PHP_CEDAR_SCOPE_NONE) {
        return 1;
    }

    if (scope->constraint == PHP_CEDAR_SCOPE_IS
        || scope->constraint == PHP_CEDAR_SCOPE_IS_IN)
    {
        if (!php_cedar_str_eq(entity_type, &scope->entity_type)) {
            return 0;
        }

        if (scope->constraint == PHP_CEDAR_SCOPE_IS) {
            return 1;
        }

        /* IS_IN: reuse hierarchical match on the entity_ref target */
        target = scope->target;

        if (target == NULL
            || target->type != PHP_CEDAR_NODE_ENTITY_REF)
        {
            return 0;
        }

        return php_cedar_entity_in_target(entity_type, entity_id, parents,
                                          &target->u.entity_ref.entity_type,
                                          &target->u.entity_ref.entity_id);
    }

    target = scope->target;
    if (target == NULL) {
        return 0;
    }

    if (scope->constraint == PHP_CEDAR_SCOPE_EQ) {
        if (target->type != PHP_CEDAR_NODE_ENTITY_REF) {
            return 0;
        }
        return (php_cedar_str_eq(entity_type,
                                 &target->u.entity_ref.entity_type)
                && php_cedar_str_eq(entity_id,
                                    &target->u.entity_ref.entity_id));
    }

    /* SCOPE_IN */
    if (target->type == PHP_CEDAR_NODE_ENTITY_REF) {
        return php_cedar_entity_in_target(entity_type, entity_id, parents,
                                          &target->u.entity_ref.entity_type,
                                          &target->u.entity_ref.entity_id);
    }

    /* set target: entity in [Group::"a", Group::"b"] */
    if (target->type == PHP_CEDAR_NODE_SET) {
        if (target->u.set_elts == NULL) {
            return 0;
        }

        elts = target->u.set_elts->elts;

        for (i = 0; i < target->u.set_elts->nelts; i++) {
            if (elts[i]->type == PHP_CEDAR_NODE_ENTITY_REF
                && php_cedar_entity_in_target(entity_type, entity_id,
                                              parents,
                                              &elts[i]->u.entity_ref.entity_type,
                                              &elts[i]->u.entity_ref.entity_id))
            {
                return 1;
            }
        }

        return 0;
    }

    return 0;
}


/* --- condition matching --- */

static php_cedar_int_t
php_cedar_condition_matches(php_cedar_condition_t *cond,
    php_cedar_eval_ctx_t *ctx, php_cedar_pool_t *pool, php_cedar_log_t *log)
{
    php_cedar_value_t val;

    val = php_cedar_expr_eval(cond->expr, ctx, pool, log);

    if (val.type == PHP_CEDAR_RVAL_ERROR) {
        return 0;
    }

    if (val.type != PHP_CEDAR_RVAL_BOOL) {
        return 0;
    }

    if (cond->is_unless) {
        return !val.v.bool_val;
    }

    return val.v.bool_val;
}


/* --- evaluation context API --- */

/*
 * Reject duplicate attribute names within a single attrs array.
 * Entity attributes (principal / action / resource / context) and
 * record fields share the same flat (name, value) representation, so
 * both contracts use the same uniqueness check: a second insertion
 * with a name that already exists returns PHP_CEDAR_ERROR before any push.
 *
 * Cedar records are semantically unordered key -> value maps with
 * unique keys; the parser already rejects duplicates in record
 * literals, and equality / hashing assume that invariant. This
 * matches the parser-side contract for the injection API too.
 *
 * Returns 1 if a matching name is already present (caller should
 * reject), 0 otherwise. Tolerates a NULL attrs (treated as empty).
 */
static php_cedar_int_t
php_cedar_attrs_has_name(php_cedar_array_t *attrs, const php_cedar_str_t *name)
{
    php_cedar_attr_t *elts;
    php_cedar_uint_t i;

    if (attrs == NULL || name == NULL) {
        return 0;
    }

    elts = attrs->elts;
    for (i = 0; i < attrs->nelts; i++) {
        if (php_cedar_str_eq(&elts[i].name, name)) {
            return 1;
        }
    }

    return 0;
}


static php_cedar_int_t
php_cedar_eval_ctx_add_str_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    php_cedar_attr_t *attr;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_STRING;
    attr->value.v.str_val = *value;

    return PHP_CEDAR_OK;
}


static php_cedar_int_t
php_cedar_eval_ctx_add_long_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, int64_t value)
{
    php_cedar_attr_t *attr;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_LONG;
    attr->value.v.long_val = value;

    return PHP_CEDAR_OK;
}


static php_cedar_int_t
php_cedar_eval_ctx_add_bool_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, php_cedar_flag_t value)
{
    php_cedar_attr_t *attr;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_BOOL;
    attr->value.v.bool_val = value;

    return PHP_CEDAR_OK;
}


/*
 * IP attributes are eagerly parsed at injection time so readers can
 * see the binary representation directly. Invalid IP strings are
 * rejected here with PHP_CEDAR_ERROR instead of surfacing as a silent
 * evaluation error on first access.
 */
static php_cedar_int_t
php_cedar_eval_ctx_add_ip_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    php_cedar_attr_t *attr;
    php_cedar_value_t ip_val;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    ip_val = php_cedar_make_ip(value);
    if (ip_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value = ip_val;

    return PHP_CEDAR_OK;
}


/*
 * Decimal attributes are eagerly parsed at injection time, mirroring
 * the IP path: callers see malformed input rejected with PHP_CEDAR_ERROR up
 * front instead of as a silent evaluation error later.
 */
static php_cedar_int_t
php_cedar_eval_ctx_add_decimal_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    php_cedar_attr_t *attr;
    php_cedar_value_t dec_val;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    dec_val = php_cedar_make_decimal(value);
    if (dec_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value = dec_val;

    return PHP_CEDAR_OK;
}


/*
 * Datetime attributes are eagerly parsed at injection time, mirroring
 * the IP / decimal paths: malformed ISO 8601 input is rejected with
 * PHP_CEDAR_ERROR up front rather than surfacing as a silent evaluation error
 * later.
 */
static php_cedar_int_t
php_cedar_eval_ctx_add_datetime_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    php_cedar_attr_t *attr;
    php_cedar_value_t dt_val;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    dt_val = php_cedar_make_datetime(value);
    if (dt_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value = dt_val;

    return PHP_CEDAR_OK;
}


/*
 * Duration attributes are eagerly parsed at injection time, mirroring
 * the datetime path: malformed duration strings are rejected with
 * PHP_CEDAR_ERROR up front.
 */
static php_cedar_int_t
php_cedar_eval_ctx_add_duration_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    php_cedar_attr_t *attr;
    php_cedar_value_t dur_val;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    dur_val = php_cedar_make_duration(value);
    if (dur_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    attr->name = *name;
    attr->value = dur_val;

    return PHP_CEDAR_OK;
}


/*
 * Record handle.
 *
 * - attrs: array of php_cedar_attr_t (shared with the attribute value
 *   stored in the owning entity / parent record).
 * - pool: owns all record / attribute allocations; freed with the
 *   evaluation context.
 * - depth: current nesting depth (1 = direct child of an entity /
 *   context, increments by 1 for each php_cedar_record_add_record).
 */
struct php_cedar_record_s {
    php_cedar_array_t *attrs;
    php_cedar_pool_t  *pool;
    php_cedar_uint_t   depth;
};


static php_cedar_record_t *
php_cedar_record_create(php_cedar_pool_t *pool, php_cedar_uint_t depth)
{
    php_cedar_record_t *rec;

    rec = php_cedar_pcalloc(pool, sizeof(php_cedar_record_t));
    if (rec == NULL) {
        return NULL;
    }

    rec->attrs = php_cedar_array_create(pool, 4, sizeof(php_cedar_attr_t));
    if (rec->attrs == NULL) {
        return NULL;
    }

    rec->pool = pool;
    rec->depth = depth;

    return rec;
}


/*
 * Reserve a new record-valued attribute on the given attr array and
 * return a populated handle. Shared helper for the four
 * php_cedar_eval_ctx_add_*_attr_record entry points.
 */
static php_cedar_record_t *
php_cedar_eval_ctx_add_record_attr(php_cedar_array_t *attrs, php_cedar_pool_t *pool,
    const php_cedar_str_t *name)
{
    php_cedar_attr_t *attr;
    php_cedar_record_t *rec;

    if (php_cedar_attrs_has_name(attrs, name)) {
        return NULL;
    }

    rec = php_cedar_record_create(pool, 1);
    if (rec == NULL) {
        return NULL;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return NULL;
    }

    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_RECORD;
    attr->value.v.record_attrs = rec->attrs;

    return rec;
}


php_cedar_eval_ctx_t *
php_cedar_eval_ctx_create(php_cedar_pool_t *pool)
{
    php_cedar_eval_ctx_t *ctx;

    if (pool == NULL) {
        return NULL;
    }

    ctx = php_cedar_pcalloc(pool, sizeof(php_cedar_eval_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->pool = pool;

    ctx->principal_attrs = php_cedar_array_create(pool, 4,
                                            sizeof(php_cedar_attr_t));
    ctx->action_attrs = php_cedar_array_create(pool, 4,
                                         sizeof(php_cedar_attr_t));
    ctx->resource_attrs = php_cedar_array_create(pool, 4,
                                           sizeof(php_cedar_attr_t));
    ctx->context_attrs = php_cedar_array_create(pool, 4,
                                          sizeof(php_cedar_attr_t));

    ctx->principal_parents = php_cedar_array_create(pool, 2,
                                              sizeof(php_cedar_entity_ref_t));
    ctx->action_parents = php_cedar_array_create(pool, 2,
                                           sizeof(php_cedar_entity_ref_t));
    ctx->resource_parents = php_cedar_array_create(pool, 2,
                                             sizeof(php_cedar_entity_ref_t));

    if (ctx->principal_attrs == NULL
        || ctx->action_attrs == NULL
        || ctx->resource_attrs == NULL
        || ctx->context_attrs == NULL
        || ctx->principal_parents == NULL
        || ctx->action_parents == NULL
        || ctx->resource_parents == NULL)
    {
        return NULL;
    }

    return ctx;
}


void
php_cedar_eval_ctx_set_principal(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    ctx->principal_type = *type;
    ctx->principal_id = *id;
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_str_attr(ctx->principal_attrs,
                                           name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_long(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, int64_t value)
{
    return php_cedar_eval_ctx_add_long_attr(ctx->principal_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_bool(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, php_cedar_flag_t value)
{
    return php_cedar_eval_ctx_add_bool_attr(ctx->principal_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_ip(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_ip_attr(ctx->principal_attrs,
                                          name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_decimal(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_decimal_attr(ctx->principal_attrs,
                                               name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_datetime(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_datetime_attr(ctx->principal_attrs,
                                                name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_duration(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_duration_attr(ctx->principal_attrs,
                                                name, value);
}


void
php_cedar_eval_ctx_set_action(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    ctx->action_type = *type;
    ctx->action_id = *id;
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_str_attr(ctx->action_attrs,
                                           name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_long(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, int64_t value)
{
    return php_cedar_eval_ctx_add_long_attr(ctx->action_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_bool(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, php_cedar_flag_t value)
{
    return php_cedar_eval_ctx_add_bool_attr(ctx->action_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_ip(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_ip_attr(ctx->action_attrs,
                                          name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_decimal(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_decimal_attr(ctx->action_attrs,
                                               name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_datetime(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_datetime_attr(ctx->action_attrs,
                                                name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_duration(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_duration_attr(ctx->action_attrs,
                                                name, value);
}


void
php_cedar_eval_ctx_set_resource(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    ctx->resource_type = *type;
    ctx->resource_id = *id;
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_str_attr(ctx->resource_attrs,
                                           name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_long(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, int64_t value)
{
    return php_cedar_eval_ctx_add_long_attr(ctx->resource_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_bool(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, php_cedar_flag_t value)
{
    return php_cedar_eval_ctx_add_bool_attr(ctx->resource_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_ip(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_ip_attr(ctx->resource_attrs,
                                          name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_decimal(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_decimal_attr(ctx->resource_attrs,
                                               name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_datetime(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_datetime_attr(ctx->resource_attrs,
                                                name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_duration(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_duration_attr(ctx->resource_attrs,
                                                name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_str_attr(ctx->context_attrs,
                                           name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_long(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, int64_t value)
{
    return php_cedar_eval_ctx_add_long_attr(ctx->context_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_bool(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, php_cedar_flag_t value)
{
    return php_cedar_eval_ctx_add_bool_attr(ctx->context_attrs,
                                            name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_ip(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_ip_attr(ctx->context_attrs,
                                          name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_decimal(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_decimal_attr(ctx->context_attrs,
                                               name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_datetime(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_datetime_attr(ctx->context_attrs,
                                                name, value);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_duration(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    return php_cedar_eval_ctx_add_duration_attr(ctx->context_attrs,
                                                name, value);
}


php_cedar_record_t *
php_cedar_eval_ctx_add_principal_attr_record(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    return php_cedar_eval_ctx_add_record_attr(ctx->principal_attrs,
                                              ctx->pool, name);
}


php_cedar_record_t *
php_cedar_eval_ctx_add_action_attr_record(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    return php_cedar_eval_ctx_add_record_attr(ctx->action_attrs,
                                              ctx->pool, name);
}


php_cedar_record_t *
php_cedar_eval_ctx_add_resource_attr_record(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    return php_cedar_eval_ctx_add_record_attr(ctx->resource_attrs,
                                              ctx->pool, name);
}


php_cedar_record_t *
php_cedar_eval_ctx_add_context_attr_record(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    return php_cedar_eval_ctx_add_record_attr(ctx->context_attrs,
                                              ctx->pool, name);
}


php_cedar_int_t
php_cedar_record_add_str(php_cedar_record_t *rec, const php_cedar_str_t *name,
    const php_cedar_str_t *value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_str_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_long(php_cedar_record_t *rec, const php_cedar_str_t *name,
    int64_t value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_long_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_bool(php_cedar_record_t *rec, const php_cedar_str_t *name,
    php_cedar_flag_t value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_bool_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_ip(php_cedar_record_t *rec, const php_cedar_str_t *name,
    const php_cedar_str_t *value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_ip_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_decimal(php_cedar_record_t *rec,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_decimal_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_datetime(php_cedar_record_t *rec,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_datetime_attr(rec->attrs, name, value);
}


php_cedar_int_t
php_cedar_record_add_duration(php_cedar_record_t *rec,
    const php_cedar_str_t *name, const php_cedar_str_t *value)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_duration_attr(rec->attrs, name, value);
}


php_cedar_record_t *
php_cedar_record_add_record(php_cedar_record_t *rec, const php_cedar_str_t *name)
{
    php_cedar_attr_t *attr;
    php_cedar_record_t *child;

    if (rec == NULL) {
        return NULL;
    }

    if (php_cedar_attrs_has_name(rec->attrs, name)) {
        return NULL;
    }

    if (rec->depth >= PHP_CEDAR_MAX_RECORD_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, rec->pool->log, 0,
                      "php_cedar_record_add_record: "
                      "record nesting exceeds max depth (%d)",
                      PHP_CEDAR_MAX_RECORD_DEPTH);
        return NULL;
    }

    child = php_cedar_record_create(rec->pool, rec->depth + 1);
    if (child == NULL) {
        return NULL;
    }

    attr = php_cedar_array_push(rec->attrs);
    if (attr == NULL) {
        return NULL;
    }

    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_RECORD;
    attr->value.v.record_attrs = child->attrs;

    return child;
}


/* --- set values --- */

/*
 * Set handle.
 *
 * - elts: array of php_cedar_value_t shared with the attribute value
 *   stored in the owning entity / record / set; element pushes are
 *   visible through both views.
 * - pool: owns all set / element allocations; freed with the
 *   evaluation context.
 * - depth: nesting depth for set-in-set (1 = direct child of an
 *   entity / context / record / set).
 */
struct php_cedar_set_s {
    php_cedar_array_t *elts;
    php_cedar_pool_t  *pool;
    php_cedar_uint_t   depth;
};


static php_cedar_set_t *
php_cedar_set_create(php_cedar_pool_t *pool, php_cedar_uint_t depth)
{
    php_cedar_set_t *set;

    set = php_cedar_pcalloc(pool, sizeof(php_cedar_set_t));
    if (set == NULL) {
        return NULL;
    }

    set->elts = php_cedar_array_create(pool, 4, sizeof(php_cedar_value_t));
    if (set->elts == NULL) {
        return NULL;
    }

    set->pool = pool;
    set->depth = depth;

    return set;
}


/*
 * Reserve a new set-valued attribute on the given attr array and
 * return a populated handle. Shared helper for the four
 * php_cedar_eval_ctx_add_*_attr_set entry points (depth = 1) and for
 * php_cedar_record_add_set, which passes its own depth + 1 so a mixed
 * record / set graph respects one PHP_CEDAR_MAX_SET_DEPTH ceiling.
 */
static php_cedar_set_t *
php_cedar_eval_ctx_add_set_attr(php_cedar_array_t *attrs, php_cedar_pool_t *pool,
    const php_cedar_str_t *name, php_cedar_uint_t depth)
{
    php_cedar_attr_t *attr;
    php_cedar_set_t *set;

    if (attrs == NULL || pool == NULL || name == NULL) {
        return NULL;
    }

    if (php_cedar_attrs_has_name(attrs, name)) {
        return NULL;
    }

    if (depth > PHP_CEDAR_MAX_SET_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, pool->log, 0,
                      "php_cedar_eval_ctx_add_set_attr: "
                      "set nesting exceeds max depth (%d)",
                      PHP_CEDAR_MAX_SET_DEPTH);
        return NULL;
    }

    set = php_cedar_set_create(pool, depth);
    if (set == NULL) {
        return NULL;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return NULL;
    }

    php_cedar_memzero(attr, sizeof(php_cedar_attr_t));
    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_SET;
    attr->value.v.set_elts = set->elts;

    return set;
}


/*
 * Append an entity-valued attribute to the given attr array.
 * Shared helper for the four php_cedar_eval_ctx_add_*_attr_entity
 * entry points and for php_cedar_record_add_entity().
 */
static php_cedar_int_t
php_cedar_eval_ctx_add_entity_attr(php_cedar_array_t *attrs,
    const php_cedar_str_t *name, const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    php_cedar_attr_t *attr;

    if (attrs == NULL || name == NULL || type == NULL || id == NULL) {
        return PHP_CEDAR_ERROR;
    }

    if (php_cedar_attrs_has_name(attrs, name)) {
        return PHP_CEDAR_ERROR;
    }

    attr = php_cedar_array_push(attrs);
    if (attr == NULL) {
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memzero(attr, sizeof(php_cedar_attr_t));
    attr->name = *name;
    attr->value.type = PHP_CEDAR_RVAL_ENTITY;
    attr->value.v.entity.type = *type;
    attr->value.v.entity.id = *id;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_str(php_cedar_set_t *set, const php_cedar_str_t *value)
{
    php_cedar_value_t *v;

    if (set == NULL || value == NULL) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_STRING;
    v->v.str_val = *value;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_long(php_cedar_set_t *set, int64_t value)
{
    php_cedar_value_t *v;

    if (set == NULL) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_LONG;
    v->v.long_val = value;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_bool(php_cedar_set_t *set, php_cedar_flag_t value)
{
    php_cedar_value_t *v;

    if (set == NULL) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_BOOL;
    v->v.bool_val = value;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_ip(php_cedar_set_t *set, const php_cedar_str_t *value)
{
    php_cedar_value_t *v, ip_val;

    if (set == NULL || value == NULL) {
        return PHP_CEDAR_ERROR;
    }

    ip_val = php_cedar_make_ip(value);
    if (ip_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    *v = ip_val;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_decimal(php_cedar_set_t *set, const php_cedar_str_t *value)
{
    php_cedar_value_t *v, dec_val;

    if (set == NULL || value == NULL) {
        return PHP_CEDAR_ERROR;
    }

    dec_val = php_cedar_make_decimal(value);
    if (dec_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    *v = dec_val;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_datetime(php_cedar_set_t *set, const php_cedar_str_t *value)
{
    php_cedar_value_t *v, dt_val;

    if (set == NULL || value == NULL) {
        return PHP_CEDAR_ERROR;
    }

    dt_val = php_cedar_make_datetime(value);
    if (dt_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    *v = dt_val;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_duration(php_cedar_set_t *set, const php_cedar_str_t *value)
{
    php_cedar_value_t *v, dur_val;

    if (set == NULL || value == NULL) {
        return PHP_CEDAR_ERROR;
    }

    dur_val = php_cedar_make_duration(value);
    if (dur_val.type == PHP_CEDAR_RVAL_ERROR) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    *v = dur_val;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_set_add_entity(php_cedar_set_t *set,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    php_cedar_value_t *v;

    if (set == NULL || type == NULL || id == NULL) {
        return PHP_CEDAR_ERROR;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return PHP_CEDAR_ERROR;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_ENTITY;
    v->v.entity.type = *type;
    v->v.entity.id = *id;

    return PHP_CEDAR_OK;
}


php_cedar_set_t *
php_cedar_set_add_set(php_cedar_set_t *set)
{
    php_cedar_value_t *v;
    php_cedar_set_t *child;

    if (set == NULL) {
        return NULL;
    }

    if (set->depth >= PHP_CEDAR_MAX_SET_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, set->pool->log, 0,
                      "php_cedar_set_add_set: "
                      "set nesting exceeds max depth (%d)",
                      PHP_CEDAR_MAX_SET_DEPTH);
        return NULL;
    }

    child = php_cedar_set_create(set->pool, set->depth + 1);
    if (child == NULL) {
        return NULL;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return NULL;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_SET;
    v->v.set_elts = child->elts;

    return child;
}


php_cedar_record_t *
php_cedar_set_add_record(php_cedar_set_t *set)
{
    php_cedar_value_t *v;
    php_cedar_record_t *child;

    if (set == NULL) {
        return NULL;
    }

    /*
     * Inherit the set's depth so a mixed graph (record -> set ->
     * record -> ...) shares one ceiling. Without this, kind switches
     * reset the counter to 1 and `==` could descend deeper than
     * PHP_CEDAR_MAX_RECORD_DEPTH on alternating chains.
     */
    if (set->depth >= PHP_CEDAR_MAX_RECORD_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, set->pool->log, 0,
                      "php_cedar_set_add_record: "
                      "record nesting exceeds max depth (%d)",
                      PHP_CEDAR_MAX_RECORD_DEPTH);
        return NULL;
    }

    child = php_cedar_record_create(set->pool, set->depth + 1);
    if (child == NULL) {
        return NULL;
    }

    v = php_cedar_array_push(set->elts);
    if (v == NULL) {
        return NULL;
    }

    php_cedar_memzero(v, sizeof(php_cedar_value_t));
    v->type = PHP_CEDAR_RVAL_RECORD;
    v->v.record_attrs = child->attrs;

    return child;
}


php_cedar_set_t *
php_cedar_eval_ctx_add_principal_attr_set(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    if (ctx == NULL) {
        return NULL;
    }
    return php_cedar_eval_ctx_add_set_attr(ctx->principal_attrs,
                                           ctx->pool, name, 1);
}


php_cedar_set_t *
php_cedar_eval_ctx_add_action_attr_set(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    if (ctx == NULL) {
        return NULL;
    }
    return php_cedar_eval_ctx_add_set_attr(ctx->action_attrs,
                                           ctx->pool, name, 1);
}


php_cedar_set_t *
php_cedar_eval_ctx_add_resource_attr_set(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    if (ctx == NULL) {
        return NULL;
    }
    return php_cedar_eval_ctx_add_set_attr(ctx->resource_attrs,
                                           ctx->pool, name, 1);
}


php_cedar_set_t *
php_cedar_eval_ctx_add_context_attr_set(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name)
{
    if (ctx == NULL) {
        return NULL;
    }
    return php_cedar_eval_ctx_add_set_attr(ctx->context_attrs,
                                           ctx->pool, name, 1);
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_attr_entity(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_entity_attr(ctx->principal_attrs,
                                              name, type, id);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_attr_entity(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_entity_attr(ctx->action_attrs,
                                              name, type, id);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_attr_entity(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_entity_attr(ctx->resource_attrs,
                                              name, type, id);
}


php_cedar_int_t
php_cedar_eval_ctx_add_context_attr_entity(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *name, const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_entity_attr(ctx->context_attrs,
                                              name, type, id);
}


php_cedar_int_t
php_cedar_record_add_entity(php_cedar_record_t *rec, const php_cedar_str_t *name,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (rec == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_entity_attr(rec->attrs, name, type, id);
}


php_cedar_set_t *
php_cedar_record_add_set(php_cedar_record_t *rec, const php_cedar_str_t *name)
{
    if (rec == NULL) {
        return NULL;
    }
    if (rec->depth >= PHP_CEDAR_MAX_SET_DEPTH) {
        php_cedar_log_error(PHP_CEDAR_LOG_ERR, rec->pool->log, 0,
                      "php_cedar_record_add_set: "
                      "set nesting exceeds max depth (%d)",
                      PHP_CEDAR_MAX_SET_DEPTH);
        return NULL;
    }
    return php_cedar_eval_ctx_add_set_attr(rec->attrs, rec->pool, name,
                                           rec->depth + 1);
}


/* --- entity hierarchy --- */

static php_cedar_int_t
php_cedar_eval_ctx_add_parent(php_cedar_array_t *parents,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    php_cedar_entity_ref_t *ref;

    if (parents == NULL || type == NULL || id == NULL) {
        return PHP_CEDAR_ERROR;
    }

    ref = php_cedar_array_push(parents);
    if (ref == NULL) {
        return PHP_CEDAR_ERROR;
    }

    ref->type = *type;
    ref->id = *id;

    return PHP_CEDAR_OK;
}


php_cedar_int_t
php_cedar_eval_ctx_add_principal_parent(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_parent(ctx->principal_parents, type, id);
}


php_cedar_int_t
php_cedar_eval_ctx_add_action_parent(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_parent(ctx->action_parents, type, id);
}


php_cedar_int_t
php_cedar_eval_ctx_add_resource_parent(php_cedar_eval_ctx_t *ctx,
    const php_cedar_str_t *type, const php_cedar_str_t *id)
{
    if (ctx == NULL) {
        return PHP_CEDAR_ERROR;
    }
    return php_cedar_eval_ctx_add_parent(ctx->resource_parents, type, id);
}


/* --- main evaluation --- */

php_cedar_str_t *
php_cedar_policy_get_annotation(php_cedar_policy_t *policy, php_cedar_str_t *key)
{
    php_cedar_annotation_t *elts;
    php_cedar_uint_t i;

    if (policy == NULL || key == NULL || policy->annotations == NULL) {
        return NULL;
    }

    elts = policy->annotations->elts;
    for (i = 0; i < policy->annotations->nelts; i++) {
        if (php_cedar_str_eq(&elts[i].key, key)) {
            return &elts[i].value;
        }
    }

    return NULL;
}


/*
 * Test all scope and condition clauses of `policy` against `ctx`.
 * Returns 1 when every clause matches (the policy contributes to the
 * decision), 0 otherwise. Shared by the detail-collecting evaluator
 * so the forbid and permit passes apply identical match semantics.
 */
static php_cedar_int_t
php_cedar_policy_matches(php_cedar_policy_t *policy,
    php_cedar_eval_ctx_t *ctx, php_cedar_log_t *log)
{
    php_cedar_condition_t *conds, *c;
    php_cedar_uint_t j;

    if (!php_cedar_scope_matches(&policy->principal,
                                 &ctx->principal_type, &ctx->principal_id,
                                 ctx->principal_parents))
    {
        return 0;
    }

    if (!php_cedar_scope_matches(&policy->action,
                                 &ctx->action_type, &ctx->action_id,
                                 ctx->action_parents))
    {
        return 0;
    }

    if (!php_cedar_scope_matches(&policy->resource,
                                 &ctx->resource_type, &ctx->resource_id,
                                 ctx->resource_parents))
    {
        return 0;
    }

    if (policy->conditions != NULL && policy->conditions->nelts > 0) {
        conds = policy->conditions->elts;

        for (j = 0; j < policy->conditions->nelts; j++) {
            c = &conds[j];

            if (!php_cedar_condition_matches(c, ctx, ctx->pool, log)) {
                return 0;
            }
        }
    }

    return 1;
}


/*
 * Record a matching policy into `out->policies`, growing the buffer
 * geometrically. Returns PHP_CEDAR_OK on success, PHP_CEDAR_ERROR if allocation
 * fails. A NULL `out` is treated as success (detail is opt-in).
 */
static php_cedar_int_t
php_cedar_detail_push(php_cedar_decision_detail_t *out,
    php_cedar_policy_t *policy, php_cedar_pool_t *pool,
    php_cedar_uint_t *cap)
{
    php_cedar_policy_t **buf;
    php_cedar_uint_t new_cap;

    if (out == NULL) {
        return PHP_CEDAR_OK;
    }

    if (out->npolicies >= *cap) {
        new_cap = (*cap == 0) ? 4 : (*cap * 2);
        buf = php_cedar_palloc(pool, new_cap * sizeof(php_cedar_policy_t *));
        if (buf == NULL) {
            return PHP_CEDAR_ERROR;
        }

        if (out->npolicies > 0) {
            php_cedar_memcpy(buf, out->policies,
                       out->npolicies * sizeof(php_cedar_policy_t *));
        }

        out->policies = buf;
        *cap = new_cap;
    }

    out->policies[out->npolicies++] = policy;
    return PHP_CEDAR_OK;
}


php_cedar_decision_t
php_cedar_eval_detail(php_cedar_policy_set_t *policy_set,
    php_cedar_eval_ctx_t *ctx, php_cedar_log_t *log,
    php_cedar_decision_detail_t *out)
{
    php_cedar_policy_t *policies, *p;
    php_cedar_uint_t i;
    php_cedar_uint_t has_forbid, has_permit, cap;

    if (out != NULL) {
        out->policies = NULL;
        out->npolicies = 0;
        out->errored = NULL;
        out->nerrored = 0;
    }

    if (policy_set == NULL || policy_set->policies == NULL
        || ctx == NULL)
    {
        return PHP_CEDAR_DECISION_DENY;
    }

    policies = policy_set->policies->elts;

    /*
     * Forbid pass: evaluate every policy so all matching forbids are
     * captured into `out`. Cedar's `forbid` priority means a single
     * forbid is enough to deny, but the diagnostic API contract is to
     * return every contributing forbid, not just the first one.
     */
    has_forbid = 0;
    cap = 0;

    for (i = 0; i < policy_set->policies->nelts; i++) {
        p = &policies[i];

        if (!p->is_forbid) {
            continue;
        }

        if (!php_cedar_policy_matches(p, ctx, log)) {
            continue;
        }

        has_forbid = 1;

        if (out == NULL) {
            /* fast path: no need to enumerate the rest */
            return PHP_CEDAR_DECISION_DENY;
        }

        if (php_cedar_detail_push(out, p, ctx->pool, &cap) != PHP_CEDAR_OK) {
            /* allocation failure still produces a correct decision */
            return PHP_CEDAR_DECISION_DENY;
        }
    }

    if (has_forbid) {
        return PHP_CEDAR_DECISION_DENY;
    }

    /* Permit pass: list every matching permit when no forbid fired. */
    has_permit = 0;
    cap = 0;

    for (i = 0; i < policy_set->policies->nelts; i++) {
        p = &policies[i];

        if (p->is_forbid) {
            continue;
        }

        if (!php_cedar_policy_matches(p, ctx, log)) {
            continue;
        }

        has_permit = 1;

        if (out == NULL) {
            /* fast path: caller only wants the decision */
            return PHP_CEDAR_DECISION_ALLOW;
        }

        if (php_cedar_detail_push(out, p, ctx->pool, &cap) != PHP_CEDAR_OK) {
            return PHP_CEDAR_DECISION_ALLOW;
        }
    }

    if (has_permit) {
        return PHP_CEDAR_DECISION_ALLOW;
    }

    return PHP_CEDAR_DECISION_DENY;
}


php_cedar_decision_t
php_cedar_eval(php_cedar_policy_set_t *policy_set,
    php_cedar_eval_ctx_t *ctx, php_cedar_log_t *log)
{
    return php_cedar_eval_detail(policy_set, ctx, log, NULL);
}
