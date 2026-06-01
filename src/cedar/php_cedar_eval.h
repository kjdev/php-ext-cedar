/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_eval.h - Cedar policy set evaluator
 *
 * Forbid-priority evaluation and context manipulation public API.
 */

#ifndef PHP_CEDAR_EVAL_H
#define PHP_CEDAR_EVAL_H

#include "php_cedar_types.h"
#include "php_cedar_expr.h"


/*
 * Opaque handle used to populate a record-valued attribute one field
 * at a time. Created by php_cedar_eval_ctx_add_*_attr_record() for a
 * top-level record, or by php_cedar_record_add_record() for a nested
 * record. The implementation lives in php_cedar_eval.c.
 */
typedef struct php_cedar_record_s php_cedar_record_t;

/*
 * Opaque handle used to populate a set-valued attribute element by
 * element. Created by php_cedar_eval_ctx_add_*_attr_set() for a
 * top-level set, by php_cedar_record_add_set() inside a record, or by
 * php_cedar_set_add_set() inside another set.
 */
typedef struct php_cedar_set_s php_cedar_set_t;


php_cedar_decision_t php_cedar_eval(php_cedar_policy_set_t *policy_set,
    php_cedar_eval_ctx_t *ctx, php_cedar_log_t *log);

/*
 * Variant of php_cedar_eval() that records the policies responsible
 * for the decision into `out`. On DENY because at least one `forbid`
 * matched, `out->policies` lists every matching `forbid`; on ALLOW it
 * lists every matching `permit`; on default DENY (no policy matched)
 * `out->policies` is NULL and `out->npolicies` is 0. The pointer
 * array is allocated from `ctx->pool`; each entry points into the
 * input policy set, so the caller must not dereference entries past
 * the shorter of `ctx->pool` and the policy set's lifetimes.
 *
 * Detail collection is best-effort: if allocation fails while growing
 * the pointer array, the returned decision remains correct but
 * `out->policies` may be truncated (it lists a prefix of the matching
 * policies rather than every one).
 *
 * `out` may be NULL; php_cedar_eval() is a thin wrapper that passes
 * NULL and is preserved for callers that only need the decision.
 */
php_cedar_decision_t php_cedar_eval_detail(
    php_cedar_policy_set_t *policy_set,
    php_cedar_eval_ctx_t *ctx, php_cedar_log_t *log,
    php_cedar_decision_detail_t *out);

/*
 * Lookup an annotation value by key on a parsed policy. Returns the
 * annotation's value (which may be an empty string for valueless
 * annotations like `@deprecated`) or NULL when the key is absent.
 * The returned php_cedar_str_t is owned by the policy set; the caller must
 * not modify or free it.
 */
php_cedar_str_t *php_cedar_policy_get_annotation(php_cedar_policy_t *policy,
    php_cedar_str_t *key);

php_cedar_eval_ctx_t *php_cedar_eval_ctx_create(php_cedar_pool_t *pool);

void php_cedar_eval_ctx_set_principal(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_principal_attr(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_principal_attr_long(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, int64_t value);
php_cedar_int_t php_cedar_eval_ctx_add_principal_attr_bool(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_flag_t value);
php_cedar_int_t php_cedar_eval_ctx_add_principal_attr_ip(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_principal_attr_decimal(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);

void php_cedar_eval_ctx_set_action(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr_long(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, int64_t value);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr_bool(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_flag_t value);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr_ip(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr_decimal(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);

void php_cedar_eval_ctx_set_resource(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr_long(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, int64_t value);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr_bool(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_flag_t value);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr_ip(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr_decimal(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);

php_cedar_int_t php_cedar_eval_ctx_add_context_attr(php_cedar_eval_ctx_t *ctx,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_context_attr_long(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, int64_t value);
php_cedar_int_t php_cedar_eval_ctx_add_context_attr_bool(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_flag_t value);
php_cedar_int_t php_cedar_eval_ctx_add_context_attr_ip(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_eval_ctx_add_context_attr_decimal(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name, php_cedar_str_t *value);

/*
 * Record-valued attribute constructors.
 *
 * Each php_cedar_eval_ctx_add_*_attr_record() reserves a new
 * record-valued attribute on the corresponding entity / context and
 * returns a handle for populating its fields. Callers add fields via
 * php_cedar_record_add_{str,long,bool,ip,record}().
 *
 * php_cedar_record_add_record() returns NULL when the resulting record
 * would exceed PHP_CEDAR_MAX_RECORD_DEPTH. The record nesting limit is
 * aligned with the parser's member-chain limit; scalar fields added
 * directly to a record at exactly PHP_CEDAR_MAX_RECORD_DEPTH are
 * writable but require one more member step and are not reachable from
 * policy text.
 *
 * Returns NULL on allocation failure as well.
 */
php_cedar_record_t *php_cedar_eval_ctx_add_principal_attr_record(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_record_t *php_cedar_eval_ctx_add_action_attr_record(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_record_t *php_cedar_eval_ctx_add_resource_attr_record(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_record_t *php_cedar_eval_ctx_add_context_attr_record(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);

php_cedar_int_t php_cedar_record_add_str(php_cedar_record_t *rec,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_record_add_long(php_cedar_record_t *rec,
    php_cedar_str_t *name, int64_t value);
php_cedar_int_t php_cedar_record_add_bool(php_cedar_record_t *rec,
    php_cedar_str_t *name, php_cedar_flag_t value);
php_cedar_int_t php_cedar_record_add_ip(php_cedar_record_t *rec,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_int_t php_cedar_record_add_decimal(php_cedar_record_t *rec,
    php_cedar_str_t *name, php_cedar_str_t *value);
php_cedar_record_t *php_cedar_record_add_record(php_cedar_record_t *rec,
    php_cedar_str_t *name);
php_cedar_int_t php_cedar_record_add_entity(php_cedar_record_t *rec,
    php_cedar_str_t *name, php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_set_t *php_cedar_record_add_set(php_cedar_record_t *rec,
    php_cedar_str_t *name);


/*
 * Set-valued attribute constructors. Each call reserves a new
 * set-valued attribute on the corresponding entity / context and
 * returns a handle for appending elements via
 * php_cedar_set_add_{str,long,bool,ip,entity,set,record}().
 *
 * Returns NULL on allocation failure.
 */
php_cedar_set_t *php_cedar_eval_ctx_add_principal_attr_set(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_set_t *php_cedar_eval_ctx_add_action_attr_set(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_set_t *php_cedar_eval_ctx_add_resource_attr_set(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);
php_cedar_set_t *php_cedar_eval_ctx_add_context_attr_set(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name);

php_cedar_int_t php_cedar_eval_ctx_add_principal_attr_entity(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_action_attr_entity(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_resource_attr_entity(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_context_attr_entity(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *name,
    php_cedar_str_t *type, php_cedar_str_t *id);


/*
 * Set element constructors. Add one element to an existing set
 * handle. php_cedar_set_add_set() and php_cedar_set_add_record()
 * return a handle for the new nested container; the other variants
 * return PHP_CEDAR_OK / PHP_CEDAR_ERROR.
 *
 * Set handles enforce PHP_CEDAR_MAX_SET_DEPTH for set-in-set nesting
 * and PHP_CEDAR_MAX_RECORD_DEPTH for record values placed inside a
 * set; exceeding either ceiling returns NULL.
 */
php_cedar_int_t php_cedar_set_add_str(php_cedar_set_t *set, php_cedar_str_t *value);
php_cedar_int_t php_cedar_set_add_long(php_cedar_set_t *set, int64_t value);
php_cedar_int_t php_cedar_set_add_bool(php_cedar_set_t *set, php_cedar_flag_t value);
php_cedar_int_t php_cedar_set_add_ip(php_cedar_set_t *set, php_cedar_str_t *value);
php_cedar_int_t php_cedar_set_add_decimal(php_cedar_set_t *set,
    php_cedar_str_t *value);
php_cedar_int_t php_cedar_set_add_entity(php_cedar_set_t *set,
    php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_set_t *php_cedar_set_add_set(php_cedar_set_t *set);
php_cedar_record_t *php_cedar_set_add_record(php_cedar_set_t *set);


/*
 * Entity hierarchy registration.
 *
 * Each call records one ancestor of the given entity (principal,
 * action, or resource) for `in` evaluation. The caller is responsible
 * for supplying the transitive closure: if `User::"alice"` is a member
 * of `Group::"developers"`, which is a member of `Group::"staff"`,
 * register both `Group::"developers"` and `Group::"staff"` as
 * principal parents. Reflexive membership (`X in X`) is handled by the
 * evaluator and does not need to be registered.
 *
 * Returns PHP_CEDAR_OK on success, PHP_CEDAR_ERROR on allocation failure.
 */
php_cedar_int_t php_cedar_eval_ctx_add_principal_parent(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_action_parent(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *type, php_cedar_str_t *id);
php_cedar_int_t php_cedar_eval_ctx_add_resource_parent(
    php_cedar_eval_ctx_t *ctx, php_cedar_str_t *type, php_cedar_str_t *id);


/*
 * Internal helpers shared with the expression evaluator. Resolve the
 * ancestor list by the origin slot stamped on the entity value
 * (PHP_CEDAR_ENTITY_SLOT_*); returns NULL for PHP_CEDAR_ENTITY_SLOT_NONE
 * so `in` evaluation falls back to reflexive comparison only. The
 * second helper performs the reflexive + ancestor membership check used
 * by `in` operators.
 */
php_cedar_array_t *php_cedar_eval_ctx_lookup_parents(
    php_cedar_eval_ctx_t *ctx, php_cedar_uint_t slot);
php_cedar_int_t php_cedar_entity_in_target(
    php_cedar_str_t *entity_type, php_cedar_str_t *entity_id, php_cedar_array_t *parents,
    php_cedar_str_t *target_type, php_cedar_str_t *target_id);


#endif /* PHP_CEDAR_EVAL_H */
