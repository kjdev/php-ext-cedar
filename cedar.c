/*
 * php-ext-cedar — Local Cedar policy evaluator (AVP-compatible API)
 *
 * Cedar\PolicyStore          : container that holds multiple policies
 * Cedar\AuthorizationClient  : AVP-compatible evaluation client
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdatomic.h>

#include "php.h"
#include "ext/standard/info.h"
#include "ext/random/php_random_csprng.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_string.h"
#include "ext/spl/spl_exceptions.h"

#include "php_cedar.h"

#include "php_cedar_compat.h"
#include "php_cedar_parser.h"
#include "php_cedar_eval.h"
#include "php_cedar_types.h"

#include "cedar_arginfo.h"

/* ---- Class entries -------------------------------------------------- */
static zend_class_entry *cedar_ce_PolicyStore;
static zend_class_entry *cedar_ce_AuthorizationClient;
static zend_class_entry *cedar_ce_PolicyParseException;
static zend_class_entry *cedar_ce_EvaluationException;
static zend_class_entry *cedar_ce_ResourceNotFoundException;

/* ============================================================
 * Cedar\PolicyStore
 * ============================================================ */

typedef struct {
    php_cedar_pool_t *pool;
    php_cedar_log_t   log;
    zend_string      *id;
    HashTable         policies;   /* policyId (zend_string) => php_cedar_policy_set_t* */
    zend_object       std;
} cedar_policy_store_t;

static inline cedar_policy_store_t *
cedar_policy_store_from_obj(zend_object *obj)
{
    return (cedar_policy_store_t *)
        ((char *) obj - XtOffsetOf(cedar_policy_store_t, std));
}
#define Z_CEDAR_POLICY_STORE_P(zv)  cedar_policy_store_from_obj(Z_OBJ_P(zv))

static zend_object_handlers cedar_policy_store_handlers;

static zend_object *
cedar_policy_store_create(zend_class_entry *ce)
{
    cedar_policy_store_t *intern = zend_object_alloc(sizeof(*intern), ce);

    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);
    intern->std.handlers = &cedar_policy_store_handlers;

    /* Suppress evaluator-internal logs (level=0 silences every level);
     * error details are surfaced via exceptions instead. */
    intern->log.level   = 0;
    intern->log.handler = NULL;
    intern->pool = php_cedar_pool_create(&intern->log);
    intern->id   = NULL;
    zend_hash_init(&intern->policies, 0, NULL, NULL, 0);

    return &intern->std;
}

static void
cedar_policy_store_free(zend_object *obj)
{
    cedar_policy_store_t *intern = cedar_policy_store_from_obj(obj);

    if (intern->id) {
        zend_string_release(intern->id);
        intern->id = NULL;
    }
    zend_hash_destroy(&intern->policies);
    if (intern->pool) {
        php_cedar_pool_destroy(intern->pool);
        intern->pool = NULL;
    }
    zend_object_std_dtor(&intern->std);
}

/* Generate a 32-char lowercase hex id from 16 random bytes. */
static zend_string *
cedar_generate_policy_store_id(void)
{
    unsigned char raw[16];
    char           hex[33];
    int            i;
    static const char *digits = "0123456789abcdef";

    if (php_random_bytes_silent(raw, sizeof(raw)) == FAILURE) {
        /* Fallback (only when the CSPRNG fails) still fills the 16-byte
         * buffer, so the output keeps the same 32-char hex shape. The
         * counter is atomic so ids stay unique across threads under ZTS. */
        static atomic_uint_least64_t seq;
        uint64_t t = (uint64_t) time(NULL);
        uint64_t s = (uint64_t) atomic_fetch_add(&seq, 1) + 1;
        memcpy(raw, &t, sizeof(t));
        memcpy(raw + sizeof(t), &s, sizeof(s));
    }
    for (i = 0; i < 16; i++) {
        hex[i * 2]     = digits[(raw[i] >> 4) & 0xf];
        hex[i * 2 + 1] = digits[raw[i] & 0xf];
    }
    hex[32] = '\0';
    return zend_string_init(hex, 32, 0);
}

PHP_METHOD(Cedar_PolicyStore, __construct)
{
    cedar_policy_store_t *intern;
    zend_string          *id = NULL;

    ZEND_PARSE_PARAMETERS_START(0, 1)
        Z_PARAM_OPTIONAL
        Z_PARAM_STR_OR_NULL(id)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_POLICY_STORE_P(ZEND_THIS);
    if (intern->pool == NULL) {
        zend_throw_exception_ex(spl_ce_RuntimeException, 0,
            "failed to allocate PolicyStore backing pool");
        return;
    }
    if (id) {
        intern->id = zend_string_copy(id);
    } else {
        intern->id = cedar_generate_policy_store_id();
    }
}

/* Shared body for loadFile / loadString. Throws on failure. */
static void
cedar_policy_store_register_text(cedar_policy_store_t *intern,
                                 zend_string *policy_id,
                                 const char *text, size_t text_len)
{
    php_cedar_str_t          src;
    php_cedar_policy_set_t  *ps;

    if (zend_hash_exists(&intern->policies, policy_id)) {
        zend_throw_exception_ex(cedar_ce_PolicyParseException, 0,
            "policy id \"%s\" already loaded", ZSTR_VAL(policy_id));
        return;
    }
    src.data = (unsigned char *) text;
    src.len  = text_len;

    ps = php_cedar_parse(intern->pool, &intern->log, &src);
    if (ps == NULL) {
        zend_throw_exception_ex(cedar_ce_PolicyParseException, 0,
            "failed to parse cedar policy \"%s\"", ZSTR_VAL(policy_id));
        return;
    }
    zend_hash_add_ptr(&intern->policies, policy_id, ps);
}

PHP_METHOD(Cedar_PolicyStore, loadFile)
{
    cedar_policy_store_t *intern;
    zend_string          *policy_id;
    zend_string          *path;
    php_stream           *stream;
    zend_string          *contents;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(policy_id)
        Z_PARAM_PATH_STR(path)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_POLICY_STORE_P(ZEND_THIS);

    stream = php_stream_open_wrapper(ZSTR_VAL(path), "rb",
                                     0, NULL);
    if (stream == NULL) {
        zend_throw_exception_ex(cedar_ce_PolicyParseException, 0,
            "failed to open cedar policy file \"%s\"", ZSTR_VAL(path));
        return;
    }
    contents = php_stream_copy_to_mem(stream, PHP_STREAM_COPY_ALL, 0);
    php_stream_close(stream);
    if (contents == NULL) {
        zend_throw_exception_ex(cedar_ce_PolicyParseException, 0,
            "failed to read cedar policy file \"%s\"", ZSTR_VAL(path));
        return;
    }

    cedar_policy_store_register_text(intern, policy_id,
                                     ZSTR_VAL(contents), ZSTR_LEN(contents));
    zend_string_release(contents);

    if (EG(exception) == NULL) {
        RETURN_OBJ_COPY(Z_OBJ_P(ZEND_THIS));
    }
}

PHP_METHOD(Cedar_PolicyStore, loadString)
{
    cedar_policy_store_t *intern;
    zend_string          *policy_id;
    zend_string          *text;

    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STR(policy_id)
        Z_PARAM_STR(text)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_POLICY_STORE_P(ZEND_THIS);
    cedar_policy_store_register_text(intern, policy_id,
                                     ZSTR_VAL(text), ZSTR_LEN(text));
    if (EG(exception) == NULL) {
        RETURN_OBJ_COPY(Z_OBJ_P(ZEND_THIS));
    }
}

PHP_METHOD(Cedar_PolicyStore, id)
{
    cedar_policy_store_t *intern;

    ZEND_PARSE_PARAMETERS_NONE();
    intern = Z_CEDAR_POLICY_STORE_P(ZEND_THIS);
    if (intern->id) {
        RETURN_STR_COPY(intern->id);
    }
    RETURN_EMPTY_STRING();
}

PHP_METHOD(Cedar_PolicyStore, policyIds)
{
    cedar_policy_store_t *intern;
    zend_string          *key;

    ZEND_PARSE_PARAMETERS_NONE();
    intern = Z_CEDAR_POLICY_STORE_P(ZEND_THIS);
    array_init(return_value);
    ZEND_HASH_FOREACH_STR_KEY(&intern->policies, key) {
        if (key) {
            add_next_index_str(return_value, zend_string_copy(key));
        }
    } ZEND_HASH_FOREACH_END();
}

/* ============================================================
 * Cedar\AuthorizationClient
 * ============================================================ */

typedef struct {
    zval         policy_store;     /* PolicyStore object held by reference */
    zval         identity_source;  /* options['identitySource'] array or UNDEF */
    zend_object  std;
} cedar_authz_client_t;

static inline cedar_authz_client_t *
cedar_authz_client_from_obj(zend_object *obj)
{
    return (cedar_authz_client_t *)
        ((char *) obj - XtOffsetOf(cedar_authz_client_t, std));
}
#define Z_CEDAR_AUTHZ_CLIENT_P(zv)  cedar_authz_client_from_obj(Z_OBJ_P(zv))

static zend_object_handlers cedar_authz_client_handlers;

static zend_object *
cedar_authz_client_create(zend_class_entry *ce)
{
    cedar_authz_client_t *intern = zend_object_alloc(sizeof(*intern), ce);
    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);
    intern->std.handlers = &cedar_authz_client_handlers;
    ZVAL_UNDEF(&intern->policy_store);
    ZVAL_UNDEF(&intern->identity_source);
    return &intern->std;
}

static void
cedar_authz_client_free(zend_object *obj)
{
    cedar_authz_client_t *intern = cedar_authz_client_from_obj(obj);
    zval_ptr_dtor(&intern->policy_store);
    zval_ptr_dtor(&intern->identity_source);
    zend_object_std_dtor(&intern->std);
}

PHP_METHOD(Cedar_AuthorizationClient, __construct)
{
    cedar_authz_client_t *intern;
    zval                 *store;
    HashTable            *options = NULL;

    ZEND_PARSE_PARAMETERS_START(1, 2)
        Z_PARAM_OBJECT_OF_CLASS(store, cedar_ce_PolicyStore)
        Z_PARAM_OPTIONAL
        Z_PARAM_ARRAY_HT(options)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_AUTHZ_CLIENT_P(ZEND_THIS);
    ZVAL_COPY(&intern->policy_store, store);

    if (options) {
        zval *id_src = zend_hash_str_find(options,
            "identitySource", sizeof("identitySource") - 1);
        if (id_src && Z_TYPE_P(id_src) == IS_ARRAY) {
            ZVAL_COPY(&intern->identity_source, id_src);
        }
    }
}

/* Extract a php_cedar_str_t pair (type, id) from an AVP-style
 * EntityIdentifier or ActionIdentifier associative array. */
static int
cedar_pick_entity_ids(zval *ent,
                      const char *type_key, size_t type_key_len,
                      const char *id_key,   size_t id_key_len,
                      php_cedar_str_t *type_out, php_cedar_str_t *id_out)
{
    zval *zt, *zi;

    if (ent == NULL || Z_TYPE_P(ent) != IS_ARRAY) {
        return PHP_CEDAR_ERROR;
    }
    zt = zend_hash_str_find(Z_ARRVAL_P(ent), type_key, type_key_len);
    zi = zend_hash_str_find(Z_ARRVAL_P(ent), id_key,   id_key_len);
    if (!zt || !zi
        || Z_TYPE_P(zt) != IS_STRING || Z_TYPE_P(zi) != IS_STRING) {
        return PHP_CEDAR_ERROR;
    }
    type_out->data = (unsigned char *) Z_STRVAL_P(zt);
    type_out->len  = Z_STRLEN_P(zt);
    id_out->data   = (unsigned char *) Z_STRVAL_P(zi);
    id_out->len    = Z_STRLEN_P(zi);
    return PHP_CEDAR_OK;
}

/* ============================================================
 * AttributeValue (AVP Union) -> php_cedar evaluator helpers
 * ============================================================ */

typedef enum {
    CEDAR_TARGET_PRINCIPAL,
    CEDAR_TARGET_ACTION,
    CEDAR_TARGET_RESOURCE,
    CEDAR_TARGET_CONTEXT
} cedar_attr_target_t;

/* AVP's AttributeValue is a one-of union encoded as a single-key
 * associative array, e.g. ['string' => 'x'] or ['set' => [...]].
 * Resolve that wrapper and return the kind string + inner zval. */
static int
cedar_resolve_attr_union(zval *attr_val,
                         zend_string **kind_out, zval **inner_out)
{
    HashTable   *ht;
    zend_string *key;
    zval        *val;

    if (attr_val == NULL || Z_TYPE_P(attr_val) != IS_ARRAY) {
        return PHP_CEDAR_ERROR;
    }
    ht = Z_ARRVAL_P(attr_val);
    if (zend_hash_num_elements(ht) != 1) {
        return PHP_CEDAR_ERROR;
    }
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, key, val) {
        if (!key) {
            return PHP_CEDAR_ERROR;
        }
        *kind_out  = key;
        *inner_out = val;
        return PHP_CEDAR_OK;
    } ZEND_HASH_FOREACH_END();
    return PHP_CEDAR_ERROR;
}

/* Build a php_cedar_str_t view over a zval string (no copy). */
static int
cedar_zval_to_cedar_str(zval *zv, php_cedar_str_t *out)
{
    if (Z_TYPE_P(zv) != IS_STRING) {
        return PHP_CEDAR_ERROR;
    }
    out->data = (unsigned char *) Z_STRVAL_P(zv);
    out->len  = Z_STRLEN_P(zv);
    return PHP_CEDAR_OK;
}

/* Forward declarations for the mutually recursive helpers. */
static int cedar_apply_top_attr(php_cedar_eval_ctx_t *ctx,
                                cedar_attr_target_t tgt,
                                php_cedar_str_t *name, zval *attr_val);
static int cedar_apply_record_attr(php_cedar_record_t *rec,
                                   php_cedar_str_t *name, zval *attr_val);
static int cedar_apply_set_element(php_cedar_set_t *set, zval *attr_val);

/* Populate a record from {key => AttributeValue, ...}. */
static int
cedar_apply_record_children(php_cedar_record_t *rec, zval *inner)
{
    HashTable   *ht;
    zend_string *key;
    zval        *val;

    if (Z_TYPE_P(inner) != IS_ARRAY) {
        return PHP_CEDAR_ERROR;
    }
    ht = Z_ARRVAL_P(inner);
    ZEND_HASH_FOREACH_STR_KEY_VAL(ht, key, val) {
        php_cedar_str_t name;
        if (!key) {
            return PHP_CEDAR_ERROR;
        }
        name.data = (unsigned char *) ZSTR_VAL(key);
        name.len  = ZSTR_LEN(key);
        if (cedar_apply_record_attr(rec, &name, val) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
    } ZEND_HASH_FOREACH_END();
    return PHP_CEDAR_OK;
}

/* Populate a set from [AttributeValue, ...]. */
static int
cedar_apply_set_children(php_cedar_set_t *set, zval *inner)
{
    HashTable *ht;
    zval      *val;

    if (Z_TYPE_P(inner) != IS_ARRAY) {
        return PHP_CEDAR_ERROR;
    }
    ht = Z_ARRVAL_P(inner);
    ZEND_HASH_FOREACH_VAL(ht, val) {
        if (cedar_apply_set_element(set, val) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
    } ZEND_HASH_FOREACH_END();
    return PHP_CEDAR_OK;
}

/* Apply an AttributeValue as a top-level eval_ctx attribute. */
static int
cedar_apply_top_attr(php_cedar_eval_ctx_t *ctx, cedar_attr_target_t tgt,
                     php_cedar_str_t *name, zval *attr_val)
{
    zend_string *kind;
    zval        *inner;
    php_cedar_str_t v;

    if (cedar_resolve_attr_union(attr_val, &kind, &inner) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }

    if (zend_string_equals_literal(kind, "string")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr(ctx, name, &v);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr   (ctx, name, &v);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr (ctx, name, &v);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr  (ctx, name, &v);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "long")) {
        int64_t lv;
        if (Z_TYPE_P(inner) != IS_LONG) return PHP_CEDAR_ERROR;
        lv = (int64_t) Z_LVAL_P(inner);
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_long(ctx, name, lv);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_long   (ctx, name, lv);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_long (ctx, name, lv);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_long  (ctx, name, lv);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "boolean")) {
        php_cedar_flag_t b;
        if (Z_TYPE_P(inner) != IS_TRUE && Z_TYPE_P(inner) != IS_FALSE) {
            return PHP_CEDAR_ERROR;
        }
        b = (Z_TYPE_P(inner) == IS_TRUE) ? 1 : 0;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_bool(ctx, name, b);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_bool   (ctx, name, b);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_bool (ctx, name, b);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_bool  (ctx, name, b);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "ipaddr")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_ip(ctx, name, &v);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_ip   (ctx, name, &v);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_ip (ctx, name, &v);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_ip  (ctx, name, &v);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "decimal")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_decimal(ctx, name, &v);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_decimal   (ctx, name, &v);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_decimal (ctx, name, &v);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_decimal  (ctx, name, &v);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "datetime")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_datetime(ctx, name, &v);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_datetime   (ctx, name, &v);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_datetime (ctx, name, &v);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_datetime  (ctx, name, &v);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "duration")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_duration(ctx, name, &v);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_duration   (ctx, name, &v);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_duration (ctx, name, &v);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_duration  (ctx, name, &v);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "entityIdentifier")) {
        php_cedar_str_t et, eid;
        if (cedar_pick_entity_ids(inner,
                "entityType", sizeof("entityType") - 1,
                "entityId",   sizeof("entityId")   - 1,
                &et, &eid) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: return php_cedar_eval_ctx_add_principal_attr_entity(ctx, name, &et, &eid);
        case CEDAR_TARGET_ACTION:    return php_cedar_eval_ctx_add_action_attr_entity   (ctx, name, &et, &eid);
        case CEDAR_TARGET_RESOURCE:  return php_cedar_eval_ctx_add_resource_attr_entity (ctx, name, &et, &eid);
        case CEDAR_TARGET_CONTEXT:   return php_cedar_eval_ctx_add_context_attr_entity  (ctx, name, &et, &eid);
        }
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "record")) {
        php_cedar_record_t *rec = NULL;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: rec = php_cedar_eval_ctx_add_principal_attr_record(ctx, name); break;
        case CEDAR_TARGET_ACTION:    rec = php_cedar_eval_ctx_add_action_attr_record   (ctx, name); break;
        case CEDAR_TARGET_RESOURCE:  rec = php_cedar_eval_ctx_add_resource_attr_record (ctx, name); break;
        case CEDAR_TARGET_CONTEXT:   rec = php_cedar_eval_ctx_add_context_attr_record  (ctx, name); break;
        }
        if (rec == NULL) return PHP_CEDAR_ERROR;
        return cedar_apply_record_children(rec, inner);
    }
    if (zend_string_equals_literal(kind, "set")) {
        php_cedar_set_t *set = NULL;
        switch (tgt) {
        case CEDAR_TARGET_PRINCIPAL: set = php_cedar_eval_ctx_add_principal_attr_set(ctx, name); break;
        case CEDAR_TARGET_ACTION:    set = php_cedar_eval_ctx_add_action_attr_set   (ctx, name); break;
        case CEDAR_TARGET_RESOURCE:  set = php_cedar_eval_ctx_add_resource_attr_set (ctx, name); break;
        case CEDAR_TARGET_CONTEXT:   set = php_cedar_eval_ctx_add_context_attr_set  (ctx, name); break;
        }
        if (set == NULL) return PHP_CEDAR_ERROR;
        return cedar_apply_set_children(set, inner);
    }
    return PHP_CEDAR_ERROR;
}

/* Apply an AttributeValue as a record member. */
static int
cedar_apply_record_attr(php_cedar_record_t *rec,
                        php_cedar_str_t *name, zval *attr_val)
{
    zend_string *kind;
    zval        *inner;
    php_cedar_str_t v;

    if (cedar_resolve_attr_union(attr_val, &kind, &inner) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "string")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_record_add_str(rec, name, &v);
    }
    if (zend_string_equals_literal(kind, "long")) {
        int64_t lv;
        if (Z_TYPE_P(inner) != IS_LONG) return PHP_CEDAR_ERROR;
        lv = (int64_t) Z_LVAL_P(inner);
        return php_cedar_record_add_long(rec, name, lv);
    }
    if (zend_string_equals_literal(kind, "boolean")) {
        if (Z_TYPE_P(inner) != IS_TRUE && Z_TYPE_P(inner) != IS_FALSE) {
            return PHP_CEDAR_ERROR;
        }
        return php_cedar_record_add_bool(rec, name, (Z_TYPE_P(inner) == IS_TRUE) ? 1 : 0);
    }
    if (zend_string_equals_literal(kind, "ipaddr")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_record_add_ip(rec, name, &v);
    }
    if (zend_string_equals_literal(kind, "decimal")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_record_add_decimal(rec, name, &v);
    }
    if (zend_string_equals_literal(kind, "datetime")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_record_add_datetime(rec, name, &v);
    }
    if (zend_string_equals_literal(kind, "duration")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_record_add_duration(rec, name, &v);
    }
    if (zend_string_equals_literal(kind, "entityIdentifier")) {
        php_cedar_str_t et, eid;
        if (cedar_pick_entity_ids(inner,
                "entityType", sizeof("entityType") - 1,
                "entityId",   sizeof("entityId")   - 1,
                &et, &eid) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
        return php_cedar_record_add_entity(rec, name, &et, &eid);
    }
    if (zend_string_equals_literal(kind, "record")) {
        php_cedar_record_t *child = php_cedar_record_add_record(rec, name);
        if (!child) return PHP_CEDAR_ERROR;
        return cedar_apply_record_children(child, inner);
    }
    if (zend_string_equals_literal(kind, "set")) {
        php_cedar_set_t *child = php_cedar_record_add_set(rec, name);
        if (!child) return PHP_CEDAR_ERROR;
        return cedar_apply_set_children(child, inner);
    }
    return PHP_CEDAR_ERROR;
}

/* Apply an AttributeValue as a set element. */
static int
cedar_apply_set_element(php_cedar_set_t *set, zval *attr_val)
{
    zend_string *kind;
    zval        *inner;
    php_cedar_str_t v;

    if (cedar_resolve_attr_union(attr_val, &kind, &inner) != PHP_CEDAR_OK) {
        return PHP_CEDAR_ERROR;
    }
    if (zend_string_equals_literal(kind, "string")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_set_add_str(set, &v);
    }
    if (zend_string_equals_literal(kind, "long")) {
        int64_t lv;
        if (Z_TYPE_P(inner) != IS_LONG) return PHP_CEDAR_ERROR;
        lv = (int64_t) Z_LVAL_P(inner);
        return php_cedar_set_add_long(set, lv);
    }
    if (zend_string_equals_literal(kind, "boolean")) {
        if (Z_TYPE_P(inner) != IS_TRUE && Z_TYPE_P(inner) != IS_FALSE) {
            return PHP_CEDAR_ERROR;
        }
        return php_cedar_set_add_bool(set, (Z_TYPE_P(inner) == IS_TRUE) ? 1 : 0);
    }
    if (zend_string_equals_literal(kind, "ipaddr")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_set_add_ip(set, &v);
    }
    if (zend_string_equals_literal(kind, "decimal")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_set_add_decimal(set, &v);
    }
    if (zend_string_equals_literal(kind, "datetime")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_set_add_datetime(set, &v);
    }
    if (zend_string_equals_literal(kind, "duration")) {
        if (cedar_zval_to_cedar_str(inner, &v) != PHP_CEDAR_OK) return PHP_CEDAR_ERROR;
        return php_cedar_set_add_duration(set, &v);
    }
    if (zend_string_equals_literal(kind, "entityIdentifier")) {
        php_cedar_str_t et, eid;
        if (cedar_pick_entity_ids(inner,
                "entityType", sizeof("entityType") - 1,
                "entityId",   sizeof("entityId")   - 1,
                &et, &eid) != PHP_CEDAR_OK) {
            return PHP_CEDAR_ERROR;
        }
        return php_cedar_set_add_entity(set, &et, &eid);
    }
    if (zend_string_equals_literal(kind, "set")) {
        php_cedar_set_t *child = php_cedar_set_add_set(set);
        if (!child) return PHP_CEDAR_ERROR;
        return cedar_apply_set_children(child, inner);
    }
    if (zend_string_equals_literal(kind, "record")) {
        php_cedar_record_t *child = php_cedar_set_add_record(set);
        if (!child) return PHP_CEDAR_ERROR;
        return cedar_apply_record_children(child, inner);
    }
    return PHP_CEDAR_ERROR;
}

/* Append {errorDescription: msg} to the errors array. */
static void
cedar_push_error(zval *errors, const char *fmt, ...)
{
    char    buf[512];
    va_list ap;
    zval    entry;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    array_init(&entry);
    add_assoc_string(&entry, "errorDescription", buf);
    add_next_index_zval(errors, &entry);
}

/* Walk context.contextMap and push each entry into eval_ctx. */
static void
cedar_apply_context_map(php_cedar_eval_ctx_t *ctx, zval *params, zval *errors)
{
    zval        *zv_ctx, *zv_map, *val;
    zend_string *key;

    zv_ctx = zend_hash_str_find(Z_ARRVAL_P(params),
                                "context", sizeof("context") - 1);
    if (!zv_ctx || Z_TYPE_P(zv_ctx) != IS_ARRAY) return;
    zv_map = zend_hash_str_find(Z_ARRVAL_P(zv_ctx),
                                "contextMap", sizeof("contextMap") - 1);
    if (!zv_map || Z_TYPE_P(zv_map) != IS_ARRAY) return;

    ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zv_map), key, val) {
        php_cedar_str_t name;
        if (!key) continue;
        name.data = (unsigned char *) ZSTR_VAL(key);
        name.len  = ZSTR_LEN(key);
        if (cedar_apply_top_attr(ctx, CEDAR_TARGET_CONTEXT, &name, val)
            != PHP_CEDAR_OK) {
            cedar_push_error(errors,
                "unsupported or malformed AttributeValue for context.%s",
                ZSTR_VAL(key));
        }
    } ZEND_HASH_FOREACH_END();
}

/* True iff two php_cedar_str_t hold the same bytes. */
static int
cedar_str_equal(const php_cedar_str_t *a, const php_cedar_str_t *b)
{
    return a->len == b->len && memcmp(a->data, b->data, a->len) == 0;
}

/* Walk entities.entityList. For each entry whose identifier matches
 * the request principal/action/resource, inject its attributes; parents
 * are always forwarded to the corresponding add_*_parent call. */
static void
cedar_apply_entities(php_cedar_eval_ctx_t *ctx, zval *params, zval *errors,
                     const php_cedar_str_t *p_type, const php_cedar_str_t *p_id,
                     const php_cedar_str_t *a_type, const php_cedar_str_t *a_id,
                     const php_cedar_str_t *r_type, const php_cedar_str_t *r_id)
{
    zval *zv_entities, *zv_list, *entity;

    zv_entities = zend_hash_str_find(Z_ARRVAL_P(params),
                                     "entities", sizeof("entities") - 1);
    if (!zv_entities || Z_TYPE_P(zv_entities) != IS_ARRAY) return;
    zv_list = zend_hash_str_find(Z_ARRVAL_P(zv_entities),
                                 "entityList", sizeof("entityList") - 1);
    if (!zv_list || Z_TYPE_P(zv_list) != IS_ARRAY) return;

    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(zv_list), entity) {
        zval               *zv_id_obj, *zv_attrs, *zv_parents;
        php_cedar_str_t     e_type, e_id;
        int                 match_principal, match_action, match_resource;
        int                 matched_subject;

        if (Z_TYPE_P(entity) != IS_ARRAY) continue;
        zv_id_obj = zend_hash_str_find(Z_ARRVAL_P(entity),
                                       "identifier", sizeof("identifier") - 1);
        if (!zv_id_obj || cedar_pick_entity_ids(zv_id_obj,
                "entityType", sizeof("entityType") - 1,
                "entityId",   sizeof("entityId")   - 1,
                &e_type, &e_id) != PHP_CEDAR_OK) {
            continue;
        }

        /* The same identifier may be principal, action, and/or resource;
         * apply attributes and parents to every target it matches. */
        match_principal = cedar_str_equal(&e_type, p_type) && cedar_str_equal(&e_id, p_id);
        match_action    = cedar_str_equal(&e_type, a_type) && cedar_str_equal(&e_id, a_id);
        match_resource  = cedar_str_equal(&e_type, r_type) && cedar_str_equal(&e_id, r_id);
        matched_subject = match_principal || match_action || match_resource;

        if (matched_subject) {
            zv_attrs = zend_hash_str_find(Z_ARRVAL_P(entity),
                                          "attributes",
                                          sizeof("attributes") - 1);
            if (zv_attrs && Z_TYPE_P(zv_attrs) == IS_ARRAY) {
                zend_string *key;
                zval        *val;
                ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(zv_attrs), key, val) {
                    php_cedar_str_t name;
                    int             arc = PHP_CEDAR_OK;
                    if (!key) continue;
                    name.data = (unsigned char *) ZSTR_VAL(key);
                    name.len  = ZSTR_LEN(key);
                    if (match_principal) {
                        arc = cedar_apply_top_attr(ctx, CEDAR_TARGET_PRINCIPAL,
                                                   &name, val);
                    }
                    if (arc == PHP_CEDAR_OK && match_action) {
                        arc = cedar_apply_top_attr(ctx, CEDAR_TARGET_ACTION,
                                                   &name, val);
                    }
                    if (arc == PHP_CEDAR_OK && match_resource) {
                        arc = cedar_apply_top_attr(ctx, CEDAR_TARGET_RESOURCE,
                                                   &name, val);
                    }
                    if (arc != PHP_CEDAR_OK) {
                        cedar_push_error(errors,
                            "unsupported or malformed AttributeValue for "
                            "%.*s::\"%.*s\".%s",
                            (int) e_type.len, (const char *) e_type.data,
                            (int) e_id.len,   (const char *) e_id.data,
                            ZSTR_VAL(key));
                    }
                } ZEND_HASH_FOREACH_END();
            }
        }

        zv_parents = zend_hash_str_find(Z_ARRVAL_P(entity),
                                        "parents", sizeof("parents") - 1);
        if (zv_parents && Z_TYPE_P(zv_parents) == IS_ARRAY) {
            zval *parent;
            ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(zv_parents), parent) {
                php_cedar_str_t pt, pi;
                if (cedar_pick_entity_ids(parent,
                        "entityType", sizeof("entityType") - 1,
                        "entityId",   sizeof("entityId")   - 1,
                        &pt, &pi) != PHP_CEDAR_OK) {
                    continue;
                }
                if (!matched_subject) {
                    /* Entities other than principal/resource have no
                     * place to attach parents in the current eval_ctx
                     * shape; skip silently. */
                    continue;
                }
                if (match_principal) {
                    php_cedar_eval_ctx_add_principal_parent(ctx, &pt, &pi);
                }
                if (match_action) {
                    php_cedar_eval_ctx_add_action_parent(ctx, &pt, &pi);
                }
                if (match_resource) {
                    php_cedar_eval_ctx_add_resource_parent(ctx, &pt, &pi);
                }
            } ZEND_HASH_FOREACH_END();
        }
    } ZEND_HASH_FOREACH_END();
}

/* Populate return_value with the AVP-compatible response shape.
 *
 * AVP rules: forbid overrides permit. If any forbid matched, decision
 * is DENY and determiningPolicies lists only the forbids. Otherwise, if
 * any permit matched, decision is ALLOW and determiningPolicies lists
 * the permits. With no matches at all, decision is DENY (implicit) and
 * determiningPolicies is empty. The unused permit/forbid bucket is
 * released here so the caller can hand both buckets unconditionally. */
static void
cedar_finalize_response(zval *return_value,
                        zval *permit_ids, zval *forbid_ids, zval *errors)
{
    int         has_forbid = zend_hash_num_elements(Z_ARRVAL_P(forbid_ids)) > 0;
    const char *decision   = has_forbid ? "DENY"
                           : (zend_hash_num_elements(Z_ARRVAL_P(permit_ids)) > 0
                              ? "ALLOW" : "DENY");

    array_init(return_value);
    add_assoc_string(return_value, "decision", decision);
    if (has_forbid) {
        add_assoc_zval(return_value, "determiningPolicies", forbid_ids);
        zval_ptr_dtor(permit_ids);
    } else {
        add_assoc_zval(return_value, "determiningPolicies", permit_ids);
        zval_ptr_dtor(forbid_ids);
    }
    add_assoc_zval(return_value, "errors", errors);
}

/* Append {policyId: policy_id} to the target array. */
static void
cedar_push_policy_id(zval *target, zend_string *policy_id)
{
    zval entry;
    if (!policy_id) {
        return;
    }
    array_init(&entry);
    add_assoc_str(&entry, "policyId", zend_string_copy(policy_id));
    add_next_index_zval(target, &entry);
}

/* Evaluate one policy_set and accumulate matched policy ids per kind.
 * AVP semantics: when at least one forbid matches across the whole
 * evaluation, determiningPolicies must list only the forbids; otherwise
 * it lists every matching permit. Buffer permits and forbids separately
 * so the caller can pick the right bucket once all bundles are done. */
static void
cedar_eval_one_bundle(zend_string *policy_id,
                      php_cedar_policy_set_t *ps,
                      php_cedar_eval_ctx_t *ctx,
                      php_cedar_log_t *log,
                      zval *permit_ids, zval *forbid_ids)
{
    php_cedar_decision_detail_t detail;
    php_cedar_decision_t        d;

    memset(&detail, 0, sizeof(detail));
    d = php_cedar_eval_detail(ps, ctx, log, &detail);

    if (d == PHP_CEDAR_DECISION_ALLOW) {
        cedar_push_policy_id(permit_ids, policy_id);
    } else if (d == PHP_CEDAR_DECISION_DENY && detail.npolicies > 0) {
        /* DENY because at least one forbid matched. */
        cedar_push_policy_id(forbid_ids, policy_id);
    }
    /* Implicit DENY (no policy matched) contributes nothing. */
}

/* Common evaluation routine shared by isAuthorized() and
 * isAuthorizedWithToken().
 *
 * Caller supplies the resolved principal / action / resource. Optional
 * group_parents (an array of {entityType, entityId} entries) are
 * additionally registered as principal parents — this is how the token
 * path injects identitySource.groupIdsClaim. When include_principal is
 * non-zero, the response array carries an extra "principal" entry
 * matching AVP's IsAuthorizedWithToken output shape.
 *
 * Throws ResourceNotFoundException / EvaluationException as needed;
 * caller should check EG(exception) on return. */
static void
cedar_evaluate_request(cedar_policy_store_t *store, zval *params,
                       const php_cedar_str_t *p_type,
                       const php_cedar_str_t *p_id,
                       const php_cedar_str_t *a_type,
                       const php_cedar_str_t *a_id,
                       const php_cedar_str_t *r_type,
                       const php_cedar_str_t *r_id,
                       zval *group_parents,
                       bool include_principal,
                       zval *return_value)
{
    php_cedar_pool_t       *eval_pool;
    php_cedar_log_t         eval_log;
    php_cedar_eval_ctx_t   *eval_ctx;
    zval                    permit_ids, forbid_ids, errors;
    zend_string            *pid_key;
    php_cedar_policy_set_t *ps;
    zval                   *zid;

    /* policyStoreId is a required AVP key; reject non-string values. */
    zid = zend_hash_str_find(Z_ARRVAL_P(params),
                             "policyStoreId", sizeof("policyStoreId") - 1);
    if (!zid || Z_TYPE_P(zid) != IS_STRING) {
        zend_throw_error(NULL, "'policyStoreId' (string) is required");
        return;
    }
    if (!store->id || !zend_string_equals(Z_STR_P(zid), store->id)) {
        zend_throw_exception_ex(cedar_ce_ResourceNotFoundException, 0,
            "policyStoreId '%s' does not match the bound PolicyStore",
            Z_STRVAL_P(zid));
        return;
    }

    memset(&eval_log, 0, sizeof(eval_log));
    eval_log.level = 0;
    eval_pool = php_cedar_pool_create(&eval_log);
    if (!eval_pool) {
        zend_throw_exception_ex(cedar_ce_EvaluationException, 0,
            "failed to allocate evaluation pool");
        return;
    }
    eval_ctx = php_cedar_eval_ctx_create(eval_pool);
    if (!eval_ctx) {
        php_cedar_pool_destroy(eval_pool);
        zend_throw_exception_ex(cedar_ce_EvaluationException, 0,
            "failed to create evaluation context");
        return;
    }

    php_cedar_eval_ctx_set_principal(eval_ctx, p_type, p_id);
    php_cedar_eval_ctx_set_action(eval_ctx, a_type, a_id);
    php_cedar_eval_ctx_set_resource(eval_ctx, r_type, r_id);

    array_init(&permit_ids);
    array_init(&forbid_ids);
    array_init(&errors);

    cedar_apply_context_map(eval_ctx, params, &errors);
    cedar_apply_entities(eval_ctx, params, &errors,
                         p_type, p_id, a_type, a_id, r_type, r_id);

    /* Token-derived group parents (identitySource.groupIdsClaim). */
    if (group_parents && Z_TYPE_P(group_parents) == IS_ARRAY) {
        zval *entry;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(group_parents), entry) {
            php_cedar_str_t gt, gi;
            if (cedar_pick_entity_ids(entry,
                    "entityType", sizeof("entityType") - 1,
                    "entityId",   sizeof("entityId")   - 1,
                    &gt, &gi) == PHP_CEDAR_OK) {
                php_cedar_eval_ctx_add_principal_parent(eval_ctx, &gt, &gi);
            }
        } ZEND_HASH_FOREACH_END();
    }

    ZEND_HASH_FOREACH_STR_KEY_PTR(&store->policies, pid_key, ps) {
        cedar_eval_one_bundle(pid_key, ps, eval_ctx, &eval_log,
                              &permit_ids, &forbid_ids);
    } ZEND_HASH_FOREACH_END();

    php_cedar_pool_destroy(eval_pool);

    cedar_finalize_response(return_value, &permit_ids, &forbid_ids, &errors);

    if (include_principal) {
        zval principal_zv;
        array_init(&principal_zv);
        add_assoc_stringl(&principal_zv, "entityType",
            (char *) p_type->data, p_type->len);
        add_assoc_stringl(&principal_zv, "entityId",
            (char *) p_id->data, p_id->len);
        add_assoc_zval(return_value, "principal", &principal_zv);
    }
}

PHP_METHOD(Cedar_AuthorizationClient, isAuthorized)
{
    cedar_authz_client_t *intern;
    cedar_policy_store_t *store;
    zval                 *params;
    zval                 *zp, *za, *zr;
    php_cedar_str_t       p_type, p_id, a_type, a_id, r_type, r_id;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(params)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_AUTHZ_CLIENT_P(ZEND_THIS);
    if (Z_TYPE(intern->policy_store) != IS_OBJECT) {
        zend_throw_exception_ex(cedar_ce_EvaluationException, 0,
            "AuthorizationClient is not bound to a PolicyStore");
        return;
    }
    store = Z_CEDAR_POLICY_STORE_P(&intern->policy_store);

    zp = zend_hash_str_find(Z_ARRVAL_P(params),
                            "principal", sizeof("principal") - 1);
    za = zend_hash_str_find(Z_ARRVAL_P(params),
                            "action",    sizeof("action")    - 1);
    zr = zend_hash_str_find(Z_ARRVAL_P(params),
                            "resource",  sizeof("resource")  - 1);

    if (cedar_pick_entity_ids(zp, "entityType", sizeof("entityType") - 1,
                                  "entityId",   sizeof("entityId")   - 1,
                              &p_type, &p_id) != PHP_CEDAR_OK
     || cedar_pick_entity_ids(za, "actionType", sizeof("actionType") - 1,
                                  "actionId",   sizeof("actionId")   - 1,
                              &a_type, &a_id) != PHP_CEDAR_OK
     || cedar_pick_entity_ids(zr, "entityType", sizeof("entityType") - 1,
                                  "entityId",   sizeof("entityId")   - 1,
                              &r_type, &r_id) != PHP_CEDAR_OK) {
        zend_throw_error(NULL,
            "isAuthorized(): principal/resource must be "
            "{entityType, entityId}, action must be {actionType, actionId}");
        return;
    }

    cedar_evaluate_request(store, params,
                           &p_type, &p_id, &a_type, &a_id, &r_type, &r_id,
                           NULL,  /* no group parents */
                           false, /* do not include principal in response */
                           return_value);
}

/* Locate a string-valued claim inside a payload array. */
static int
cedar_payload_str(zval *payload, const char *claim, size_t claim_len,
                  php_cedar_str_t *out)
{
    zval *v;
    if (Z_TYPE_P(payload) != IS_ARRAY) return PHP_CEDAR_ERROR;
    v = zend_hash_str_find(Z_ARRVAL_P(payload), claim, claim_len);
    if (!v || Z_TYPE_P(v) != IS_STRING) return PHP_CEDAR_ERROR;
    out->data = (unsigned char *) Z_STRVAL_P(v);
    out->len  = Z_STRLEN_P(v);
    return PHP_CEDAR_OK;
}

/* Convert payload[claim] (expected to be a list of strings) into an
 * array of {entityType, entityId} entries usable as principal parents. */
static int
cedar_build_group_parents(zval *payload, const char *claim, size_t claim_len,
                          zval *group_type_zv, zval *out_parents)
{
    zval *list, *gid;

    if (Z_TYPE_P(payload) != IS_ARRAY) return PHP_CEDAR_ERROR;
    list = zend_hash_str_find(Z_ARRVAL_P(payload), claim, claim_len);
    if (!list || Z_TYPE_P(list) != IS_ARRAY) {
        /* Claim absent or not a list: treat as no groups (not an error). */
        return PHP_CEDAR_OK;
    }
    if (!group_type_zv || Z_TYPE_P(group_type_zv) != IS_STRING) {
        return PHP_CEDAR_ERROR;
    }

    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(list), gid) {
        zval entry;
        if (Z_TYPE_P(gid) != IS_STRING) continue;
        array_init(&entry);
        add_assoc_str(&entry, "entityType", zend_string_copy(Z_STR_P(group_type_zv)));
        add_assoc_str(&entry, "entityId",   zend_string_copy(Z_STR_P(gid)));
        add_next_index_zval(out_parents, &entry);
    } ZEND_HASH_FOREACH_END();
    return PHP_CEDAR_OK;
}

PHP_METHOD(Cedar_AuthorizationClient, isAuthorizedWithToken)
{
    cedar_authz_client_t *intern;
    cedar_policy_store_t *store;
    zval                 *params, *za, *zr;
    zval                 *id_tok, *ac_tok, *payload;
    HashTable            *id_src;
    zval                 *p_type_zv, *p_claim_zv, *g_type_zv, *g_claim_zv;
    const char           *p_claim_name;
    size_t                p_claim_len;
    php_cedar_str_t       p_type, p_id, a_type, a_id, r_type, r_id;
    zval                  group_parents;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(params)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_AUTHZ_CLIENT_P(ZEND_THIS);
    if (Z_TYPE(intern->policy_store) != IS_OBJECT) {
        zend_throw_exception_ex(cedar_ce_EvaluationException, 0,
            "AuthorizationClient is not bound to a PolicyStore");
        return;
    }
    store = Z_CEDAR_POLICY_STORE_P(&intern->policy_store);

    /* identitySource must have been supplied to the constructor. */
    if (Z_TYPE(intern->identity_source) != IS_ARRAY) {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): AuthorizationClient was not "
            "constructed with an 'identitySource' option");
        return;
    }
    id_src = Z_ARRVAL(intern->identity_source);

    /* Reject 'principal' from the caller — it is derived from the token. */
    if (zend_hash_str_exists(Z_ARRVAL_P(params),
            "principal", sizeof("principal") - 1)) {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): 'principal' must not be supplied; "
            "it is derived from the token");
        return;
    }

    /* At least one of identityToken / accessToken (verified payload). */
    id_tok = zend_hash_str_find(Z_ARRVAL_P(params),
                                "identityToken", sizeof("identityToken") - 1);
    ac_tok = zend_hash_str_find(Z_ARRVAL_P(params),
                                "accessToken",   sizeof("accessToken")   - 1);
    if (id_tok && Z_TYPE_P(id_tok) == IS_ARRAY) {
        payload = id_tok;
    } else if (ac_tok && Z_TYPE_P(ac_tok) == IS_ARRAY) {
        payload = ac_tok;
    } else {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): 'identityToken' or 'accessToken' "
            "(verified claims array) is required");
        return;
    }

    /* Resolve principalEntityType + principalIdClaim (default "sub"). */
    p_type_zv  = zend_hash_str_find(id_src,
        "principalEntityType", sizeof("principalEntityType") - 1);
    p_claim_zv = zend_hash_str_find(id_src,
        "principalIdClaim",    sizeof("principalIdClaim")    - 1);
    if (!p_type_zv || Z_TYPE_P(p_type_zv) != IS_STRING) {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): identitySource.principalEntityType "
            "(string) is required");
        return;
    }
    if (p_claim_zv && Z_TYPE_P(p_claim_zv) == IS_STRING) {
        p_claim_name = Z_STRVAL_P(p_claim_zv);
        p_claim_len  = Z_STRLEN_P(p_claim_zv);
    } else {
        p_claim_name = "sub";
        p_claim_len  = sizeof("sub") - 1;
    }

    p_type.data = (unsigned char *) Z_STRVAL_P(p_type_zv);
    p_type.len  = Z_STRLEN_P(p_type_zv);

    if (cedar_payload_str(payload, p_claim_name, p_claim_len, &p_id)
        != PHP_CEDAR_OK) {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): claim '%s' is missing or not a "
            "string in the supplied token payload", p_claim_name);
        return;
    }

    /* action / resource: same shape as isAuthorized(). */
    za = zend_hash_str_find(Z_ARRVAL_P(params),
                            "action",   sizeof("action")   - 1);
    zr = zend_hash_str_find(Z_ARRVAL_P(params),
                            "resource", sizeof("resource") - 1);
    if (cedar_pick_entity_ids(za, "actionType", sizeof("actionType") - 1,
                                  "actionId",   sizeof("actionId")   - 1,
                              &a_type, &a_id) != PHP_CEDAR_OK
     || cedar_pick_entity_ids(zr, "entityType", sizeof("entityType") - 1,
                                  "entityId",   sizeof("entityId")   - 1,
                              &r_type, &r_id) != PHP_CEDAR_OK) {
        zend_throw_error(NULL,
            "isAuthorizedWithToken(): action must be "
            "{actionType, actionId}, resource must be "
            "{entityType, entityId}");
        return;
    }

    /* Build group parents from identitySource.groupIdsClaim, if any. */
    array_init(&group_parents);
    g_type_zv  = zend_hash_str_find(id_src,
        "groupEntityType", sizeof("groupEntityType") - 1);
    g_claim_zv = zend_hash_str_find(id_src,
        "groupIdsClaim",   sizeof("groupIdsClaim")   - 1);
    if (g_type_zv && Z_TYPE_P(g_type_zv) == IS_STRING
     && g_claim_zv && Z_TYPE_P(g_claim_zv) == IS_STRING) {
        if (cedar_build_group_parents(payload,
                Z_STRVAL_P(g_claim_zv), Z_STRLEN_P(g_claim_zv),
                g_type_zv, &group_parents) != PHP_CEDAR_OK) {
            zval_ptr_dtor(&group_parents);
            zend_throw_error(NULL,
                "isAuthorizedWithToken(): failed to map group claims");
            return;
        }
    }

    cedar_evaluate_request(store, params,
                           &p_type, &p_id, &a_type, &a_id, &r_type, &r_id,
                           &group_parents,
                           true, /* include extracted principal in response */
                           return_value);

    zval_ptr_dtor(&group_parents);
}

/* ============================================================
 * Module initialization
 * ============================================================ */

PHP_MINIT_FUNCTION(cedar)
{
#if defined(ZTS) && defined(COMPILE_DL_CEDAR)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    /* PolicyStore */
    cedar_ce_PolicyStore = register_class_Cedar_PolicyStore();
    cedar_ce_PolicyStore->create_object = cedar_policy_store_create;
    memcpy(&cedar_policy_store_handlers, zend_get_std_object_handlers(),
           sizeof(zend_object_handlers));
    cedar_policy_store_handlers.offset    = XtOffsetOf(cedar_policy_store_t, std);
    cedar_policy_store_handlers.free_obj  = cedar_policy_store_free;
    cedar_policy_store_handlers.clone_obj = NULL;

    /* AuthorizationClient */
    cedar_ce_AuthorizationClient = register_class_Cedar_AuthorizationClient();
    cedar_ce_AuthorizationClient->create_object = cedar_authz_client_create;
    memcpy(&cedar_authz_client_handlers, zend_get_std_object_handlers(),
           sizeof(zend_object_handlers));
    cedar_authz_client_handlers.offset    = XtOffsetOf(cedar_authz_client_t, std);
    cedar_authz_client_handlers.free_obj  = cedar_authz_client_free;
    cedar_authz_client_handlers.clone_obj = NULL;

    /* Exceptions (subclass of \RuntimeException) */
    cedar_ce_PolicyParseException =
        register_class_Cedar_Exception_PolicyParseException(
            spl_ce_RuntimeException);
    cedar_ce_EvaluationException =
        register_class_Cedar_Exception_EvaluationException(
            spl_ce_RuntimeException);
    cedar_ce_ResourceNotFoundException =
        register_class_Cedar_Exception_ResourceNotFoundException(
            spl_ce_RuntimeException);

    return SUCCESS;
}

PHP_MINFO_FUNCTION(cedar)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "cedar support", "enabled");
    php_info_print_table_row(2, "version", PHP_CEDAR_VERSION);
    php_info_print_table_end();
}

zend_module_entry cedar_module_entry = {
    STANDARD_MODULE_HEADER,
    "cedar",
    NULL,              /* functions */
    PHP_MINIT(cedar),
    NULL,              /* MSHUTDOWN */
    NULL,              /* RINIT     */
    NULL,              /* RSHUTDOWN */
    PHP_MINFO(cedar),
    PHP_CEDAR_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_CEDAR
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(cedar)
#endif
