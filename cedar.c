/*
 * php-ext-cedar — Local Cedar policy evaluator (AVP-compatible API)
 *
 * Cedar\PolicyStore          : container that holds multiple policies
 * Cedar\AuthorizationClient  : AVP-compatible evaluation client
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
         * buffer, so the output keeps the same 32-char hex shape. */
        static uint64_t seq = 0;
        uint64_t t = (uint64_t) time(NULL);
        uint64_t s = ++seq;
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
    zval         policy_store;   /* PolicyStore object held by reference */
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
    return &intern->std;
}

static void
cedar_authz_client_free(zend_object *obj)
{
    cedar_authz_client_t *intern = cedar_authz_client_from_obj(obj);
    zval_ptr_dtor(&intern->policy_store);
    zend_object_std_dtor(&intern->std);
}

PHP_METHOD(Cedar_AuthorizationClient, __construct)
{
    cedar_authz_client_t *intern;
    zval                 *store;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_OBJECT_OF_CLASS(store, cedar_ce_PolicyStore)
    ZEND_PARSE_PARAMETERS_END();

    intern = Z_CEDAR_AUTHZ_CLIENT_P(ZEND_THIS);
    ZVAL_COPY(&intern->policy_store, store);
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

/* Populate return_value with the AVP-compatible response shape. */
static void
cedar_finalize_response(zval *return_value,
                        int has_allow, int has_forbid,
                        zval *determining, zval *errors)
{
    const char *decision = (has_forbid || !has_allow) ? "DENY" : "ALLOW";

    array_init(return_value);
    add_assoc_string(return_value, "decision", decision);
    add_assoc_zval(return_value,   "determiningPolicies", determining);
    add_assoc_zval(return_value,   "errors", errors);
}

/* Evaluate one policy_set and update the aggregated decision state. */
static void
cedar_eval_one_bundle(zend_string *policy_id,
                      php_cedar_policy_set_t *ps,
                      php_cedar_eval_ctx_t *ctx,
                      php_cedar_log_t *log,
                      int *has_allow, int *has_forbid,
                      zval *determining)
{
    php_cedar_decision_detail_t detail;
    php_cedar_decision_t        d;

    memset(&detail, 0, sizeof(detail));
    d = php_cedar_eval_detail(ps, ctx, log, &detail);

    if (d == PHP_CEDAR_DECISION_ALLOW) {
        *has_allow = 1;
    } else if (d == PHP_CEDAR_DECISION_DENY && detail.npolicies > 0) {
        /* DENY reached because at least one forbid matched. */
        *has_forbid = 1;
    } else {
        /* Implicit DENY (no permit matched); do not add to determining. */
        return;
    }
    if (policy_id) {
        zval entry;
        array_init(&entry);
        add_assoc_str(&entry, "policyId", zend_string_copy(policy_id));
        add_next_index_zval(determining, &entry);
    }
}

PHP_METHOD(Cedar_AuthorizationClient, isAuthorized)
{
    cedar_authz_client_t *intern;
    cedar_policy_store_t *store;
    zval                 *params;
    zval                 *zid, *zp, *za, *zr;
    php_cedar_str_t       p_type, p_id, a_type, a_id, r_type, r_id;
    php_cedar_pool_t     *eval_pool;
    php_cedar_log_t       eval_log;
    php_cedar_eval_ctx_t *eval_ctx;
    int                   has_allow = 0;
    int                   has_forbid = 0;
    zval                  determining, errors;
    zend_string          *pid_key;
    php_cedar_policy_set_t *ps;

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

    /* policyStoreId is a required AVP key; reject non-string values. */
    zid = zend_hash_str_find(Z_ARRVAL_P(params),
                             "policyStoreId", sizeof("policyStoreId") - 1);
    if (!zid || Z_TYPE_P(zid) != IS_STRING) {
        zend_throw_error(NULL,
            "isAuthorized(): 'policyStoreId' (string) is required");
        return;
    }
    if (!store->id
        || Z_STRLEN_P(zid) != ZSTR_LEN(store->id)
        || memcmp(Z_STRVAL_P(zid), ZSTR_VAL(store->id),
                  ZSTR_LEN(store->id)) != 0) {
        zend_throw_exception_ex(cedar_ce_ResourceNotFoundException, 0,
            "policyStoreId '%s' does not match the bound PolicyStore",
            Z_STRVAL_P(zid));
        return;
    }

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

    /* Request-scoped evaluation pool and context. */
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

    php_cedar_eval_ctx_set_principal(eval_ctx, &p_type, &p_id);
    php_cedar_eval_ctx_set_action(eval_ctx,    &a_type, &a_id);
    php_cedar_eval_ctx_set_resource(eval_ctx,  &r_type, &r_id);

    /* TODO (M4 follow-up): context.contextMap, entities.entityList,
     * AttributeValue Union beyond scalars, transitive parent resolution. */

    array_init(&determining);
    array_init(&errors);

    /* Evaluate every policy_set in the store and combine the results. */
    ZEND_HASH_FOREACH_STR_KEY_PTR(&store->policies, pid_key, ps) {
        cedar_eval_one_bundle(pid_key, ps, eval_ctx, &eval_log,
                              &has_allow, &has_forbid, &determining);
    } ZEND_HASH_FOREACH_END();

    php_cedar_pool_destroy(eval_pool);

    cedar_finalize_response(return_value, has_allow, has_forbid,
                            &determining, &errors);
}

/* isAuthorizedWithToken defers JWT verification to the caller, so the
 * extension itself does not implement it yet. Surface a clear runtime
 * error pointing users to isAuthorized() with an extracted principal. */
PHP_METHOD(Cedar_AuthorizationClient, isAuthorizedWithToken)
{
    zval *params;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_ARRAY(params)
    ZEND_PARSE_PARAMETERS_END();
    (void) params;

    zend_throw_exception_ex(spl_ce_RuntimeException, 0,
        "isAuthorizedWithToken() is not implemented yet; "
        "verify JWT externally and call isAuthorized() with the extracted principal");
}

/* ============================================================
 * Module initialization
 * ============================================================ */

PHP_MINIT_FUNCTION(cedar)
{
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
ZEND_GET_MODULE(cedar)
#endif
