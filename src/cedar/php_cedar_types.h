/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_types.h - data structure definitions for nxe-cedar
 *
 * Type definitions used by the Cedar policy language subset
 * implementation in C. No implementation code, types only.
 */

#ifndef PHP_CEDAR_TYPES_H
#define PHP_CEDAR_TYPES_H

#include "php_cedar_compat.h"
#include <stdint.h>


/* --- decision result --- */

typedef enum {
    PHP_CEDAR_DECISION_DENY  = 0,   /* deny (default) */
    PHP_CEDAR_DECISION_ALLOW = 1    /* allow */
} php_cedar_decision_t;


/* --- token types --- */

typedef enum {
    /* keywords */
    PHP_CEDAR_TOKEN_PERMIT,
    PHP_CEDAR_TOKEN_FORBID,
    PHP_CEDAR_TOKEN_WHEN,
    PHP_CEDAR_TOKEN_UNLESS,
    PHP_CEDAR_TOKEN_PRINCIPAL,
    PHP_CEDAR_TOKEN_ACTION,
    PHP_CEDAR_TOKEN_RESOURCE,
    PHP_CEDAR_TOKEN_CONTEXT,
    PHP_CEDAR_TOKEN_TRUE,
    PHP_CEDAR_TOKEN_FALSE,
    PHP_CEDAR_TOKEN_IN,
    PHP_CEDAR_TOKEN_IF,             /* Phase 2 */
    PHP_CEDAR_TOKEN_THEN,           /* Phase 2 */
    PHP_CEDAR_TOKEN_ELSE,           /* Phase 2 */
    PHP_CEDAR_TOKEN_HAS,            /* Phase 2 */
    PHP_CEDAR_TOKEN_LIKE,           /* Phase 2 */
    PHP_CEDAR_TOKEN_IP,             /* Phase 3 */
    PHP_CEDAR_TOKEN_DECIMAL,        /* Phase 3 */
    PHP_CEDAR_TOKEN_IS,             /* Phase 4 */

    /* operators */
    PHP_CEDAR_TOKEN_EQ,             /* == */
    PHP_CEDAR_TOKEN_NE,             /* != */
    PHP_CEDAR_TOKEN_AND,            /* && */
    PHP_CEDAR_TOKEN_OR,             /* || */
    PHP_CEDAR_TOKEN_NOT,            /* ! */
    PHP_CEDAR_TOKEN_MINUS,          /* -  (binary and unary; Phase 4) */
    PHP_CEDAR_TOKEN_PLUS,           /* +  (Phase 4) */
    PHP_CEDAR_TOKEN_STAR,           /* *  (Phase 4) */
    PHP_CEDAR_TOKEN_LT,             /* <  (Phase 2) */
    PHP_CEDAR_TOKEN_GT,             /* >  (Phase 2) */
    PHP_CEDAR_TOKEN_LE,             /* <= (Phase 2) */
    PHP_CEDAR_TOKEN_GE,             /* >= (Phase 2) */

    /* delimiters */
    PHP_CEDAR_TOKEN_DOT,            /* . */
    PHP_CEDAR_TOKEN_COMMA,          /* , */
    PHP_CEDAR_TOKEN_SEMICOLON,      /* ; */
    PHP_CEDAR_TOKEN_LPAREN,         /* ( */
    PHP_CEDAR_TOKEN_RPAREN,         /* ) */
    PHP_CEDAR_TOKEN_LBRACE,         /* { */
    PHP_CEDAR_TOKEN_RBRACE,         /* } */
    PHP_CEDAR_TOKEN_LBRACKET,       /* [ */
    PHP_CEDAR_TOKEN_RBRACKET,       /* ] */
    PHP_CEDAR_TOKEN_COLONCOLON,     /* :: */
    PHP_CEDAR_TOKEN_COLON,          /* :  (Phase 4 record literal) */
    PHP_CEDAR_TOKEN_AT,             /* @  (Phase 4) */

    /* literals */
    PHP_CEDAR_TOKEN_STRING,         /* "..." */
    PHP_CEDAR_TOKEN_NUMBER,         /* [0-9]+ */
    PHP_CEDAR_TOKEN_IDENT,          /* identifier */

    /* special */
    PHP_CEDAR_TOKEN_EOF,
    PHP_CEDAR_TOKEN_ERROR
} php_cedar_token_type_t;


/* --- token --- */

typedef struct {
    php_cedar_token_type_t  type;
    php_cedar_str_t               value;      /* string representation */
    php_cedar_str_t               raw;        /* raw source for STRING tokens
                                           (used by like pattern compiler) */
    php_cedar_flag_t              has_star_escape;  /* 1 if \* found in string */
} php_cedar_token_t;


/* --- binary operators --- */

typedef enum {
    PHP_CEDAR_OP_EQ,                /* == */
    PHP_CEDAR_OP_NE,                /* != */
    PHP_CEDAR_OP_AND,               /* && */
    PHP_CEDAR_OP_OR,                /* || */
    PHP_CEDAR_OP_IN,                /* in */
    PHP_CEDAR_OP_LT,               /* <  (Phase 2) */
    PHP_CEDAR_OP_GT,               /* >  (Phase 2) */
    PHP_CEDAR_OP_LE,               /* <= (Phase 2) */
    PHP_CEDAR_OP_GE,               /* >= (Phase 2) */
    PHP_CEDAR_OP_PLUS,             /* +  (Phase 4) */
    PHP_CEDAR_OP_MINUS,            /* -  (Phase 4) */
    PHP_CEDAR_OP_MUL               /* *  (Phase 4) */
} php_cedar_op_t;


/* --- variable types --- */

typedef enum {
    PHP_CEDAR_VAR_PRINCIPAL = 0,
    PHP_CEDAR_VAR_ACTION    = 1,
    PHP_CEDAR_VAR_RESOURCE  = 2,
    PHP_CEDAR_VAR_CONTEXT   = 3
} php_cedar_var_type_t;


/* --- AST node types --- */

typedef enum {
    /* literals */
    PHP_CEDAR_NODE_BOOL_LIT,        /* true / false */
    PHP_CEDAR_NODE_STRING_LIT,      /* "..." */
    PHP_CEDAR_NODE_LONG_LIT,        /* integer */
    PHP_CEDAR_NODE_ENTITY_REF,      /* Type::"id" */
    PHP_CEDAR_NODE_SET,             /* [expr, ...] */

    /* variables */
    PHP_CEDAR_NODE_VAR,             /* principal, action, resource, context */

    /* operations */
    PHP_CEDAR_NODE_ATTR_ACCESS,     /* expr.ident */
    PHP_CEDAR_NODE_BINOP,           /* ==, !=, <, >, <=, >=, &&, ||, in,
                                     +, -, * (Phase 4) */
    PHP_CEDAR_NODE_UNOP,            /* ! */
    PHP_CEDAR_NODE_NEGATE,          /* - (unary) */

    /* Phase 2 */
    PHP_CEDAR_NODE_HAS,             /* expr has ident */
    PHP_CEDAR_NODE_LIKE,            /* expr like "pattern" */
    PHP_CEDAR_NODE_IF_THEN_ELSE,    /* if expr then expr else expr */
    PHP_CEDAR_NODE_METHOD_CALL,     /* expr.method(args) */

    /* Phase 3 */
    PHP_CEDAR_NODE_IP_LITERAL,      /* ip("addr") */
    PHP_CEDAR_NODE_DECIMAL_LITERAL, /* decimal("1.23") */

    /* Phase 4 */
    PHP_CEDAR_NODE_IS,              /* expr is type_name [in expr] */
    PHP_CEDAR_NODE_RECORD           /* { key: expr, ... } */
} php_cedar_node_type_t;


/* --- AST node --- */

typedef struct php_cedar_node_s php_cedar_node_t;

/* parse-time record literal entry (key and value expression) */
typedef struct {
    php_cedar_str_t         key;
    php_cedar_node_t *value;
} php_cedar_record_entry_t;

struct php_cedar_node_s {
    php_cedar_node_type_t  type;
    union {
        php_cedar_flag_t  bool_val;                   /* BOOL_LIT */
        php_cedar_str_t   string_val;                 /* STRING_LIT, LIKE pattern */
        int64_t     long_val;                   /* LONG_LIT (Cedar i64) */

        struct {                                /* ENTITY_REF */
            php_cedar_str_t  entity_type;
            php_cedar_str_t  entity_id;
        } entity_ref;

        php_cedar_var_type_t  var_type;         /* VAR */

        struct {                                /* ATTR_ACCESS */
            php_cedar_node_t *object;
            php_cedar_str_t         attr;
        } attr_access;

        struct {                                /* BINOP */
            php_cedar_uint_t        op;               /* php_cedar_op_t */
            php_cedar_node_t *left;
            php_cedar_node_t *right;
        } binop;

        struct {                                /* UNOP */
            php_cedar_node_t *operand;
        } unop;

        php_cedar_array_t *set_elts;                  /* SET: array of
                                                        php_cedar_node_t* */

        struct {                                /* HAS */
            php_cedar_node_t *object;
            php_cedar_str_t         attr;
        } has;

        struct {                                /* LIKE */
            php_cedar_node_t *object;
            php_cedar_str_t         pattern;
        } like;

        struct {                                /* IF_THEN_ELSE */
            php_cedar_node_t *cond;
            php_cedar_node_t *then_expr;
            php_cedar_node_t *else_expr;
        } if_then_else;

        struct {                                /* METHOD_CALL */
            php_cedar_node_t *object;
            php_cedar_str_t         method;           /* "containsAll",
                                                   "containsAny",
                                                   "contains",
                                                   "isInRange",
                                                   "isIpv4", "isIpv6",
                                                   "isLoopback",
                                                   "isMulticast",
                                                   "lessThan",
                                                   "lessThanOrEqual",
                                                   "greaterThan",
                                                   "greaterThanOrEqual" */
            php_cedar_node_t *arg;              /* NULL for zero-arg
                                                   methods (isIpv4 etc.) */
        } method_call;

        struct {                                /* IP_LITERAL */
            php_cedar_str_t  addr;
        } ip_literal;

        struct {                                /* DECIMAL_LITERAL */
            php_cedar_str_t  text;
        } decimal_literal;

        struct {                                /* IS (Phase 4) */
            php_cedar_node_t *object;           /* expression under test */
            php_cedar_str_t         entity_type;      /* type_name
                                                   ("User", "Ns::User", ...) */
            php_cedar_node_t *in_entity;        /* "is T in expr" expr,
                                                   NULL if plain "is T" */
        } is_check;

        php_cedar_array_t *record_entries;            /* RECORD: array of
                                                        php_cedar_record_entry_t */
    } u;
};


/* --- policy structures --- */

/* scope constraint type */
typedef enum {
    PHP_CEDAR_SCOPE_NONE,           /* no constraint (matches all) */
    PHP_CEDAR_SCOPE_EQ,             /* == entity_ref */
    PHP_CEDAR_SCOPE_IN,             /* in entity_ref | set */
    PHP_CEDAR_SCOPE_IS,             /* is type_name (Phase 4) */
    PHP_CEDAR_SCOPE_IS_IN           /* is type_name in entity_ref
                                       (Phase 4) */
} php_cedar_scope_constraint_t;

/* scope constraint */
typedef struct {
    php_cedar_scope_constraint_t  constraint;
    php_cedar_node_t             *target;   /* entity_ref or set
                                               (NULL if NONE, IS) */
    php_cedar_str_t                     entity_type;  /* type_name (IS, IS_IN
                                                   only; empty otherwise) */
} php_cedar_scope_t;

/* annotation (Phase 4) */
typedef struct {
    php_cedar_str_t  key;                     /* annotation name (e.g. "id", "advice") */
    php_cedar_str_t  value;                   /* annotation value; empty if valueless */
} php_cedar_annotation_t;

/* condition clause */
typedef struct {
    unsigned          is_unless:1;          /* 0 = when, 1 = unless */
    php_cedar_node_t *expr;
} php_cedar_condition_t;

/* single policy */
typedef struct {
    unsigned           is_forbid:1;         /* 0 = permit, 1 = forbid */
    php_cedar_array_t       *annotations;         /* array of php_cedar_annotation_t
                                               (Phase 4, NULL if none) */
    php_cedar_scope_t  principal;
    php_cedar_scope_t  action;
    php_cedar_scope_t  resource;
    php_cedar_array_t       *conditions;          /* array of
                                               php_cedar_condition_t */
} php_cedar_policy_t;

/* policy set */
typedef struct {
    php_cedar_array_t *policies;                  /* array of php_cedar_policy_t */
} php_cedar_policy_set_t;


/*
 * Diagnostic detail returned by php_cedar_eval_detail().
 *
 * `policies` points to the subset of policies that produced the
 * decision: every matching `forbid` when the decision is DENY because
 * at least one `forbid` matched, or every matching `permit` when the
 * decision is ALLOW. For a default-deny outcome (no policy matched)
 * `policies` is NULL and `npolicies` is 0.
 *
 * Each entry is a pointer to a policy inside the input
 * `php_cedar_policy_set_t`; the caller must not reference them past
 * the lifetime of that policy set (or of the evaluation pool used to
 * allocate the pointer array).
 *
 * `errored` / `nerrored` are reserved for policies whose conditions
 * produced an evaluation error. They are unused in the current
 * implementation (always NULL / 0) and reserved for a future revision.
 */
typedef struct {
    php_cedar_policy_t **policies;
    php_cedar_uint_t           npolicies;
    php_cedar_policy_t **errored;
    php_cedar_uint_t           nerrored;
} php_cedar_decision_detail_t;


/* --- evaluation context --- */

/*
 * Parser member-chain limit. Caps `expr.a.b.c...` to this many `.ident`
 * or `["key"]` steps. Shared with the record-value nesting limit below
 * so the parser's reachable depth and the writable record depth stay
 * in sync (bumping one automatically bumps the other).
 */
#define PHP_CEDAR_MAX_MEMBER_CHAIN 16

/*
 * Record-value nesting limit. Defined as PHP_CEDAR_MAX_MEMBER_CHAIN so
 * no record value can be created at a depth that policy text cannot
 * reference: a depth-N record is the value returned by an N-step member
 * chain, and the parser caps that chain at PHP_CEDAR_MAX_MEMBER_CHAIN.
 * Note that reading a scalar (or sub-record) inside a depth-N record
 * takes N+1 steps, so scalar fields placed directly inside a
 * depth-PHP_CEDAR_MAX_RECORD_DEPTH record are writable but unreachable
 * from any policy. Keep deep scalars one level above the limit.
 */
#define PHP_CEDAR_MAX_RECORD_DEPTH PHP_CEDAR_MAX_MEMBER_CHAIN

/*
 * Set-value nesting limit. Mirrors PHP_CEDAR_MAX_RECORD_DEPTH so a
 * value graph mixing nested records and sets shares one depth ceiling,
 * preventing unbounded recursion in `==` and other value walks.
 */
#define PHP_CEDAR_MAX_SET_DEPTH PHP_CEDAR_MAX_RECORD_DEPTH

/*
 * Independent recursion limit for php_cedar_value_equals(). The function
 * recurses into nested set/record elements without going through
 * php_cedar_expr_eval(), so ctx->eval_depth does not protect it. In
 * practice the structural caps on injected values (MAX_RECORD_DEPTH and
 * MAX_SET_DEPTH) and the parser's MAX_PARSE_DEPTH already bound the
 * graph, but value_equals deserves its own ceiling as a defense-in-depth
 * measure so the safety of one recursive walk is not load-bearing on
 * invariants enforced elsewhere. The sum of MAX_RECORD_DEPTH and
 * MAX_SET_DEPTH (=32) is the worst case for an alternating record/set
 * chain at the injection-API ceiling.
 */
#define PHP_CEDAR_MAX_VALUE_EQUALS_DEPTH \
        (PHP_CEDAR_MAX_RECORD_DEPTH + PHP_CEDAR_MAX_SET_DEPTH)

/*
 * Expression-evaluation recursion limit. AST shape is already bounded
 * by the parser (PHP_CEDAR_MAX_PARSE_DEPTH, MAX_MEMBER_CHAIN,
 * MAX_BINOP_CHAIN), but recursive walks during evaluation can stack
 * AST depth on top of attribute lookups and method-call dispatch, so
 * an evaluator-side ceiling is needed too. Each entry into
 * php_cedar_expr_eval() increments ctx->eval_depth; once the count
 * reaches the limit further entries short-circuit to RVAL_ERROR.
 * 128 gives ~2x the parser's PHP_CEDAR_MAX_PARSE_DEPTH (64) so any
 * AST the parser accepts evaluates without spuriously hitting the
 * cap, while keeping recursion well under typical thread stack sizes.
 */
#define PHP_CEDAR_MAX_EVAL_DEPTH 128


/* --- runtime values --- */

/* runtime value types */
#define PHP_CEDAR_RVAL_STRING   0
#define PHP_CEDAR_RVAL_LONG     1
#define PHP_CEDAR_RVAL_BOOL     2
#define PHP_CEDAR_RVAL_ENTITY   3
#define PHP_CEDAR_RVAL_SET      4
#define PHP_CEDAR_RVAL_ERROR    5
#define PHP_CEDAR_RVAL_IP       6
#define PHP_CEDAR_RVAL_RECORD   7
#define PHP_CEDAR_RVAL_DECIMAL  8


/*
 * Origin tag on entity values. NONE is the default for derived entities
 * (literals, attribute lookups, set elements) and must compare equal to
 * zero so php_cedar_memzero-initialized values inherit it. PRINCIPAL / ACTION
 * / RESOURCE are stamped only when the value is produced by evaluating
 * the corresponding PHP_CEDAR_NODE_VAR. The slot lets `in` evaluation
 * pick the matching parents array even when principal / action /
 * resource share the same (type, id) — looking up by identity alone
 * collapses on collisions and silently picks the first slot.
 */
#define PHP_CEDAR_ENTITY_SLOT_NONE      0
#define PHP_CEDAR_ENTITY_SLOT_PRINCIPAL 1
#define PHP_CEDAR_ENTITY_SLOT_ACTION    2
#define PHP_CEDAR_ENTITY_SLOT_RESOURCE  3


typedef struct {
    php_cedar_uint_t  type;       /* PHP_CEDAR_RVAL_* */
    union {
        php_cedar_str_t   str_val;
        int64_t     long_val;    /* Cedar i64 runtime value */
        php_cedar_flag_t  bool_val;
        struct {
            php_cedar_str_t   type;
            php_cedar_str_t   id;
            php_cedar_uint_t  slot;    /* PHP_CEDAR_ENTITY_SLOT_* */
        } entity;
        php_cedar_array_t *set_elts;     /* array of php_cedar_value_t */
        php_cedar_array_t *record_attrs; /* array of php_cedar_attr_t */
        struct {
            unsigned char      addr[16];    /* network byte order */
            php_cedar_uint_t  prefix_len;  /* /prefix; single=32(v4)/128(v6) */
            unsigned    is_ipv6   :1;
        } ip_addr;
        /*
         * Cedar decimal: fixed-point i64 with implicit scale 10^4.
         * "1.23" is stored as 12300, "-0.5" as -5000, "0.0001" as 1.
         * Holds the full int64_t range; the parser rejects inputs whose
         * scaled value would overflow.
         */
        int64_t  decimal_val;
    } v;
} php_cedar_value_t;


/*
 * Named runtime value used both as an entity attribute (principal /
 * action / resource / context) and as a record entry.
 */
typedef struct {
    php_cedar_str_t          name;
    php_cedar_value_t  value;
} php_cedar_attr_t;


/*
 * Entity reference used to record ancestors / group memberships in the
 * evaluation context. Callers supply the transitive closure (including
 * indirect ancestors) as a flat list; `in` checks are reflexive.
 */
typedef struct {
    php_cedar_str_t  type;
    php_cedar_str_t  id;
} php_cedar_entity_ref_t;


/* evaluation context (built per-request) */
typedef struct {
    php_cedar_pool_t  *pool;

    /* principal */
    php_cedar_str_t    principal_type;
    php_cedar_str_t    principal_id;
    php_cedar_array_t *principal_attrs;            /* array of php_cedar_attr_t */
    php_cedar_array_t *principal_parents;          /* array of
                                                php_cedar_entity_ref_t */

    /* action */
    php_cedar_str_t    action_type;
    php_cedar_str_t    action_id;
    php_cedar_array_t *action_attrs;              /* array of php_cedar_attr_t */
    php_cedar_array_t *action_parents;            /* array of
                                               php_cedar_entity_ref_t */

    /* resource */
    php_cedar_str_t    resource_type;
    php_cedar_str_t    resource_id;
    php_cedar_array_t *resource_attrs;             /* array of php_cedar_attr_t */
    php_cedar_array_t *resource_parents;           /* array of
                                                php_cedar_entity_ref_t */

    /* context */
    php_cedar_array_t *context_attrs;              /* array of php_cedar_attr_t */

    /*
     * Recursion guard for php_cedar_expr_eval(). Incremented at entry
     * and decremented at exit; the entry guard returns an RVAL_ERROR
     * value before recursing further when the count would exceed
     * PHP_CEDAR_MAX_EVAL_DEPTH.
     */
    php_cedar_uint_t  eval_depth;
} php_cedar_eval_ctx_t;


#endif /* PHP_CEDAR_TYPES_H */
