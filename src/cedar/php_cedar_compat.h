/*
 * NGINX type / function compatibility layer.
 *
 * The sources copied from nxe-cedar (the NGINX-edge Cedar evaluator)
 * depend on NGINX symbols such as ngx_pool_t / ngx_str_t /
 * ngx_log_error. This header replaces them with PHP-extension-friendly
 * equivalents.
 *
 * Memory management switches to the Zend Memory Manager
 * (emalloc/efree) when PHP_CEDAR_USE_ZEND_MM is defined at build time
 * (the extension build sets it via config.m4); otherwise it falls
 * back to the standard C allocator (malloc/free).
 */

#ifndef PHP_CEDAR_COMPAT_H
#define PHP_CEDAR_COMPAT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- Return codes (NGINX-compatible) --------------------------------- */
#define PHP_CEDAR_OK         0
#define PHP_CEDAR_ERROR     -1
#define PHP_CEDAR_DECLINED  -5

/* ---- Log levels (NGINX-compatible numbering) ------------------------- */
#define PHP_CEDAR_LOG_EMERG   1
#define PHP_CEDAR_LOG_ALERT   2
#define PHP_CEDAR_LOG_CRIT    3
#define PHP_CEDAR_LOG_ERR     4
#define PHP_CEDAR_LOG_WARN    5
#define PHP_CEDAR_LOG_NOTICE  6
#define PHP_CEDAR_LOG_INFO    7
#define PHP_CEDAR_LOG_DEBUG   8

/* ---- Integer types --------------------------------------------------- */
typedef intptr_t   php_cedar_int_t;
typedef uintptr_t  php_cedar_uint_t;
typedef intptr_t   php_cedar_flag_t;

/* ---- String type ----------------------------------------------------- */
typedef struct {
    size_t          len;
    unsigned char  *data;
} php_cedar_str_t;

#define php_cedar_null_string  { 0, NULL }
#define php_cedar_string(s)    { sizeof(s) - 1, (unsigned char *) s }

/* ---- Memory helpers -------------------------------------------------- */
#define php_cedar_memcmp(s1, s2, n)   memcmp((s1), (s2), (n))
#define php_cedar_memcpy(dst, src, n) memcpy((dst), (src), (n))
#define php_cedar_memzero(buf, n)     memset((buf), 0, (n))

/* ---- Log context ----------------------------------------------------- */
typedef struct {
    int level;        /* lower bound; messages with a larger level are dropped */
    void *handler;    /* reserved: a future hook for routing to PHP's error log */
} php_cedar_log_t;

void php_cedar_log_error(int level, php_cedar_log_t *log,
                         int err, const char *fmt, ...);

/* ---- Memory pool ----------------------------------------------------- *
 * Behaves like NGINX's ngx_pool_t: palloc/pcalloc grow the arena and
 * pool_destroy frees everything at once. Backed by a singly-linked
 * list of emalloc chunks.
 */
typedef struct php_cedar_pool_chunk_s {
    struct php_cedar_pool_chunk_s *next;
    void                          *data;
} php_cedar_pool_chunk_t;

typedef struct {
    php_cedar_pool_chunk_t *chunks;
    php_cedar_log_t        *log;     /* optional; may be NULL */
} php_cedar_pool_t;

php_cedar_pool_t *php_cedar_pool_create(php_cedar_log_t *log);
void              php_cedar_pool_destroy(php_cedar_pool_t *pool);

void *php_cedar_palloc(php_cedar_pool_t *pool, size_t size);
void *php_cedar_pcalloc(php_cedar_pool_t *pool, size_t size);

/* ---- Dynamic array --------------------------------------------------- */
typedef struct {
    void              *elts;
    php_cedar_uint_t   nelts;
    size_t             size;
    php_cedar_uint_t   nalloc;
    php_cedar_pool_t  *pool;
} php_cedar_array_t;

php_cedar_array_t *php_cedar_array_create(php_cedar_pool_t *pool,
                                          php_cedar_uint_t n, size_t size);
void              *php_cedar_array_push(php_cedar_array_t *a);

#endif /* PHP_CEDAR_COMPAT_H */
