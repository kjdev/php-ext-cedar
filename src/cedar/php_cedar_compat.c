/*
 * Implementation for the function bodies declared in
 * php_cedar_compat.h (pool / array / log).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_cedar_compat.h"

#include <stdarg.h>
#include <stdio.h>

#ifdef PHP_CEDAR_USE_ZEND_MM
#  include "php.h"
#  define PHP_CEDAR_MALLOC(sz)     emalloc(sz)
#  define PHP_CEDAR_FREE(ptr)      efree(ptr)
#else
#  include <stdlib.h>
#  define PHP_CEDAR_MALLOC(sz)     malloc(sz)
#  define PHP_CEDAR_FREE(ptr)      free(ptr)
#endif

/* ---- pool ------------------------------------------------------------ */

php_cedar_pool_t *
php_cedar_pool_create(php_cedar_log_t *log)
{
    php_cedar_pool_t *p = (php_cedar_pool_t *) PHP_CEDAR_MALLOC(sizeof(*p));
    if (p == NULL) {
        return NULL;
    }
    p->chunks = NULL;
    p->log    = log;
    return p;
}

void
php_cedar_pool_destroy(php_cedar_pool_t *pool)
{
    php_cedar_pool_chunk_t *c, *next;

    if (pool == NULL) {
        return;
    }
    for (c = pool->chunks; c != NULL; c = next) {
        next = c->next;
        PHP_CEDAR_FREE(c->data);
        PHP_CEDAR_FREE(c);
    }
    PHP_CEDAR_FREE(pool);
}

void *
php_cedar_palloc(php_cedar_pool_t *pool, size_t size)
{
    php_cedar_pool_chunk_t *c;

    if (pool == NULL || size == 0) {
        return NULL;
    }
    c = (php_cedar_pool_chunk_t *) PHP_CEDAR_MALLOC(sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    c->data = PHP_CEDAR_MALLOC(size);
    if (c->data == NULL) {
        PHP_CEDAR_FREE(c);
        return NULL;
    }
    c->next      = pool->chunks;
    pool->chunks = c;
    return c->data;
}

void *
php_cedar_pcalloc(php_cedar_pool_t *pool, size_t size)
{
    void *p = php_cedar_palloc(pool, size);
    if (p != NULL) {
        memset(p, 0, size);
    }
    return p;
}

/* ---- array ----------------------------------------------------------- */

php_cedar_array_t *
php_cedar_array_create(php_cedar_pool_t *pool,
                       php_cedar_uint_t n, size_t size)
{
    php_cedar_array_t *a;

    if (pool == NULL || n == 0 || size == 0) {
        return NULL;
    }
    if ((size_t) n > SIZE_MAX / size) {
        return NULL; /* n * size would overflow */
    }
    a = (php_cedar_array_t *) php_cedar_palloc(pool, sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
    a->elts = php_cedar_palloc(pool, (size_t) n * size);
    if (a->elts == NULL) {
        return NULL;
    }
    a->nelts  = 0;
    a->size   = size;
    a->nalloc = n;
    a->pool   = pool;
    return a;
}

void *
php_cedar_array_push(php_cedar_array_t *a)
{
    void *elt;

    if (a == NULL) {
        return NULL;
    }
    if (a->nelts == a->nalloc) {
        php_cedar_uint_t new_alloc = a->nalloc * 2;
        void            *new_elts;

        if (new_alloc <= a->nalloc) {
            return NULL; /* nalloc * 2 wrapped around */
        }
        if ((size_t) new_alloc > SIZE_MAX / a->size) {
            return NULL; /* new_alloc * size would overflow */
        }
        new_elts = php_cedar_palloc(a->pool, (size_t) new_alloc * a->size);
        if (new_elts == NULL) {
            return NULL;
        }
        memcpy(new_elts, a->elts, (size_t) a->nelts * a->size);
        a->elts   = new_elts;
        a->nalloc = new_alloc;
    }
    elt = (char *) a->elts + a->size * a->nelts;
    a->nelts++;
    return elt;
}

/* ---- log ------------------------------------------------------------- */

void
php_cedar_log_error(int level, php_cedar_log_t *log,
                    int err, const char *fmt, ...)
{
    char    buf[1024];
    va_list ap;

    if (log != NULL && level > log->level) {
        return;
    }
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

#ifdef PHP_CEDAR_USE_ZEND_MM
    {
        int e = (level <= PHP_CEDAR_LOG_ERR) ? E_WARNING : E_NOTICE;
        if (err) {
            php_error_docref(NULL, e, "%s (errno=%d)", buf, err);
        } else {
            php_error_docref(NULL, e, "%s", buf);
        }
    }
#else
    if (err) {
        fprintf(stderr, "[cedar] %s (errno=%d)\n", buf, err);
    } else {
        fprintf(stderr, "[cedar] %s\n", buf);
    }
#endif
}
