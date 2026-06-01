/*
 * Copyright (c) Tatsuya Kamijo
 * Copyright (c) Bengo4.com, Inc.
 *
 * php_cedar_lexer.c - Cedar policy text tokenizer
 *
 * Converts input string to a token stream.
 * php_cedar_str_t is not NUL-terminated; always check bounds with pos < input.len.
 */

#include "php_cedar_compat.h"
#include "php_cedar_lexer.h"


/* keyword table entry */
typedef struct {
    php_cedar_str_t               name;
    php_cedar_token_type_t  type;
} php_cedar_keyword_t;


static php_cedar_keyword_t php_cedar_keywords[] = {
    { php_cedar_string("permit"),    PHP_CEDAR_TOKEN_PERMIT },
    { php_cedar_string("forbid"),    PHP_CEDAR_TOKEN_FORBID },
    { php_cedar_string("when"),      PHP_CEDAR_TOKEN_WHEN },
    { php_cedar_string("unless"),    PHP_CEDAR_TOKEN_UNLESS },
    { php_cedar_string("principal"), PHP_CEDAR_TOKEN_PRINCIPAL },
    { php_cedar_string("action"),    PHP_CEDAR_TOKEN_ACTION },
    { php_cedar_string("resource"),  PHP_CEDAR_TOKEN_RESOURCE },
    { php_cedar_string("context"),   PHP_CEDAR_TOKEN_CONTEXT },
    { php_cedar_string("true"),      PHP_CEDAR_TOKEN_TRUE },
    { php_cedar_string("false"),     PHP_CEDAR_TOKEN_FALSE },
    { php_cedar_string("in"),        PHP_CEDAR_TOKEN_IN },
    { php_cedar_string("if"),        PHP_CEDAR_TOKEN_IF },
    { php_cedar_string("then"),      PHP_CEDAR_TOKEN_THEN },
    { php_cedar_string("else"),      PHP_CEDAR_TOKEN_ELSE },
    { php_cedar_string("has"),       PHP_CEDAR_TOKEN_HAS },
    { php_cedar_string("like"),      PHP_CEDAR_TOKEN_LIKE },
    { php_cedar_string("ip"),        PHP_CEDAR_TOKEN_IP },
    { php_cedar_string("decimal"),   PHP_CEDAR_TOKEN_DECIMAL },
    { php_cedar_string("is"),        PHP_CEDAR_TOKEN_IS },
    { php_cedar_null_string,         0 }
};


static void
php_cedar_lexer_skip_whitespace(php_cedar_lexer_t *lexer)
{
    unsigned char ch;

    for ( ;; ) {
        if (lexer->pos >= lexer->input.len) {
            return;
        }

        ch = lexer->input.data[lexer->pos];

        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') {
            lexer->pos++;
            continue;
        }

        /* // line comment */
        if (ch == '/'
            && lexer->pos + 1 < lexer->input.len
            && lexer->input.data[lexer->pos + 1] == '/')
        {
            lexer->pos += 2;

            while (lexer->pos < lexer->input.len
                   && lexer->input.data[lexer->pos] != '\n')
            {
                lexer->pos++;
            }

            if (lexer->pos < lexer->input.len) {
                lexer->pos++;  /* skip \n */
            }

            continue;
        }

        return;
    }
}


static php_cedar_int_t
php_cedar_hex_value(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }

    return -1;
}


static php_cedar_uint_t
php_cedar_utf8_encode(php_cedar_uint_t cp, unsigned char *dst)
{
    if (cp <= 0x7F) {
        dst[0] = (unsigned char) cp;
        return 1;
    }

    if (cp <= 0x7FF) {
        dst[0] = (unsigned char) (0xC0 | (cp >> 6));
        dst[1] = (unsigned char) (0x80 | (cp & 0x3F));
        return 2;
    }

    if (cp <= 0xFFFF) {
        dst[0] = (unsigned char) (0xE0 | (cp >> 12));
        dst[1] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
        dst[2] = (unsigned char) (0x80 | (cp & 0x3F));
        return 3;
    }

    /* cp <= 0x10FFFF */
    dst[0] = (unsigned char) (0xF0 | (cp >> 18));
    dst[1] = (unsigned char) (0x80 | ((cp >> 12) & 0x3F));
    dst[2] = (unsigned char) (0x80 | ((cp >> 6) & 0x3F));
    dst[3] = (unsigned char) (0x80 | (cp & 0x3F));
    return 4;
}


/*
 * Decode one escape sequence after the backslash.
 * *src points to the character after '\' (e.g. 'n' for \n).
 * On success: advances *src past the sequence, writes decoded bytes
 * to *dst, and returns PHP_CEDAR_OK.
 * On error: returns PHP_CEDAR_ERROR (*src and *dst are undefined).
 * reject_xff: if set, reject \xFF (0xFF reserved as wildcard marker).
 */
php_cedar_int_t
php_cedar_decode_escape(unsigned char **src, unsigned char *src_end,
    unsigned char **dst, php_cedar_flag_t reject_xff)
{
    unsigned char *p, *d;

    p = *src;
    d = *dst;

    if (p >= src_end) {
        return PHP_CEDAR_ERROR;
    }

    switch (*p) {
    case '"':
        *d++ = '"';
        p++;
        break;
    case '\\':
        *d++ = '\\';
        p++;
        break;
    case 'n':
        *d++ = '\n';
        p++;
        break;
    case 'r':
        *d++ = '\r';
        p++;
        break;
    case 't':
        *d++ = '\t';
        p++;
        break;
    case '0':
        *d++ = '\0';
        p++;
        break;
    case 'x':
    {
        php_cedar_int_t h1, h2;
        unsigned char byte;

        if (p + 2 >= src_end) {
            return PHP_CEDAR_ERROR;
        }

        h1 = php_cedar_hex_value(p[1]);
        h2 = php_cedar_hex_value(p[2]);
        if (h1 < 0 || h2 < 0) {
            return PHP_CEDAR_ERROR;
        }

        byte = (unsigned char) (h1 * 16 + h2);

        if (reject_xff && byte == 0xFF) {
            return PHP_CEDAR_ERROR;
        }

        *d++ = byte;
        p += 3;
    }
    break;

    case 'u':
    {
        php_cedar_uint_t cp, n_digits, nbytes;
        php_cedar_int_t dig;

        if (p + 1 >= src_end || p[1] != '{') {
            return PHP_CEDAR_ERROR;
        }

        p += 2;  /* skip u{ */
        cp = 0;
        n_digits = 0;

        while (p < src_end && *p != '}') {
            dig = php_cedar_hex_value(*p);
            if (dig < 0) {
                return PHP_CEDAR_ERROR;
            }

            cp = cp * 16 + dig;
            n_digits++;

            if (n_digits > 6) {
                return PHP_CEDAR_ERROR;
            }

            p++;
        }

        if (p >= src_end || n_digits == 0) {
            return PHP_CEDAR_ERROR;
        }

        if (cp > 0x10FFFF
            || (cp >= 0xD800 && cp <= 0xDFFF))
        {
            return PHP_CEDAR_ERROR;
        }

        /*
         * UTF-8 encoding never produces byte 0xFF (max leading byte
         * is 0xF4), so this cannot inject wildcard markers into
         * like patterns even without an explicit reject_xff check.
         */
        nbytes = php_cedar_utf8_encode(cp, d);
        d += nbytes;
        p++;  /* skip '}' */
    }
    break;

    default:
        return PHP_CEDAR_ERROR;
    }

    *src = p;
    *dst = d;
    return PHP_CEDAR_OK;
}


static php_cedar_token_t
php_cedar_lexer_read_string(php_cedar_lexer_t *lexer)
{
    php_cedar_token_t token;
    size_t start, len;
    unsigned char *dst;
    php_cedar_uint_t has_escape;

    /* skip opening quote */
    lexer->pos++;
    start = lexer->pos;
    has_escape = 0;

    while (lexer->pos < lexer->input.len) {
        if (lexer->input.data[lexer->pos] == '\\') {
            has_escape = 1;

            if (lexer->pos + 1 >= lexer->input.len) {
                /* trailing backslash without following char */
                lexer->pos++;
                break;
            }

            lexer->pos += 2;
            continue;
        }

        if (lexer->input.data[lexer->pos] == '"') {
            break;
        }

        lexer->pos++;
    }

    if (lexer->pos >= lexer->input.len) {
        token.type = PHP_CEDAR_TOKEN_ERROR;
        token.value.data = (unsigned char *) "unterminated string";
        token.value.len = 19;
        token.raw.data = NULL;
        token.raw.len = 0;
        token.has_star_escape = 0;
        return token;
    }

    /* content between quotes */
    len = lexer->pos - start;
    lexer->pos++;  /* skip closing quote */

    token.type = PHP_CEDAR_TOKEN_STRING;
    token.raw.data = &lexer->input.data[start];
    token.raw.len = len;
    token.has_star_escape = 0;

    if (!has_escape) {
        token.value.data = &lexer->input.data[start];
        token.value.len = len;
        return token;
    }

    /* unescape into pool-allocated buffer */
    dst = php_cedar_palloc(lexer->pool, len);
    if (dst == NULL) {
        token.type = PHP_CEDAR_TOKEN_ERROR;
        token.value.data = (unsigned char *) "alloc failed";
        token.value.len = 12;
        token.has_star_escape = 0;
        return token;
    }

    token.value.data = dst;

    {
        unsigned char *sp, *sp_end;

        sp = &lexer->input.data[start];
        sp_end = sp + len;

        while (sp < sp_end) {
            if (*sp == '\\' && sp + 1 < sp_end) {
                sp++;  /* skip backslash */

                /*
                 * \* is only valid in like pattern strings, but the
                 * lexer cannot distinguish pattern from regular strings.
                 * Accept it here so the token is produced; the pattern
                 * compiler re-processes via token.raw anyway.
                 */
                if (*sp == '*') {
                    *dst++ = '*';
                    sp++;
                    token.has_star_escape = 1;
                } else if (php_cedar_decode_escape(&sp, sp_end,
                                                   &dst, 0)
                           != PHP_CEDAR_OK)
                {
                    token.type = PHP_CEDAR_TOKEN_ERROR;
                    token.value.data =
                        (unsigned char *) "invalid escape sequence";
                    token.value.len = 23;
                    return token;
                }

            } else {
                *dst++ = *sp++;
            }
        }
    }

    token.value.len = dst - token.value.data;

    return token;
}


static php_cedar_token_t
php_cedar_lexer_read_number(php_cedar_lexer_t *lexer)
{
    php_cedar_token_t token;
    size_t start;

    start = lexer->pos;

    while (lexer->pos < lexer->input.len
           && lexer->input.data[lexer->pos] >= '0'
           && lexer->input.data[lexer->pos] <= '9')
    {
        lexer->pos++;
    }

    token.type = PHP_CEDAR_TOKEN_NUMBER;
    token.value.data = &lexer->input.data[start];
    token.value.len = lexer->pos - start;
    token.raw.data = NULL;
    token.raw.len = 0;
    token.has_star_escape = 0;

    return token;
}


static php_cedar_token_t
php_cedar_lexer_read_ident(php_cedar_lexer_t *lexer)
{
    php_cedar_token_t token;
    php_cedar_keyword_t *kw;
    size_t start;
    php_cedar_uint_t len;

    start = lexer->pos;

    while (lexer->pos < lexer->input.len) {
        unsigned char ch = lexer->input.data[lexer->pos];

        if ((ch >= 'a' && ch <= 'z')
            || (ch >= 'A' && ch <= 'Z')
            || (ch >= '0' && ch <= '9')
            || ch == '_')
        {
            lexer->pos++;
        } else {
            break;
        }
    }

    len = lexer->pos - start;

    /* check keywords */
    for (kw = php_cedar_keywords; kw->name.len != 0; kw++) {
        if (kw->name.len == len
            && php_cedar_memcmp(kw->name.data,
                          &lexer->input.data[start], len) == 0)
        {
            token.type = kw->type;
            token.value.data = &lexer->input.data[start];
            token.value.len = len;
            token.raw.data = NULL;
            token.raw.len = 0;
            token.has_star_escape = 0;
            return token;
        }
    }

    token.type = PHP_CEDAR_TOKEN_IDENT;
    token.value.data = &lexer->input.data[start];
    token.value.len = len;
    token.raw.data = NULL;
    token.raw.len = 0;
    token.has_star_escape = 0;

    return token;
}


void
php_cedar_lexer_init(php_cedar_lexer_t *lexer,
    php_cedar_pool_t *pool, php_cedar_log_t *log, const php_cedar_str_t *input)
{
    lexer->input = *input;
    lexer->pos = 0;
    lexer->pool = pool;
    lexer->log = log;
}


php_cedar_token_t
php_cedar_lexer_next(php_cedar_lexer_t *lexer)
{
    php_cedar_token_t token;
    unsigned char ch;

    token.raw.data = NULL;
    token.raw.len = 0;
    token.has_star_escape = 0;

    php_cedar_lexer_skip_whitespace(lexer);

    if (lexer->pos >= lexer->input.len) {
        token.type = PHP_CEDAR_TOKEN_EOF;
        token.value.data = NULL;
        token.value.len = 0;
        return token;
    }

    ch = lexer->input.data[lexer->pos];

    /* string literal */
    if (ch == '"') {
        return php_cedar_lexer_read_string(lexer);
    }

    /* number literal */
    if (ch >= '0' && ch <= '9') {
        return php_cedar_lexer_read_number(lexer);
    }

    /* identifier or keyword */
    if ((ch >= 'a' && ch <= 'z')
        || (ch >= 'A' && ch <= 'Z')
        || ch == '_')
    {
        return php_cedar_lexer_read_ident(lexer);
    }

    /* two-character operators */
    if (ch == '=' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '=')
    {
        token.type = PHP_CEDAR_TOKEN_EQ;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == '!' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '=')
    {
        token.type = PHP_CEDAR_TOKEN_NE;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == '&' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '&')
    {
        token.type = PHP_CEDAR_TOKEN_AND;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == '|' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '|')
    {
        token.type = PHP_CEDAR_TOKEN_OR;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == ':' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == ':')
    {
        token.type = PHP_CEDAR_TOKEN_COLONCOLON;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == ':') {
        token.type = PHP_CEDAR_TOKEN_COLON;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 1;
        lexer->pos += 1;
        return token;
    }

    if (ch == '<' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '=')
    {
        token.type = PHP_CEDAR_TOKEN_LE;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    if (ch == '>' && lexer->pos + 1 < lexer->input.len
        && lexer->input.data[lexer->pos + 1] == '=')
    {
        token.type = PHP_CEDAR_TOKEN_GE;
        token.value.data = &lexer->input.data[lexer->pos];
        token.value.len = 2;
        lexer->pos += 2;
        return token;
    }

    /* single-character tokens */
    token.value.data = &lexer->input.data[lexer->pos];
    token.value.len = 1;
    lexer->pos++;

    switch (ch) {
    case '!':
        token.type = PHP_CEDAR_TOKEN_NOT;
        return token;
    case '-':
        token.type = PHP_CEDAR_TOKEN_MINUS;
        return token;
    case '+':
        token.type = PHP_CEDAR_TOKEN_PLUS;
        return token;
    case '*':
        token.type = PHP_CEDAR_TOKEN_STAR;
        return token;
    case '.':
        token.type = PHP_CEDAR_TOKEN_DOT;
        return token;
    case ',':
        token.type = PHP_CEDAR_TOKEN_COMMA;
        return token;
    case ';':
        token.type = PHP_CEDAR_TOKEN_SEMICOLON;
        return token;
    case '(':
        token.type = PHP_CEDAR_TOKEN_LPAREN;
        return token;
    case ')':
        token.type = PHP_CEDAR_TOKEN_RPAREN;
        return token;
    case '{':
        token.type = PHP_CEDAR_TOKEN_LBRACE;
        return token;
    case '}':
        token.type = PHP_CEDAR_TOKEN_RBRACE;
        return token;
    case '[':
        token.type = PHP_CEDAR_TOKEN_LBRACKET;
        return token;
    case ']':
        token.type = PHP_CEDAR_TOKEN_RBRACKET;
        return token;
    case '@':
        token.type = PHP_CEDAR_TOKEN_AT;
        return token;
    case '<':
        token.type = PHP_CEDAR_TOKEN_LT;
        return token;
    case '>':
        token.type = PHP_CEDAR_TOKEN_GT;
        return token;
    default:
        break;
    }

    token.type = PHP_CEDAR_TOKEN_ERROR;
    token.value.data = &lexer->input.data[lexer->pos - 1];
    token.value.len = 1;

    return token;
}
