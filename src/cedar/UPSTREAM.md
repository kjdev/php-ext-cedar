# Upstream provenance of the Cedar evaluator sources

The files under `src/cedar/` (with the exception of `php_cedar_compat.h`
and `php_cedar_compat.c`, which are written for this extension) are a
physical snapshot of the **nxe-cedar** project, rewritten so that the
symbols and dependencies fit a PHP extension.

## Snapshot commit

- Upstream repository: <https://github.com/kjdev/nxe-cedar>
- Commit SHA: `cd3d1df5c5642a75b27f40fa502022c864272ed3`
- Source path: `src/`
- Snapshot date: 2026-05-27

## File mapping

| upstream | php-ext-cedar |
| --- | --- |
| `src/nxe_cedar_eval.c`   | `src/cedar/php_cedar_eval.c` |
| `src/nxe_cedar_eval.h`   | `src/cedar/php_cedar_eval.h` |
| `src/nxe_cedar_expr.c`   | `src/cedar/php_cedar_expr.c` |
| `src/nxe_cedar_expr.h`   | `src/cedar/php_cedar_expr.h` |
| `src/nxe_cedar_lexer.c`  | `src/cedar/php_cedar_lexer.c` |
| `src/nxe_cedar_lexer.h`  | `src/cedar/php_cedar_lexer.h` |
| `src/nxe_cedar_parser.c` | `src/cedar/php_cedar_parser.c` |
| `src/nxe_cedar_parser.h` | `src/cedar/php_cedar_parser.h` |
| `src/nxe_cedar_types.h`  | `src/cedar/php_cedar_types.h` |
| `src/nxe_cedar_util.h`   | `src/cedar/php_cedar_util.h` |

## Mechanical rewrites applied on import

1. Symbol prefixes
   - `nxe_cedar_*` → `php_cedar_*`
   - `NXE_CEDAR_*` → `PHP_CEDAR_*`
2. File names
   - `nxe_cedar_*` → `php_cedar_*`
3. NGINX type and function dependencies removed (via `php_cedar_compat.h`)
   - `ngx_pool_t / ngx_str_t / ngx_array_t / ngx_log_t / ngx_int_t / ngx_uint_t` → `php_cedar_*` equivalents
   - `ngx_palloc / ngx_pcalloc / ngx_array_create / ngx_array_push / ngx_log_error` → `php_cedar_*` equivalents
   - `NGX_OK / NGX_ERROR / NGX_DECLINED` → `PHP_CEDAR_OK / PHP_CEDAR_ERROR / PHP_CEDAR_DECLINED`
4. Memory management is rebased onto the Zend Memory Manager (`emalloc / efree`)

The evaluation engine itself (lexer, parser, expression evaluator) is
**not modified** — keeping logic identical to upstream avoids reintroducing
bugs and makes diffing easier when re-syncing. When a logic change is
needed, it should go to upstream first and come back via a fresh import.

## Sync policy

- No automatic sync. Submodules / subtree are deliberately avoided.
- Re-import on demand: roughly once or twice a year, or whenever upstream
  adds something material to the Cedar surface (new data types, new
  evaluator capabilities, etc.).
- Re-import procedure:
  1. Review the upstream diff (`git log <old SHA>..<new SHA> -- src/`).
  2. Apply the diff to this directory with the symbol rewrites already
     in place.
  3. Update the "Snapshot commit" section above.
  4. Run the test suite.

## Capabilities inherited from upstream (and gaps)

The features below follow whatever the snapshot supports; gaps listed
here are upstream limitations that this extension does **not** plug:

- No `datetime` / `duration` types or their methods
- No entity tag operators (`hasTag` / `getTag`)
- No policy templates (`?principal`, `?resource`)
- No schema validation
- No dynamic external entity store resolution

The README of this extension carries the user-facing version of this
list; this file documents the upstream provenance side.
