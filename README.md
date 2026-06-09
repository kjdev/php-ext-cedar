# PHP Cedar Extension

A PHP extension that evaluates [Cedar](https://www.cedarpolicy.com/) policies
locally, with an API compatible with
[Amazon Verified Permissions (AVP)](https://aws.amazon.com/verified-permissions/)
(`Aws\VerifiedPermissions\VerifiedPermissionsClient`). Swap an AVP client
for `Cedar\AuthorizationClient` in your code and the request / response
payloads keep the same shape — there is no AVP service call, the policies
are evaluated in-process.

The Cedar evaluation engine is a snapshot of
[nxe-cedar](https://github.com/kjdev/nxe-cedar) (the NGINX-edge Cedar
evaluator) rewritten for use inside a PHP extension. See
[`src/cedar/UPSTREAM.md`](src/cedar/UPSTREAM.md) for the upstream commit
and re-import policy.

## Requirements

- PHP **8.4 or later** (NTS or ZTS). PHP 8.4 introduced the `ext/random/`
  reorganization that this extension depends on for CSPRNG-backed
  `PolicyStore` id generation.
- A POSIX build environment (`phpize`, `make`, a C compiler).
- Both NTS and ZTS builds are supported (see
  [ZTS status](#zts-status) below).

## Installation

### With PIE (recommended)

[PIE](https://github.com/php/pie) is the modern PHP extension installer
(it replaces `pecl install`).

```bash
pie install kjdev/cedar
```

PIE drives the standard `phpize` → `configure` → `make` →
`make install` flow under the hood, taking care of locating
`php-config` and dropping a `cedar.ini` into the right SAPI directory.

### Manual build

```bash
phpize
./configure --enable-cedar
make
make test
make install   # may need elevated privileges
```

Then enable the extension by adding `extension=cedar.so` to a PHP ini
file (e.g. `/etc/php.d/40-cedar.ini`).

## Quick start

```php
<?php
$store = new Cedar\PolicyStore('my-app-store');
$store->loadString('admin-may-view', <<<'CEDAR'
permit (
    principal in MyApp::Group::"admins",
    action == MyApp::Action::"view",
    resource
);
CEDAR);

$client = new Cedar\AuthorizationClient($store);

$result = $client->isAuthorized([
    'policyStoreId' => 'my-app-store',
    'principal' => ['entityType' => 'MyApp::User',   'entityId' => 'alice'],
    'action'    => ['actionType' => 'MyApp::Action', 'actionId' => 'view'],
    'resource'  => ['entityType' => 'MyApp::Doc',    'entityId' => 'doc-42'],
    'entities'  => ['entityList' => [[
        'identifier' => ['entityType' => 'MyApp::User',  'entityId' => 'alice'],
        'attributes' => [],
        'parents'    => [['entityType' => 'MyApp::Group', 'entityId' => 'admins']],
    ]]],
]);

// $result === [
//     'decision' => 'ALLOW',
//     'determiningPolicies' => [['policyId' => 'admin-may-view']],
//     'errors' => [],
// ]
```

## Drop-in replacement for AWS Verified Permissions

`Cedar\AuthorizationClient::isAuthorized()` accepts the same request shape
as `Aws\VerifiedPermissions\VerifiedPermissionsClient::isAuthorized()` and
returns a response with the same top-level keys (`decision`,
`determiningPolicies`, `errors`). You can therefore swap one for the other
through dependency injection — a common setup is **AVP in production,
this extension for local development, CI, and on-prem deployments**, with
no changes at the call site.

Introduce a thin interface that both implementations satisfy, and wrap
each concrete client in a small adapter. The adapter on the AVP side
exists only to coerce `Aws\Result` (which implements `ArrayAccess`) into
a plain array so the return type matches:

```php
interface AuthorizationClientInterface
{
    public function isAuthorized(array $params): array;
    public function isAuthorizedWithToken(array $params): array;
}

final class CedarLocalClient implements AuthorizationClientInterface
{
    public function __construct(private readonly \Cedar\AuthorizationClient $client) {}

    public function isAuthorized(array $params): array
    {
        return $this->client->isAuthorized($params);
    }

    public function isAuthorizedWithToken(array $params): array
    {
        return $this->client->isAuthorizedWithToken($params);
    }
}

final class AvpClient implements AuthorizationClientInterface
{
    public function __construct(
        private readonly \Aws\VerifiedPermissions\VerifiedPermissionsClient $client,
    ) {}

    public function isAuthorized(array $params): array
    {
        return $this->client->isAuthorized($params)->toArray();
    }

    public function isAuthorizedWithToken(array $params): array
    {
        return $this->client->isAuthorizedWithToken($params)->toArray();
    }
}
```

Wire either implementation into your container, then keep the call site
identical:

```php
$authorizer = getenv('APP_ENV') === 'production'
    ? new AvpClient(new \Aws\VerifiedPermissions\VerifiedPermissionsClient([
          'region'  => 'us-east-1',
          'version' => 'latest',
      ]))
    : new CedarLocalClient(new \Cedar\AuthorizationClient($store));

$result = $authorizer->isAuthorized([
    'policyStoreId' => $policyStoreId,
    'principal'     => ['entityType' => 'MyApp::User',   'entityId' => 'alice'],
    'action'        => ['actionType' => 'MyApp::Action', 'actionId' => 'view'],
    'resource'      => ['entityType' => 'MyApp::Doc',    'entityId' => 'doc-42'],
    'entities'      => ['entityList' => [/* ... */]],
]);
// $result['decision'] === 'ALLOW' | 'DENY'
```

The `policyStoreId` value is the only thing that differs between the two
backends:

- With AVP, it is the `PS...` id returned by `CreatePolicyStore`.
- With this extension, it is the string you passed to (or that was
  auto-generated by) `Cedar\PolicyStore::__construct()`.

Inject the right value through configuration (env var, parameter, etc.)
and the rest of the request payload is byte-for-byte identical.

See [AVP compatibility](#avp-compatibility) for the per-key compatibility
matrix and [Unsupported features](#unsupported-features) for the known
gaps (entity tags, policy templates, schema validation, dynamic identity
sources).

## API overview

### `Cedar\PolicyStore`

Container that holds one or more Cedar policy bundles. It corresponds
to the **PolicyStore** concept in AVP.

| Method | Description |
| --- | --- |
| `__construct(?string $policyStoreId = null)` | Optional explicit id; auto-generated 32-char lowercase hex when omitted. |
| `loadFile(string $policyId, string $path): static` | Read a policy file via `php_stream` and register it under `$policyId`. Throws `Cedar\Exception\PolicyParseException` on parse errors or duplicate ids. |
| `loadString(string $policyId, string $cedarText): static` | Same as `loadFile` but takes the source directly. Returns `$this` (fluent). |
| `id(): string` | Returns the configured policy store id. |
| `policyIds(): list<string>` | Returns the ids of every bundle currently loaded. |

### `Cedar\AuthorizationClient`

AVP-compatible evaluation client.

```php
new Cedar\AuthorizationClient(PolicyStore $store, array $options = []);
```

`$options['identitySource']` (required only for
`isAuthorizedWithToken()`):

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `principalEntityType` | string | _(required)_ | Cedar entity type used for the derived principal, e.g. `"MyApp::User"`. |
| `principalIdClaim` | string | `"sub"` | Claim that holds the principal id inside the verified token payload. |
| `groupEntityType` | string | _(optional)_ | Cedar entity type for groups (e.g. `"MyApp::Group"`). |
| `groupIdsClaim` | string | _(optional)_ | Claim that holds the principal's group ids as a list of strings (e.g. `"cognito:groups"`). |

Methods:

| Method | Description |
| --- | --- |
| `isAuthorized(array $params): array` | AVP-shaped evaluation against the bound `PolicyStore`. |
| `isAuthorizedWithToken(array $params): array` | Like `isAuthorized()` but the principal (and optional group parents) come from a token payload; see [Token verification](#token-verification-is-callers-responsibility) below. |

### Request shape (AVP-compatible)

Both methods accept the same keys as the corresponding AVP API:

```php
[
    'policyStoreId' => string,                 // required, must equal $store->id()
    'principal' => ['entityType' => ..., 'entityId' => ...],   // required (isAuthorized only)
    'action'    => ['actionType' => ..., 'actionId' => ...],   // required
    'resource'  => ['entityType' => ..., 'entityId' => ...],   // required
    'context'   => ['contextMap' => [name => AttributeValue, ...]],   // optional
    'entities'  => ['entityList' => [                                 // optional
        [
            'identifier' => ['entityType' => ..., 'entityId' => ...],
            'attributes' => [name => AttributeValue, ...],
            'parents'    => [['entityType' => ..., 'entityId' => ...], ...],
        ],
        ...
    ]],
    // isAuthorizedWithToken only:
    'identityToken' => [claim => value, ...],   // verified claims array
    'accessToken'   => [claim => value, ...],   // verified claims array
]
```

`policyStoreId`, `principal` (for `isAuthorized()`), `action`, and
`resource` are required; `context` and `entities` are optional and may be
omitted entirely when the policies do not reference them. A request with
only the required keys is valid and evaluates normally.

`AttributeValue` is the same single-key union AVP uses:

```php
['string' => 'admin']
['long'    => 42]
['boolean' => true]
['ipaddr'  => '10.0.0.1']
['decimal' => '12.3400']
['datetime' => '2026-01-01T00:00:00Z']
['duration' => '1d12h']
['entityIdentifier' => ['entityType' => 'MyApp::User', 'entityId' => 'bob']]
['set'    => [AttributeValue, ...]]
['record' => [name => AttributeValue, ...]]
```

### Response shape

```php
[
    'decision' => 'ALLOW' | 'DENY',
    'determiningPolicies' => [['policyId' => string], ...],
    'errors' => [['errorDescription' => string], ...],
    // isAuthorizedWithToken only:
    'principal' => ['entityType' => string, 'entityId' => string],
]
```

### Exceptions

All three subclass `\RuntimeException`:

| Class | When |
| --- | --- |
| `Cedar\Exception\PolicyParseException` | Cedar syntax error or duplicate `policyId` in `loadFile` / `loadString`. |
| `Cedar\Exception\EvaluationException` | Allocation / engine-level failures. |
| `Cedar\Exception\ResourceNotFoundException` | `policyStoreId` in the request does not match `PolicyStore::id()`. AVP raises the same-named error in this case. |

Argument-shape errors (missing `policyStoreId`, supplying `principal`
to `isAuthorizedWithToken`, etc.) surface as the engine-level `Error`
class, not as one of the Cedar exceptions.

## AVP compatibility

| Aspect | Compatibility |
| --- | --- |
| `isAuthorized()` request keys | **Complete** (`policyStoreId / principal / action / resource / context / entities`). |
| `AttributeValue` union members | **Complete** for everything the bundled Cedar evaluator supports (see [Unsupported features](#unsupported-features) for the upstream gaps). |
| Response keys | `decision / determiningPolicies / errors` match exactly. `Aws\Result`'s `ArrayAccess` methods (`->get(...)`) are **not** available — the response is a plain array. |
| `isAuthorizedWithToken()` | API-shape compatible (`policyStoreId / identityToken / accessToken / action / resource / context / entities`, response includes the derived `principal`), but **the token is expected to be a verified claims array, not a raw JWT string**. See [Token verification](#token-verification-is-callers-responsibility). |

Beyond matching the request / response *shape*, what makes this extension
substitutable for AVP is that **the same request yields the same
`decision`**. The evaluation engine is kept logically identical to its
upstream nxe-cedar snapshot (see
[`src/cedar/UPSTREAM.md`](src/cedar/UPSTREAM.md)), so it inherits
nxe-cedar's behavioral conformance: the C implementation is
differential-tested against the upstream `cedar-policy` reference crate,
with **100% C-vs-reference parity** reported over the official Cedar
integration-test corpus (see
[nxe-cedar's conformance notes](https://github.com/kjdev/nxe-cedar/blob/main/tests/conformance/README.md)).
This parity guarantee covers only the **supported subset**: the
[unsupported features](#unsupported-features) (entity tags, policy
templates, schema validation, dynamic identity sources) lie outside the
conformance corpus and are not part of the claim.

For a worked example of swapping AVP and this extension behind a single
interface, see
[Drop-in replacement for AWS Verified Permissions](#drop-in-replacement-for-aws-verified-permissions).

## Token verification is caller's responsibility

`isAuthorizedWithToken()` accepts the token as a **decoded, verified
claims array** rather than as a raw JWT string. This is a deliberate
design choice:

- The extension does not bundle a JWT verifier; it would force
  OpenSSL / json parsing dependencies onto the build.
- Accepting a string would invite a class of bugs where the JWT is
  decoded without checking the signature, allowing an attacker to
  forge principals.

Use a dedicated PHP library — for example
[`firebase/php-jwt`](https://github.com/firebase/php-jwt) or
[`web-token/jwt-framework`](https://github.com/web-token/jwt-framework) —
to verify the JWT (signature, issuer, expiry, audience, `token_use`)
and pass the resulting payload array to this extension:

```php
$payload = $jwtVerifier->decode($rawJwt);   // verified by your library

$client = new Cedar\AuthorizationClient($store, [
    'identitySource' => [
        'principalEntityType' => 'MyApp::User',
        'principalIdClaim'    => 'sub',
        'groupEntityType'     => 'MyApp::Group',
        'groupIdsClaim'       => 'cognito:groups',
    ],
]);

$result = $client->isAuthorizedWithToken([
    'policyStoreId' => $store->id(),
    'identityToken' => $payload,
    'action'   => ['actionType' => 'MyApp::Action', 'actionId' => 'view'],
    'resource' => ['entityType' => 'MyApp::Doc',    'entityId' => 'doc-42'],
]);
```

When both `identityToken` and `accessToken` are supplied, this extension
uses `identityToken` and ignores `accessToken`. This differs slightly from
AVP, which accepts both and resolves the principal and claim mapping from
the configured identity source and each token's `token_use` claim.

## Unsupported features

The Cedar evaluator follows the feature set bundled from upstream
nxe-cedar. The following features are **not** available in this
release:

- Entity tags (`.hasTag()` / `.getTag()`). A `tags` key on an
  `entities.entityList[]` entry is silently ignored rather than raising an error.
- Policy templates (`?principal`, `?resource`) and template-linked
  policies.
- Schema validation (`@anyOf`, `@oneOf`, declared attributes).
- Dynamic identity sources: AVP can validate a JWT against a Cognito
  user pool or generic OIDC IdP and derive the principal. This
  extension delegates that to the caller (see
  [Token verification](#token-verification-is-callers-responsibility)).
- Passing `context` as raw Cedar JSON via the `cedarJson` key. Only
  `contextMap` is supported; a `cedarJson` context is silently ignored.

A malformed or unsupported `AttributeValue` (for example an unknown
union key, or `['datetime' => 'not-a-date']`) does not abort the
request: the entry is skipped and an entry is appended to the
response's `errors[]`. This
matches AVP's behavior of returning a successful response with
populated `errors` when a single attribute is broken.

## Performance and persistence

The current implementation is **request-scoped**: every PHP-FPM
request that needs to authorize re-parses the policy bundles via
`PolicyStore::loadFile()` / `loadString()`. Parsing is fast for the
small / medium policy sets typical of authorization rules (the
Cedar grammar is small and the evaluator is hand-written C with no
external dependencies), so this is normally not a hot spot.

If you need to share parsed policies across requests within a worker:

- For now, cache the **policy text** in [APCu](https://www.php.net/apcu)
  or [opcache.preload](https://www.php.net/manual/en/opcache.preloading.php)
  and rebuild the `PolicyStore` once per request from the cached
  string. Parsing is still cheap.
- A future release may add a persistent (`pemalloc`) policy store
  variant that survives `RSHUTDOWN`. This is tracked as a known
  follow-up; the request-scoped API will remain the default.

## Multiple PolicyStores per client

This release supports **one `PolicyStore` per `AuthorizationClient`**.
If you need to evaluate requests against different stores (e.g. one
store per tenant), instantiate a separate `AuthorizationClient` for
each one. A future release may accept multiple stores on the
constructor and dispatch on the request's `policyStoreId`.

## ZTS status

Both **NTS** and **ZTS** builds are supported. `composer.json` reports
`support-zts: true`, and CI runs a full `--enable-zts` build plus
`make test` for every PHP version in the matrix. Thread-safety notes:

- The extension has no request-scoped module globals
  (`ZEND_BEGIN_MODULE_GLOBALS`). For ZTS DSO builds it only defines the
  TSRMLS cache symbol (`ZEND_TSRMLS_CACHE_DEFINE` / `EXTERN`) that the
  Zend ABI requires.
- File-scope `static` state (class entries, object handlers) is written
  exactly once in `MINIT` and read-only thereafter.
- The one mutable file-scope counter — the fallback in
  `cedar_generate_policy_store_id` used only when the CSPRNG fails — is
  an atomic counter, so ids stay unique across threads.
- Per-request data lives on PHP objects (`zend_object` + internal
  structs) whose lifecycle is already thread-isolated by Zend.

## Developing the extension

```bash
phpize
./configure --enable-cedar
make
make test
```

`cedar.stub.php` declares the PHP-facing API. After editing it,
regenerate `cedar_arginfo.h`:

```bash
php /usr/lib64/php/build/gen_stub.php cedar.stub.php
```

The test suite uses the standard `.phpt` format under `tests/`. Run
a subset with:

```bash
make test TESTS=tests/030-avp-photoflash-sample.phpt
```

## License

This extension is released under the [MIT License](LICENSE). The
bundled Cedar evaluator under `src/cedar/` retains its upstream
license; see [`src/cedar/UPSTREAM.md`](src/cedar/UPSTREAM.md).
