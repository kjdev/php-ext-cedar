# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-02

Initial release. A PHP extension that evaluates Cedar policies locally with an
Amazon Verified Permissions (AVP) compatible API. The evaluation engine is a
snapshot of nxe-cedar (Cedar for the NGINX edge) at v0.3.0, vendored under
`src/cedar/` and adapted for the PHP extension.

### Added

- `Cedar\PolicyStore` — a container for one or more Cedar policies, with
  inline parsing, file loading (`loadFile()`), and a stable store id.
- `Cedar\AuthorizationClient` — an AVP-compatible evaluation client whose
  `isAuthorized()` argument structure matches
  `Aws\VerifiedPermissions\VerifiedPermissionsClient::isAuthorized()`,
  allowing a single interface to switch between AVP and this extension.
- `isAuthorizedWithToken()` with a JWT claim mapper, including identity- and
  access-token claim fallback and custom claim support.
- `context.contextMap` and `entities.entityList` request inputs.
- Non-scalar `AttributeValue` variants: `ipaddr`, `decimal`, `set`, `record`,
  `entityIdentifier`, `datetime`, and `duration`.
- Cedar syntax coverage including `is` / `is in`, `like`, `if then else`, and
  policy annotations.
- Exception hierarchy: `Cedar\Exception\PolicyParseException`,
  `EvaluationException`, and `ResourceNotFoundException`.
- Thread-safe (ZTS) builds in addition to NTS, declared in the PIE manifest
  and exercised in CI.
- README with installation (PIE), usage, AVP drop-in replacement notes, and a
  build/test matrix; MIT license; PIE manifest (`composer.json`); GitHub
  Actions CI running `make test` across the PHP 8.4 / 8.5 × NTS / ZTS matrix.

[0.1.0]: https://github.com/kjdev/php-ext-cedar/releases/tag/v0.1.0
