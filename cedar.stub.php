<?php

/**
 * @generate-class-entries
 * @generate-legacy-arginfo
 */

namespace Cedar
{
    /**
     * Container that holds a set of Cedar policies, equivalent to
     * AVP's PolicyStore concept.
     *
     * Multiple policies can be added via loadFile() / loadString().
     * Pass the instance to AuthorizationClient's constructor to use
     * it as the evaluation target for isAuthorized().
     */
    final class PolicyStore
    {
        public function __construct(?string $policyStoreId = null) {}

        public function loadFile(string $policyId, string $path): static {}

        public function loadString(string $policyId, string $cedarText): static {}

        public function id(): string {}

        /** @return list<string> */
        public function policyIds(): array {}
    }

    /**
     * Local evaluation client compatible with AVP's
     * Aws\VerifiedPermissions\VerifiedPermissionsClient.
     */
    final class AuthorizationClient
    {
        public function __construct(PolicyStore $policyStore) {}

        public function isAuthorized(array $params): array {}

        public function isAuthorizedWithToken(array $params): array {}
    }
}

namespace Cedar\Exception
{
    class PolicyParseException extends \RuntimeException {}

    class EvaluationException extends \RuntimeException {}

    class ResourceNotFoundException extends \RuntimeException {}
}
