--TEST--
AuthorizationClient::isAuthorizedWithToken: error paths (no identitySource, principal supplied, missing token, missing claim)
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource);');
$base_req = [
    "policyStoreId" => $store->id(),
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
];

// 1) Client was constructed without identitySource
$plain = new Cedar\AuthorizationClient($store);
try {
    $plain->isAuthorizedWithToken($base_req + ["identityToken" => ["sub" => "x"]]);
} catch (\Error $e) {
    echo "1) ", $e->getMessage(), PHP_EOL;
}

$client = new Cedar\AuthorizationClient($store, [
    "identitySource" => [
        "principalEntityType" => "App::User",
        "principalIdClaim"    => "sub",
    ],
]);

// 2) 'principal' must not be supplied
try {
    $client->isAuthorizedWithToken($base_req + [
        "identityToken" => ["sub" => "x"],
        "principal"     => ["entityType" => "App::User", "entityId" => "x"],
    ]);
} catch (\Error $e) {
    echo "2) ", $e->getMessage(), PHP_EOL;
}

// 3) neither identityToken nor accessToken
try {
    $client->isAuthorizedWithToken($base_req);
} catch (\Error $e) {
    echo "3) ", $e->getMessage(), PHP_EOL;
}

// 4) principal claim missing from payload
try {
    $client->isAuthorizedWithToken($base_req + [
        "identityToken" => ["email" => "a@example.com"],
    ]);
} catch (\Error $e) {
    echo "4) ", $e->getMessage(), PHP_EOL;
}

// 5) policyStoreId mismatch still raises ResourceNotFoundException
try {
    $client->isAuthorizedWithToken([
        "policyStoreId" => "wrong",
        "identityToken" => ["sub" => "x"],
        "action"   => ["actionType" => "Action", "actionId" => "view"],
        "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
    ]);
} catch (Cedar\Exception\ResourceNotFoundException $e) {
    echo "5) ", $e->getMessage(), PHP_EOL;
}
?>
--EXPECT--
1) isAuthorizedWithToken(): AuthorizationClient was not constructed with an 'identitySource' option
2) isAuthorizedWithToken(): 'principal' must not be supplied; it is derived from the token
3) isAuthorizedWithToken(): 'identityToken' or 'accessToken' (verified claims array) is required
4) isAuthorizedWithToken(): claim 'sub' is missing or not a string in the supplied token payload
5) policyStoreId 'wrong' does not match the bound PolicyStore
