--TEST--
AuthorizationClient::isAuthorized: mismatched policyStoreId throws ResourceNotFoundException; missing key throws Error
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store  = new Cedar\PolicyStore("right-id");
$client = new Cedar\AuthorizationClient($store);

try {
    $client->isAuthorized([
        "policyStoreId" => "wrong-id",
        "principal" => ["entityType" => "User",   "entityId" => "alice"],
        "action"    => ["actionType" => "Action", "actionId" => "view"],
        "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
    ]);
} catch (Cedar\Exception\ResourceNotFoundException $e) {
    echo $e->getMessage(), PHP_EOL;
}

// AVP requires policyStoreId; omitting it must fail
try {
    $client->isAuthorized([
        "principal" => ["entityType" => "User",   "entityId" => "alice"],
        "action"    => ["actionType" => "Action", "actionId" => "view"],
        "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
    ]);
} catch (Error $e) {
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECT--
policyStoreId 'wrong-id' does not match the bound PolicyStore
'policyStoreId' (string) is required
