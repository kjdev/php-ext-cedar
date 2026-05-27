--TEST--
AuthorizationClient::isAuthorizedWithToken: not yet implemented in the current release
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store  = new Cedar\PolicyStore();
$client = new Cedar\AuthorizationClient($store);

try {
    $client->isAuthorizedWithToken([
        "policyStoreId" => $store->id(),
        "identityToken" => "eyJ...",
        "action"   => ["actionType" => "Action", "actionId" => "view"],
        "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
    ]);
} catch (RuntimeException $e) {
    echo $e->getMessage(), PHP_EOL;
}
?>
--EXPECTF--
isAuthorizedWithToken() is not implemented yet;%a
