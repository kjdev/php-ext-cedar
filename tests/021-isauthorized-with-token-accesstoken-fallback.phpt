--TEST--
AuthorizationClient::isAuthorizedWithToken: accessToken is used when identityToken is absent; identityToken wins when both are given
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource);');
$client = new Cedar\AuthorizationClient($store, [
    "identitySource" => [
        "principalEntityType" => "App::User",
        "principalIdClaim"    => "sub",
    ],
]);

// accessToken only
$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "accessToken"   => ["sub" => "alice"],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo "accessToken only: ", $res["principal"]["entityId"], PHP_EOL;

// identityToken wins when both are present
$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "identityToken" => ["sub" => "id-token-alice"],
    "accessToken"   => ["sub" => "access-token-alice"],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo "both present:    ", $res["principal"]["entityId"], PHP_EOL;
?>
--EXPECT--
accessToken only: alice
both present:    id-token-alice
