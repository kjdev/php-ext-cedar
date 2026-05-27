--TEST--
AuthorizationClient::isAuthorizedWithToken: principalIdClaim can be customized, context/entities still flow through
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { principal.tier == "gold" && context.mfa == true };');

$client = new Cedar\AuthorizationClient($store, [
    "identitySource" => [
        "principalEntityType" => "App::User",
        "principalIdClaim"    => "user_id", // not the default 'sub'
    ],
]);

$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "identityToken" => ["user_id" => "alice"],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
    "context"  => ["contextMap" => ["mfa" => ["boolean" => true]]],
    "entities" => ["entityList" => [[
        "identifier" => ["entityType" => "App::User", "entityId" => "alice"],
        "attributes" => ["tier" => ["string" => "gold"]],
        "parents"    => [],
    ]]],
]);
echo $res["decision"], PHP_EOL;
echo $res["principal"]["entityType"], "::", $res["principal"]["entityId"], PHP_EOL;
?>
--EXPECT--
ALLOW
App::User::alice
