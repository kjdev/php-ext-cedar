--TEST--
AuthorizationClient::isAuthorized: an entity that is both principal and resource gets attributes and parents on both targets
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { principal.team == resource.team };');
$client = new Cedar\AuthorizationClient($store);

// principal and resource are the very same entity. Its attributes must be
// applied to both targets, otherwise resource.team would be undefined.
$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User", "entityId" => "u1"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "User", "entityId" => "u1"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "u1"],
        "attributes" => ["team" => ["string" => "blue"]],
    ]]],
]);
echo $res["decision"], PHP_EOL;
echo "errors=", count($res["errors"]), PHP_EOL;
?>
--EXPECT--
ALLOW
errors=0
