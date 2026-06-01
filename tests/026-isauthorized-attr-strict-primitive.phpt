--TEST--
AuthorizationClient::isAuthorized: long/boolean AttributeValue rejects type-mismatched values without silent coercion
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource);');
$client = new Cedar\AuthorizationClient($store);

$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => [
        "okLong"  => ["long"    => 5],
        "badLong" => ["long"    => 1.9],
        "okBool"  => ["boolean" => true],
        "badBool" => ["boolean" => "false"],
    ]],
]);
echo $res["decision"], PHP_EOL;
echo "errors=", count($res["errors"]), PHP_EOL;
?>
--EXPECT--
ALLOW
errors=2
