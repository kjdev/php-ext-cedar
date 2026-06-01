--TEST--
AuthorizationClient::isAuthorized: malformed or unsupported AttributeValue surfaces in errors[]
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource);');
$client = new Cedar\AuthorizationClient($store);

echo "-- context.contextMap path --", PHP_EOL;
$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => [
        "okScalar"    => ["string"      => "hello"],
        "badUnknown"  => ["mysteryType" => "whatever"],
        "badEmpty"    => [],
    ]],
]);
echo $res["decision"], PHP_EOL;
echo "errors=", count($res["errors"]), PHP_EOL;
foreach ($res["errors"] as $e) {
    echo "- ", $e["errorDescription"], PHP_EOL;
}

echo "-- entities.entityList attribute path --", PHP_EOL;
$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "alice"],
        "attributes" => [
            "okScalar" => ["string"   => "hello"],
            "broken"   => ["datetime" => "not-a-valid-datetime"],
        ],
    ]]],
]);
echo $res["decision"], PHP_EOL;
echo "errors=", count($res["errors"]), PHP_EOL;
foreach ($res["errors"] as $e) {
    echo "- ", $e["errorDescription"], PHP_EOL;
}
?>
--EXPECTF--
-- context.contextMap path --
ALLOW
errors=2
- unsupported or malformed AttributeValue for context.%s
- unsupported or malformed AttributeValue for context.%s
-- entities.entityList attribute path --
ALLOW
errors=1
- unsupported or malformed AttributeValue for User::"alice".broken
