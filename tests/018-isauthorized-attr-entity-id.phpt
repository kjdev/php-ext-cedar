--TEST--
AuthorizationClient::isAuthorized: AttributeValue Union 'entityIdentifier' member
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource) when { resource.owner == principal };');
$client = new Cedar\AuthorizationClient($store);

$req = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User", "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",  "entityId" => "doc1"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "Doc", "entityId" => "doc1"],
        "attributes" => ["owner" => ["entityIdentifier" => [
            "entityType" => "User", "entityId" => "alice",
        ]]],
        "parents"    => [],
    ]]],
];
echo "self owner:  ", $client->isAuthorized($req)["decision"], PHP_EOL;

$req["entities"]["entityList"][0]["attributes"]["owner"]["entityIdentifier"]["entityId"] = "bob";
echo "other owner: ", $client->isAuthorized($req)["decision"], PHP_EOL;
?>
--EXPECT--
self owner:  ALLOW
other owner: DENY
