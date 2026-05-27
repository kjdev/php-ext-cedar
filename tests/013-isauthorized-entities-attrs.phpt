--TEST--
AuthorizationClient::isAuthorized: entities.entityList feeds principal/resource attributes
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { principal.tier == "gold" && resource.public == true };');
$client = new Cedar\AuthorizationClient($store);

$req = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User", "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",  "entityId" => "doc1"],
    "entities"  => ["entityList" => [
        [
            "identifier" => ["entityType" => "User", "entityId" => "alice"],
            "attributes" => ["tier" => ["string" => "gold"]],
            "parents"    => [],
        ],
        [
            "identifier" => ["entityType" => "Doc",  "entityId" => "doc1"],
            "attributes" => ["public" => ["boolean" => true]],
            "parents"    => [],
        ],
    ]],
];
echo $client->isAuthorized($req)["decision"], PHP_EOL;

$req["entities"]["entityList"][1]["attributes"]["public"] = ["boolean" => false];
echo $client->isAuthorized($req)["decision"], PHP_EOL;
?>
--EXPECT--
ALLOW
DENY
