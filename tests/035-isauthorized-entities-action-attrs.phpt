--TEST--
AuthorizationClient::isAuthorized: entities.entityList feeds action attributes
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { action.readOnly == true };');
$client = new Cedar\AuthorizationClient($store);

$req = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
    "entities"  => ["entityList" => [
        [
            "identifier" => ["entityType" => "Action", "entityId" => "view"],
            "attributes" => ["readOnly" => ["boolean" => true]],
            "parents"    => [],
        ],
    ]],
];
echo $client->isAuthorized($req)["decision"], PHP_EOL;

$req["entities"]["entityList"][0]["attributes"]["readOnly"] = ["boolean" => false];
echo $client->isAuthorized($req)["decision"], PHP_EOL;
?>
--EXPECT--
ALLOW
DENY
