--TEST--
AuthorizationClient::isAuthorized: AttributeValue Union 'set' member with contains()
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal, action, resource) when { principal.groups.contains("editors") };');
$client = new Cedar\AuthorizationClient($store);

$req = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "a"],
        "attributes" => ["groups" => ["set" => [
            ["string" => "viewers"],
            ["string" => "editors"],
        ]]],
        "parents" => [],
    ]]],
];
echo "match:    ", $client->isAuthorized($req)["decision"], PHP_EOL;

$req["entities"]["entityList"][0]["attributes"]["groups"]["set"]
    = [["string" => "viewers"]];
echo "no match: ", $client->isAuthorized($req)["decision"], PHP_EOL;
?>
--EXPECT--
match:    ALLOW
no match: DENY
