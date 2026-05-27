--TEST--
AuthorizationClient::isAuthorized: AttributeValue Union 'record' member with nested access
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { principal.profile.tier == "gold" && principal.profile.age >= 18 };');
$client = new Cedar\AuthorizationClient($store);

$req = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "a"],
        "attributes" => ["profile" => ["record" => [
            "tier" => ["string" => "gold"],
            "age"  => ["long"   => 35],
        ]]],
        "parents" => [],
    ]]],
];
echo "ok:       ", $client->isAuthorized($req)["decision"], PHP_EOL;

$req["entities"]["entityList"][0]["attributes"]["profile"]["record"]["tier"]
    = ["string" => "silver"];
echo "wrong tier:", $client->isAuthorized($req)["decision"], PHP_EOL;
?>
--EXPECT--
ok:       ALLOW
wrong tier:DENY
