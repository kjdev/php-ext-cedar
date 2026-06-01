--TEST--
AuthorizationClient::isAuthorized: entities.entityList parents drive 'principal in Group::"admins"'
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1", 'permit(principal in Group::"admins", action, resource);');
$client = new Cedar\AuthorizationClient($store);

$base = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
];

$with_admin_parent = $base + ["entities" => ["entityList" => [[
    "identifier" => ["entityType" => "User", "entityId" => "alice"],
    "attributes" => [],
    "parents"    => [["entityType" => "Group", "entityId" => "admins"]],
]]]];
echo "with admins:    ", $client->isAuthorized($with_admin_parent)["decision"], PHP_EOL;

$with_other_parent = $base + ["entities" => ["entityList" => [[
    "identifier" => ["entityType" => "User", "entityId" => "alice"],
    "attributes" => [],
    "parents"    => [["entityType" => "Group", "entityId" => "viewers"]],
]]]];
echo "with viewers:   ", $client->isAuthorized($with_other_parent)["decision"], PHP_EOL;

echo "without parents:", $client->isAuthorized($base)["decision"], PHP_EOL;
?>
--EXPECT--
with admins:    ALLOW
with viewers:   DENY
without parents:DENY
