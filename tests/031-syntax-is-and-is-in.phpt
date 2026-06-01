--TEST--
Cedar syntax: 'is' type check and 'is ... in' combined type + parent check
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
// 'is' alone: only allow when the principal is of the User type
$store = new Cedar\PolicyStore("s");
$store->loadString("p_is", 'permit(principal is User, action, resource);');
$client = new Cedar\AuthorizationClient($store);
$base = [
    "policyStoreId" => "s",
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
];
echo "User:    ", $client->isAuthorized($base + [
    "principal" => ["entityType" => "User", "entityId" => "a"],
])["decision"], PHP_EOL;
echo "Service: ", $client->isAuthorized($base + [
    "principal" => ["entityType" => "Service", "entityId" => "robot"],
])["decision"], PHP_EOL;

// 'is ... in': require both type and group membership
$store2 = new Cedar\PolicyStore("s2");
$store2->loadString("p_is_in",
    'permit(principal is User in Group::"admins", action, resource);');
$c2 = new Cedar\AuthorizationClient($store2);

$base2 = [
    "policyStoreId" => "s2",
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
];

echo "User in admins:    ", $c2->isAuthorized($base2 + [
    "principal" => ["entityType" => "User", "entityId" => "alice"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "alice"],
        "attributes" => [],
        "parents"    => [["entityType" => "Group", "entityId" => "admins"]],
    ]]],
])["decision"], PHP_EOL;

echo "User in viewers:   ", $c2->isAuthorized($base2 + [
    "principal" => ["entityType" => "User", "entityId" => "alice"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "alice"],
        "attributes" => [],
        "parents"    => [["entityType" => "Group", "entityId" => "viewers"]],
    ]]],
])["decision"], PHP_EOL;

echo "Service in admins: ", $c2->isAuthorized($base2 + [
    "principal" => ["entityType" => "Service", "entityId" => "robot"],
    "entities"  => ["entityList" => [[
        "identifier" => ["entityType" => "Service", "entityId" => "robot"],
        "attributes" => [],
        "parents"    => [["entityType" => "Group", "entityId" => "admins"]],
    ]]],
])["decision"], PHP_EOL;
?>
--EXPECT--
User:    ALLOW
Service: DENY
User in admins:    ALLOW
User in viewers:   DENY
Service in admins: DENY
