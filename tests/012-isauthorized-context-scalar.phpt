--TEST--
AuthorizationClient::isAuthorized: context.contextMap with scalar AttributeValue (string/long/boolean)
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal, action, resource) when { context.mfa == true && context.role == "admin" && context.attempts < 3 };');
$client = new Cedar\AuthorizationClient($store);

$base = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
];

$res = $client->isAuthorized($base + ["context" => ["contextMap" => [
    "mfa"      => ["boolean" => true],
    "role"     => ["string"  => "admin"],
    "attempts" => ["long"    => 1],
]]]);
echo "all match: ", $res["decision"], PHP_EOL;

$res = $client->isAuthorized($base + ["context" => ["contextMap" => [
    "mfa"      => ["boolean" => false],
    "role"     => ["string"  => "admin"],
    "attempts" => ["long"    => 1],
]]]);
echo "mfa off:   ", $res["decision"], PHP_EOL;

$res = $client->isAuthorized($base + ["context" => ["contextMap" => [
    "mfa"      => ["boolean" => true],
    "role"     => ["string"  => "viewer"],
    "attempts" => ["long"    => 1],
]]]);
echo "wrong role:", $res["decision"], PHP_EOL;
?>
--EXPECT--
all match: ALLOW
mfa off:   DENY
wrong role:DENY
