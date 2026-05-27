--TEST--
AuthorizationClient::isAuthorized: forbid overrides permit across multiple policies
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("multi");
$store->loadString("allow-all",  "permit(principal, action, resource);")
      ->loadString("forbid-doc", 'forbid(principal, action, resource == Doc::"doc1");');

$client = new Cedar\AuthorizationClient($store);
$res = $client->isAuthorized([
    "policyStoreId" => "multi",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo $res["decision"], PHP_EOL;

// a resource the forbid does not match falls back to ALLOW
$res2 = $client->isAuthorized([
    "policyStoreId" => "multi",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc2"],
]);
echo $res2["decision"], PHP_EOL;
?>
--EXPECT--
DENY
ALLOW
