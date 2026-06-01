--TEST--
AuthorizationClient::isAuthorized: a forbid policy yields DENY with the matched policy in determiningPolicies
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("my-store");
$store->loadString("p1", "forbid(principal, action, resource);");

$client = new Cedar\AuthorizationClient($store);
$res = $client->isAuthorized([
    "policyStoreId" => "my-store",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
var_dump($res);
?>
--EXPECT--
array(3) {
  ["decision"]=>
  string(4) "DENY"
  ["determiningPolicies"]=>
  array(1) {
    [0]=>
    array(1) {
      ["policyId"]=>
      string(2) "p1"
    }
  }
  ["errors"]=>
  array(0) {
  }
}
