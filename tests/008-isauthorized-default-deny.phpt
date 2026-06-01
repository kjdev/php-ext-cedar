--TEST--
AuthorizationClient::isAuthorized: an empty store falls back to implicit DENY with empty determiningPolicies
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store  = new Cedar\PolicyStore("empty-store");
$client = new Cedar\AuthorizationClient($store);

$res = $client->isAuthorized([
    "policyStoreId" => "empty-store",
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
  array(0) {
  }
  ["errors"]=>
  array(0) {
  }
}
