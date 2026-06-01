--TEST--
AuthorizationClient::isAuthorizedWithToken: claim mapper derives principal and group parents -> ALLOW
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p1",
    'permit(principal in MyApp::Group::"admins", action, resource);');

$client = new Cedar\AuthorizationClient($store, [
    "identitySource" => [
        "principalEntityType" => "MyApp::User",
        "principalIdClaim"    => "sub",
        "groupEntityType"     => "MyApp::Group",
        "groupIdsClaim"       => "cognito:groups",
    ],
]);

$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "identityToken" => [
        "sub"            => "alice-uuid",
        "cognito:groups" => ["viewers", "admins"],
        "token_use"      => "id",
    ],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
var_dump($res);
?>
--EXPECT--
array(4) {
  ["decision"]=>
  string(5) "ALLOW"
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
  ["principal"]=>
  array(2) {
    ["entityType"]=>
    string(11) "MyApp::User"
    ["entityId"]=>
    string(10) "alice-uuid"
  }
}
