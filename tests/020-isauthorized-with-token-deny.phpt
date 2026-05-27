--TEST--
AuthorizationClient::isAuthorizedWithToken: missing group claim falls back to implicit DENY
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

// User is not in admins
$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "identityToken" => [
        "sub"            => "bob-uuid",
        "cognito:groups" => ["viewers"],
    ],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo $res["decision"], PHP_EOL;
echo $res["principal"]["entityId"], PHP_EOL;

// No groups claim at all
$res = $client->isAuthorizedWithToken([
    "policyStoreId" => $store->id(),
    "identityToken" => ["sub" => "carol-uuid"],
    "action"   => ["actionType" => "Action", "actionId" => "view"],
    "resource" => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo $res["decision"], PHP_EOL;
echo $res["principal"]["entityId"], PHP_EOL;
?>
--EXPECT--
DENY
bob-uuid
DENY
carol-uuid
