--TEST--
Cedar syntax: policy annotations are accepted at parse time and the policy still evaluates
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
// Annotations (@id, @advice, ...) attach metadata to a policy. They
// must parse cleanly and not change the evaluator's decision.
$store = new Cedar\PolicyStore("s");
$store->loadString("annotated", '
    @id("policy-001")
    @advice("contact security@example.com on denial")
    permit (
        principal,
        action == Action::"view",
        resource
    );
');

$client = new Cedar\AuthorizationClient($store);
$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo $res["decision"], PHP_EOL;
echo $res["determiningPolicies"][0]["policyId"], PHP_EOL;

// A policy with annotations but a non-matching action -> DENY
$res = $client->isAuthorized([
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "delete"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
echo $res["decision"], PHP_EOL;
?>
--EXPECT--
ALLOW
annotated
DENY
