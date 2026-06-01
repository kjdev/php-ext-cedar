--TEST--
AuthorizationClient::isAuthorized: determiningPolicies lists only the forbid when forbid overrides permit (AVP semantics)
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
// AVP IsAuthorized contract: when a forbid policy overrides a matching
// permit, only the forbid(s) appear in determiningPolicies. The matched
// permit must not leak into the response.
//
// See: https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorized.html
//   "If there are multiple matching policies, where at least one is a
//    forbid policy, then because forbid always overrides permit the
//    forbid policies are the determining policies."

$store = new Cedar\PolicyStore("multi");
$store->loadString("allow-all",   "permit(principal, action, resource);")
      ->loadString("forbid-doc1", 'forbid(principal, action, resource == Doc::"doc1");')
      ->loadString("forbid-doc2", 'forbid(principal, action, resource == Doc::"doc1");');

$client = new Cedar\AuthorizationClient($store);

// (1) forbid wins: determiningPolicies must contain only the forbids,
//     never the matched permit.
$res = $client->isAuthorized([
    "policyStoreId" => "multi",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
]);
$ids = array_map(fn($p) => $p["policyId"], $res["determiningPolicies"]);
sort($ids);
echo "1 decision: ", $res["decision"], PHP_EOL;
echo "1 determining: ", implode(",", $ids), PHP_EOL;

// (2) No forbid matches: determiningPolicies lists the permit only.
$res = $client->isAuthorized([
    "policyStoreId" => "multi",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc2"],
]);
$ids = array_map(fn($p) => $p["policyId"], $res["determiningPolicies"]);
echo "2 decision: ", $res["decision"], PHP_EOL;
echo "2 determining: ", implode(",", $ids), PHP_EOL;
?>
--EXPECT--
1 decision: DENY
1 determining: forbid-doc1,forbid-doc2
2 decision: ALLOW
2 determining: allow-all
