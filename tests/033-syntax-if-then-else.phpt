--TEST--
Cedar syntax: 'if ... then ... else' ternary expression in a when clause
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p_if",
    'permit(principal, action, resource) when {
        if context.role == "admin" then true else principal.tier == "gold"
    };');
$client = new Cedar\AuthorizationClient($store);

$base = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
];
$with = function(?string $role, ?string $tier) use ($base) {
    $req = $base;
    if ($role !== null) {
        $req["context"] = ["contextMap" => ["role" => ["string" => $role]]];
    } else {
        $req["context"] = ["contextMap" => ["role" => ["string" => "guest"]]];
    }
    $req["entities"] = ["entityList" => [[
        "identifier" => ["entityType" => "User", "entityId" => "alice"],
        "attributes" => ["tier" => ["string" => $tier ?? "none"]],
        "parents"    => [],
    ]]];
    return $req;
};

// admin role -> "then true" branch
echo "admin / silver: ", ((new Cedar\AuthorizationClient($store))->isAuthorized($with("admin", "silver")))["decision"], PHP_EOL;
// non-admin + gold tier -> "else principal.tier == gold" is true
echo "guest / gold:   ", $client->isAuthorized($with("guest", "gold"))["decision"], PHP_EOL;
// non-admin + non-gold -> false
echo "guest / silver: ", $client->isAuthorized($with("guest", "silver"))["decision"], PHP_EOL;
?>
--EXPECT--
admin / silver: ALLOW
guest / gold:   ALLOW
guest / silver: DENY
