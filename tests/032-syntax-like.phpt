--TEST--
Cedar syntax: 'like' operator with wildcard matching on string attributes
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("s");
$store->loadString("p_like",
    'permit(principal, action, resource) when { resource.path like "/public/*" };');
$client = new Cedar\AuthorizationClient($store);

$base = [
    "policyStoreId" => "s",
    "principal" => ["entityType" => "User",   "entityId" => "alice"],
    "action"    => ["actionType" => "Action", "actionId" => "view"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "doc1"],
];
$entitiesWith = function(string $path) {
    return ["entityList" => [[
        "identifier" => ["entityType" => "Doc", "entityId" => "doc1"],
        "attributes" => ["path" => ["string" => $path]],
        "parents"    => [],
    ]]];
};

echo "/public/index.html: ",
    $client->isAuthorized($base + ["entities" => $entitiesWith("/public/index.html")])["decision"], PHP_EOL;
echo "/public/sub/x.txt:  ",
    $client->isAuthorized($base + ["entities" => $entitiesWith("/public/sub/x.txt")])["decision"], PHP_EOL;
echo "/private/secret:    ",
    $client->isAuthorized($base + ["entities" => $entitiesWith("/private/secret")])["decision"], PHP_EOL;
echo "/public (no slash): ",
    $client->isAuthorized($base + ["entities" => $entitiesWith("/public")])["decision"], PHP_EOL;
?>
--EXPECT--
/public/index.html: ALLOW
/public/sub/x.txt:  ALLOW
/private/secret:    DENY
/public (no slash): DENY
