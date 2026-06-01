--TEST--
AuthorizationClient::isAuthorized: AttributeValue Union 'datetime' and 'duration' members
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
/*
 * datetime / duration attribute values are materialized at injection time
 * and usable through the top-level, record-member, and set-element paths.
 */
$store = new Cedar\PolicyStore("dt");
$store->loadString("p1",
    'permit(principal, action, resource) when {'
    . ' context.now < datetime("2026-06-01T00:00:00Z")'
    . ' && context.window > duration("30m")'
    . ' && context.profile.createdAt < context.now'
    . ' && context.windows.contains(duration("1h"))'
    . ' };');
$c = new Cedar\AuthorizationClient($store);

$req = function (string $now) {
    return [
        "policyStoreId" => "dt",
        "principal" => ["entityType" => "User",   "entityId" => "a"],
        "action"    => ["actionType" => "Action", "actionId" => "x"],
        "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
        "context"   => ["contextMap" => [
            "now"     => ["datetime" => $now],
            "window"  => ["duration" => "1h"],
            "profile" => ["record" => [
                "createdAt" => ["datetime" => "2026-01-01T00:00:00Z"],
            ]],
            "windows" => ["set" => [
                ["duration" => "1h"],
                ["duration" => "2h"],
            ]],
        ]],
    ];
};

echo "allow: ", $c->isAuthorized($req("2026-05-01T12:00:00Z"))["decision"], PHP_EOL;
echo "deny:  ", $c->isAuthorized($req("2026-12-01T00:00:00Z"))["decision"], PHP_EOL;

/* duration methods dispatch on the injected value. */
$m = new Cedar\PolicyStore("dur");
$m->loadString("p1", 'permit(principal, action, resource) when { context.window.toHours() == 1 };');
$cm = new Cedar\AuthorizationClient($m);
echo "method:", $cm->isAuthorized([
    "policyStoreId" => "dur",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => ["window" => ["duration" => "60m"]]],
])["decision"], PHP_EOL;
?>
--EXPECT--
allow: ALLOW
deny:  DENY
method:ALLOW
