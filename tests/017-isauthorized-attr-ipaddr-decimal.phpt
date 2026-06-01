--TEST--
AuthorizationClient::isAuthorized: AttributeValue Union 'ipaddr' and 'decimal' members
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$ip = new Cedar\PolicyStore("ip");
$ip->loadString("p1", 'permit(principal, action, resource) when { context.client.isInRange(ip("10.0.0.0/8")) };');
$c = new Cedar\AuthorizationClient($ip);
echo "ip in:  ", $c->isAuthorized([
    "policyStoreId" => "ip",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => ["client" => ["ipaddr" => "10.1.2.3"]]],
])["decision"], PHP_EOL;

echo "ip out: ", $c->isAuthorized([
    "policyStoreId" => "ip",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => ["client" => ["ipaddr" => "192.168.0.1"]]],
])["decision"], PHP_EOL;

$dec = new Cedar\PolicyStore("dec");
$dec->loadString("p1", 'permit(principal, action, resource) when { context.score.lessThan(decimal("5.0")) };');
$c = new Cedar\AuthorizationClient($dec);
echo "dec lt: ", $c->isAuthorized([
    "policyStoreId" => "dec",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => ["score" => ["decimal" => "3.5"]]],
])["decision"], PHP_EOL;

echo "dec gt: ", $c->isAuthorized([
    "policyStoreId" => "dec",
    "principal" => ["entityType" => "User",   "entityId" => "a"],
    "action"    => ["actionType" => "Action", "actionId" => "x"],
    "resource"  => ["entityType" => "Doc",    "entityId" => "d"],
    "context"   => ["contextMap" => ["score" => ["decimal" => "9.0"]]],
])["decision"], PHP_EOL;
?>
--EXPECT--
ip in:  ALLOW
ip out: DENY
dec lt: ALLOW
dec gt: DENY
