--TEST--
PolicyStore: loadString / policyIds with fluent interface
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore("store-1");
var_dump($store->policyIds());

$ret = $store->loadString("admin", "permit(principal, action, resource);");
var_dump($ret === $store);
var_dump($store->policyIds());

$store->loadString("reader", 'permit(principal, action == Action::"read", resource);');
var_dump($store->policyIds());
?>
--EXPECT--
array(0) {
}
bool(true)
array(1) {
  [0]=>
  string(5) "admin"
}
array(2) {
  [0]=>
  string(5) "admin"
  [1]=>
  string(6) "reader"
}
