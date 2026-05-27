--TEST--
PolicyStore: loadFile reads a policy from disk
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$path = __DIR__ . "/_tmp.cedar";
file_put_contents($path, "permit(principal, action, resource);");

$store = new Cedar\PolicyStore();
$store->loadFile("p1", $path);
var_dump($store->policyIds());

unlink($path);
?>
--EXPECT--
array(1) {
  [0]=>
  string(2) "p1"
}
