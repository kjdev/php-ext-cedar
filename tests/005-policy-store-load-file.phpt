--TEST--
PolicyStore: loadFile reads a policy from disk
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$path = tempnam(sys_get_temp_dir(), "cedar_");
file_put_contents($path, "permit(principal, action, resource);");

try {
    $store = new Cedar\PolicyStore();
    $store->loadFile("p1", $path);
    var_dump($store->policyIds());
} finally {
    @unlink($path);
}
?>
--EXPECT--
array(1) {
  [0]=>
  string(2) "p1"
}
