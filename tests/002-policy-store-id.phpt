--TEST--
PolicyStore: id is auto-generated, or used as-is when explicitly supplied
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$auto = new Cedar\PolicyStore();
$id = $auto->id();
var_dump(is_string($id));
var_dump(strlen($id));

$explicit = new Cedar\PolicyStore("my-policy-store");
var_dump($explicit->id());

// auto-generated ids must differ between instances
$another = new Cedar\PolicyStore();
var_dump($id !== $another->id());
?>
--EXPECT--
bool(true)
int(32)
string(15) "my-policy-store"
bool(true)
