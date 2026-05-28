--TEST--
PolicyStore: loadFile throws PolicyParseException when the file cannot be opened
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore();
$path = __DIR__ . "/_no_such_file.cedar";
try {
    $store->loadFile("p1", $path);
    echo "no exception\n";
} catch (Cedar\Exception\PolicyParseException $e) {
    echo get_class($e), "\n";
    echo $e->getMessage(), "\n";
}
?>
--EXPECTF--
Cedar\Exception\PolicyParseException
failed to open cedar policy file "%s"
