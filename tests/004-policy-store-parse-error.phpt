--TEST--
PolicyStore: parse failure and duplicate policy id raise PolicyParseException
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
$store = new Cedar\PolicyStore();

try {
    $store->loadString("broken", "this is not a cedar policy at all");
} catch (Cedar\Exception\PolicyParseException $e) {
    echo "caught: ", $e->getMessage(), PHP_EOL;
}

// duplicate policyId
$store->loadString("dup", "permit(principal, action, resource);");
try {
    $store->loadString("dup", "permit(principal, action, resource);");
} catch (Cedar\Exception\PolicyParseException $e) {
    echo "caught: ", $e->getMessage(), PHP_EOL;
}
?>
--EXPECTF--
caught: failed to parse cedar policy "broken"
caught: policy id "dup" already loaded
