--TEST--
cedar extension is loaded and exposes the expected classes
--SKIPIF--
<?php if (!extension_loaded("cedar")) die("skip cedar extension not loaded"); ?>
--FILE--
<?php
var_dump(extension_loaded("cedar"));
var_dump(class_exists(Cedar\PolicyStore::class));
var_dump(class_exists(Cedar\AuthorizationClient::class));
var_dump(class_exists(Cedar\Exception\PolicyParseException::class));
var_dump(class_exists(Cedar\Exception\EvaluationException::class));
var_dump(class_exists(Cedar\Exception\ResourceNotFoundException::class));

var_dump(is_subclass_of(Cedar\Exception\PolicyParseException::class, RuntimeException::class));
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
