<?php // Pins: the include sits inside `if (strpos($full, $root) === 0) { ... }`, a containment guard on the realpath result.
$root = __DIR__ . '/pages/';
$full = realpath($root . $_REQUEST['p']);
if (strpos($full, $root) === 0) {
    include $full;
}
