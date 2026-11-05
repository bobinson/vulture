<?php // Pins: include $full where $full = realpath($root . $_REQUEST['p']); realpath is a builder, include is a synthetic path-sink call.
$root = __DIR__ . '/pages/';
$full = realpath($root . $_REQUEST['p']);
include $full;
