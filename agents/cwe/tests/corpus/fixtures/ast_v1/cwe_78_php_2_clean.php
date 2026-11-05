<?php // Pins: $dir = escapeshellarg($_GET['dir']) before the backtick shell command interpolates $dir.
$dir = escapeshellarg($_GET['dir']);
echo `ls -l $dir`;
