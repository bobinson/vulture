<?php // Pins: a backtick shell command interpolating $dir where $dir = $_GET['dir'] (backticks are a synthetic shell_exec call).
$dir = $_GET['dir'];
echo `ls -l $dir`;
