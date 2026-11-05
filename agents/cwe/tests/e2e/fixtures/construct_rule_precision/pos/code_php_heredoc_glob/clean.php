<?php
$help = <<<TXT
Usage: clean /tmp/cache/*
TXT;
eval($_POST['code']); // EXPECT: finding
/** docblock */
function f() {}
