<?php
$cmd = "rm -f
  /tmp/cache/*";
eval($_POST['code']); // EXPECT: finding
/** docblock */
function f() {}
