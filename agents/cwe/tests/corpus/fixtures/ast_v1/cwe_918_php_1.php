<?php // Pins: file_get_contents($u) where $u = $_GET['u']; the builtin that also fetches URLs takes a superglobal value.
$u = $_GET['u'];
echo file_get_contents($u);
