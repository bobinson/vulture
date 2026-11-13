<?php
$blocked = ['.htaccess', 'config.php', 'site-config.php'];
$file = $_GET['file'];
$target = in_array($file, $blocked) ? 'index.html' : $file;
readfile('/var/www/static/' . $target); // EXPECT: finding check=cwe.input_validation.path_traversal
