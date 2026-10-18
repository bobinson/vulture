<?php // Pins: escapeshellarg() quotes the $_GET value before it is concatenated into the shell_exec command string.
echo shell_exec('ls -l ' . escapeshellarg($_GET['dir']));
