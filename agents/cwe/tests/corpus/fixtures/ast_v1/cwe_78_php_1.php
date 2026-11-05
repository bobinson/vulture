<?php // Pins: a superglobal query value concatenated into the command string handed to the shell_exec builtin.
echo shell_exec('ls -l ' . $_GET['dir']);
