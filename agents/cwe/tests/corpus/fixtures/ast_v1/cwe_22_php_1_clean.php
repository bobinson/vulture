<?php // Pins: basename() on the $_GET value before it is concatenated under the fixed directory and passed to readfile.
readfile('/srv/docs/' . basename($_GET['f']));
