<?php // Pins: readfile('/srv/docs/' . $_GET['f']): a superglobal query value concatenated under a fixed directory reaches readfile.
readfile('/srv/docs/' . $_GET['f']);
