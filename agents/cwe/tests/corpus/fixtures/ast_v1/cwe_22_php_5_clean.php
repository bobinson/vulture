<?php // pins: 0104 WS-D - hash('sha256', ...) of a request value is a digest, so the read path is constant (negative)
$name = hash('sha256', $_GET['u']);
readfile('/srv/shelf/' . $name . '.png');
