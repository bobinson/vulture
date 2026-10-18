<?php // Pins: an early-exit host guard `if (parse_url($u, PHP_URL_HOST) !== 'api.example.test') { exit(...); }` before file_get_contents($u).
$u = $_GET['u'];
if (parse_url($u, PHP_URL_HOST) !== 'api.example.test') {
    exit('blocked host');
}
echo file_get_contents($u);
