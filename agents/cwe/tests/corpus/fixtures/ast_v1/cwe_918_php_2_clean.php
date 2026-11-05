<?php // Pins: an early-exit host allowlist guard `if (!in_array(parse_url($u, PHP_URL_HOST), TRUSTED_HOSTS, true)) { exit(...); }` before curl_setopt.
const TRUSTED_HOSTS = ['api.example.test'];
$u = $_POST['url'];
if (!in_array(parse_url($u, PHP_URL_HOST), TRUSTED_HOSTS, true)) {
    exit('blocked host');
}
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $u);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
