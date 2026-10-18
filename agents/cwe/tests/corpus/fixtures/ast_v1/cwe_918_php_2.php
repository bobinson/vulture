<?php // Pins: curl_setopt($ch, CURLOPT_URL, $u) where $u = $_POST['url']; the request target is argument 2 of the builtin.
const TRUSTED_HOSTS = ['api.example.test'];
$u = $_POST['url'];
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $u);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
echo curl_exec($ch);
