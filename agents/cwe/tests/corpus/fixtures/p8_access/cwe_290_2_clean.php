<?php
$trusted = ['10.0.0.5', '127.0.0.1'];
$authorized = false;
if (in_array($_SERVER['REMOTE_ADDR'] ?? '', $trusted, true)) {
    $authorized = true;
}
if (!$authorized && empty($_SESSION['user_id'])) {
    http_response_code(403);
    exit;
}
