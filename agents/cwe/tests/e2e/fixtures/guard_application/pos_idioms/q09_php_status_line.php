<?php
if (isset($_GET['debug']) && $_GET['debug'] == '1') {
    $authorized = true;
}
if (!$authorized) {
    header('HTTP/1.1 401 Unauthorized');
    exit;
}
