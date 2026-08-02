<?php
function csrf_value($length) {
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= bin2hex(random_bytes(1));
    }
    return $out;
}
