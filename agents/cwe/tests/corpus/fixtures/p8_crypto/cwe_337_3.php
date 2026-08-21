<?php
function csrf_value($length) {
    mt_srand(time());
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        $out .= chr(97 + mt_rand(0, 25));
    }
    return $out;
}
