<?php
// Feature 0101 tuning fixture: invented identifiers.
function openBox($cipher, $nonce, $kp) {
    try {
        return sodium_crypto_box_open($cipher, $nonce, $kp);
    } catch (\SodiumException $e) { // EXPECT: finding
        return ['ok' => false, 'error' => $e];
    }
}
