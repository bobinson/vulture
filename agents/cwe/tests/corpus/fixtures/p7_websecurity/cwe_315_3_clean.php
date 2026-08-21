<?php
function remember($card) {
    setcookie('cvv_verified', $card['ok'], ['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);
}
