<?php
function remember($card) {
    setcookie('cvv', $card['cvv'], ['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);
}
