<?php

function request_otp(): void
{
    $phone = $_POST['phone'] ?? '';
    $code = random_int(100000, 999999);
    send_sms_code($phone, $code);
    echo json_encode(['ok' => true]);
}
