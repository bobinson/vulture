<?php

function send_sms_code(string $phone, int $code): void
{
    deliver_message_to_gateway($phone, "Your code is $code");
}
