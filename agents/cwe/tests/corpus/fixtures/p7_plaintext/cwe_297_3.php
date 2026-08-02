<?php

function fetch_invoice(string $endpoint): string
{
    $ch = curl_init($endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    return curl_exec($ch);
}
