<?php
function pump($sock) {
    $frames = [];
    while (true) {
        $got = socket_recv($sock, $data, 2048, 0);
        if ($got === 0) { break; }
        // EXPECT-NEXT: finding infinite loop, receive in the body, uncapped growth
        $frames[] = $data;
    }
    return $frames;
}
