<?php
function pump($sock) {
    $buf = [];
    while (true) {
        $chunk = socket_read($sock, 2048);
        if ($chunk === false) { break; }
        // EXPECT-NEXT: finding infinite loop, sized read in the body, uncapped growth
        $buf[] = $chunk;
    }
    return $buf;
}
