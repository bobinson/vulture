<?php
function readAll($sock) {
    $out = [];
    while (!feof($sock)) {
        // EXPECT-NEXT: finding fread until end of stream
        $out[] = fread($sock, 8192);
    }
    return $out;
}
