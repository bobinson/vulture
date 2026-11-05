<?php
function slurp($sock) {
    $buf = '';
    while (!feof($sock)) {
        // EXPECT-NEXT: finding string concatenation of every read until end of stream
        $buf .= fread($sock, 8192);
    }
    return $buf;
}

function join_names($names) {
    $out = '';
    foreach ($names as $n) {
        // EXPECT-NEXT: clean concatenation over an in-memory array
        $out .= $n;
    }
    return $out;
}
