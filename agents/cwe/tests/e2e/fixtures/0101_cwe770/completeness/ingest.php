<?php
function slurp($sock) {
    $lines = [];
    while (($line = fgets($sock)) !== false) {
        // EXPECT-NEXT: finding php [] append
        $lines[] = $line;
    }
    return $lines;
}
