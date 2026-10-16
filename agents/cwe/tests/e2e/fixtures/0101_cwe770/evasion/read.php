<?php
function drain($sock) {
    $lines = [];
    while (($line = fgets($sock)) !== false) {
        // EXPECT-NEXT: finding E35 PHP append-by-subscript, fgets
        $lines[] = $line;
    }
    return $lines;
}
