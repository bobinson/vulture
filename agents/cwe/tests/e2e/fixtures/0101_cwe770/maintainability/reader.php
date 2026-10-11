<?php
function slurp($h) {
    $rows = [];
    while (($line = fgets($h)) !== false) {
        // EXPECT-NEXT: finding PHP push operator, fgets pull
        $rows[] = $line;
    }
    return $rows;
}
function slurp2($h) {
    $rows = [];
    while (($line = fgets($h)) !== false) {
        // EXPECT-NEXT: finding PHP array_push
        array_push($rows, $line);
    }
    return $rows;
}
