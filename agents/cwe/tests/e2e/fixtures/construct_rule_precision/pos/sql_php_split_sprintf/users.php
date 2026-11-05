<?php
function find($conn, $cols) {
    $sql = sprintf("SELECT %s", $cols); // EXPECT: finding
    $sql .= " FROM accounts";
    return mysqli_query($conn, $sql);
}
