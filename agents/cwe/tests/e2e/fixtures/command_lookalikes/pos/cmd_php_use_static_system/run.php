<?php
use App\Runner;
function run() {
    Runner::system($_GET["c"]); // EXPECT: finding
}
