<?php
function wipe() {
    Db::exec("DELETE FROM t WHERE id = " . $_GET["id"]); // EXPECT: finding
}
