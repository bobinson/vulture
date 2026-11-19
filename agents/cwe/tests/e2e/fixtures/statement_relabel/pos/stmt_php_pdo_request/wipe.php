<?php
function wipe(PDO $h) {
  $h->exec("DELETE FROM t WHERE id = " . $_GET["id"]); // EXPECT: finding
}
