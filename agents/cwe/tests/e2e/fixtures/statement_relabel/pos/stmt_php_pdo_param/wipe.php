<?php
function wipe(PDO $h, $id) {
  $h->exec("DELETE FROM t WHERE id = " . $id); // EXPECT: finding
}
