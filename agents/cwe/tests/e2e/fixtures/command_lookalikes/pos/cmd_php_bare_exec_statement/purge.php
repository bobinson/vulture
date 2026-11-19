<?php
function f() { exec("DELETE FROM t WHERE id = " . $_GET["id"]); } // EXPECT: finding
