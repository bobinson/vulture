<?php
function gate() {
    if ($_SESSION['is_admin'] === '1') {
        grant_admin();
    }
}
