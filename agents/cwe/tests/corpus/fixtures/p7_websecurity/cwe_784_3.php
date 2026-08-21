<?php
function gate() {
    if ($_COOKIE['is_admin'] === '1') {
        grant_admin();
    }
}
