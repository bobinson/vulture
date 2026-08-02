<?php
function start() {
    authorize($_SESSION['is_admin']);
}
