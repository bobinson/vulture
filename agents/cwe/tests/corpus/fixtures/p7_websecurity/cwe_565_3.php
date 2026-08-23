<?php
function start() {
    authorize($_COOKIE['is_admin']);
}
