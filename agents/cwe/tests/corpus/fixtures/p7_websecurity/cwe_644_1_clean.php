<?php
function banner() {
    echo htmlspecialchars($_SERVER['HTTP_USER_AGENT']);
}
