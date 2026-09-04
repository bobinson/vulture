<?php
/**
 * @param string $path the path
 */
function a($path) {
    try { risky(); } catch (ValueError) { }
    try { risky(); } catch (A | B $e) { }
    try { risky(); } catch (A | B $e) { report($e); }
    $h = @fopen($path, 'r');
    $ok = fopen($path, 'r');
}
