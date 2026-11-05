<?php
class Outcome { public $error; }
function load2($id) {
    $o = new Outcome();
    try { db($id); } catch (Exception $e) { $o->error = $e->getMessage(); }
    return $o;
}
function handle2($id) {
    $o = load2($id);
    return response()->json(['error' => $o->error], 500); // probe tp-php-F1-arrow
}
function load3($id) {
    try { db($id); return ['ok' => true]; } catch (Exception $e) { return ['ok' => false, 'error' => $e->getMessage()]; }
}
function handle3($id) {
    $r = load3($id);
    return response()->json(['error' => $r['error']], 500); // EXPECT: clean tp-php-subscript(K-gap)
}
