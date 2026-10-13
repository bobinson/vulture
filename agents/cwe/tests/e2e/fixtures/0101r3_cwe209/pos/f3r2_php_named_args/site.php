<?php
final class Outcome {
    public function __construct(public bool $ok, public ?string $error = null) {}
}
function charge(array $p): Outcome {
    try { gateway()->charge($p); return new Outcome(ok: true); }
    catch (\Throwable $e) { return new Outcome(error: $e->getMessage(), ok: false); }
}
class PayController {
    public function store($r) {
        $o = charge($r->all());
        if (!$o->ok) {
            return response()->json(['error' => $o->error], 500); // EXPECT: finding tp-F3-php-named
        }
    }
}
