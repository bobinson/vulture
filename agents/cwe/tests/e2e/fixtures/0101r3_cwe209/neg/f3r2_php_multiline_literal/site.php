<?php
final readonly class Outcome {
    public function __construct(
        public bool $ok,
        public ?string $error = null,
    ) {}
}
function charge(array $p): Outcome {
    try { gateway()->charge($p); return new Outcome(true); }
    catch (\Throwable $e) { report($e); return new Outcome(false, 'PAYMENT_FAILED'); }
}
class PayController {
    public function store($r) {
        $o = charge($r->all());
        if (!$o->ok) {
            return response()->json(['error' => $o->error], 500); // EXPECT: clean literal-code-php-multiline
        }
    }
}
