<?php
class Importer {
    // R5 PHP collects the exception into a property array
    function row($r) {
        try {
            $this->rows[] = parse_row($r);
        } catch (\Exception $e) { // EXPECT: finding known-gap (residual, still reported): R5 PHP $this->errors[
            $this->errors[] = $e;
        }
    }
}
