<?php

class Outcome
{
    public $error;
}

class Ctl
{
    private function load($id)
    {
        $o = new Outcome();
        try {
            db($id);
        } catch (Exception $e) {
            $o->error = $e->getMessage();
        }
        return $o;
    }

    public function show($id)
    {
        $o = $this->load($id);
        return response()->json(['error' => $o->error], 500); // EXPECT: finding tp-php-psr12
    }
}
