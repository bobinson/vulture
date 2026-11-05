<?php // Pins: a Laravel-shaped controller action passes $request->input('f') straight to readfile; input is a request accessor on the Request-typed $request param.
class DocController
{
    public function show(Request $request)
    {
        readfile($request->input('f'));
    }
}
