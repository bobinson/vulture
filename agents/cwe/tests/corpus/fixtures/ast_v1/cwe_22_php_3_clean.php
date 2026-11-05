<?php // Pins: basename() on the $request->input('f') value before the Laravel-shaped controller action passes it to readfile.
class DocController
{
    public function show(Request $request)
    {
        readfile(basename($request->input('f')));
    }
}
