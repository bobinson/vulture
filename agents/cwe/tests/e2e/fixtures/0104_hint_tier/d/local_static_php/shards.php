<?php
class Layout {
    public static function hash($name) {
        return substr(md5($name), 0, 2) . '/' . $name;
    }
}
$file = '/srv/shards/' . Layout::hash($_GET['name']);
readfile($file); // EXPECT: finding check=cwe.input_validation.path_traversal
