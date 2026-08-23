<?php
$target = '/var/tmp/incoming';
$ext = pathinfo($_FILES['doc']['name'], PATHINFO_EXTENSION);
if ($ext !== 'pdf') {
    throw new RuntimeException('unsupported type');
}
move_uploaded_file($_FILES['doc']['tmp_name'], $target . '/' . $ext);
