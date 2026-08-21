<?php
$target = '/var/tmp/incoming';
$mime = mime_content_type($_FILES['doc']['tmp_name']);
if ($mime !== 'application/pdf') {
    throw new RuntimeException('unsupported type');
}
move_uploaded_file($_FILES['doc']['tmp_name'], $target . '/' . bin2hex(random_bytes(8)));
