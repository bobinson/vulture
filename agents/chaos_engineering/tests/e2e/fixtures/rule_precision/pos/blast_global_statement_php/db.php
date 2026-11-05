<?php

$db = new PDO(getenv('DSN'));

function find_order($id)
{
    global $db;
    $stmt = $db->prepare('SELECT * FROM orders WHERE id = ?');
    $stmt->execute([$id]);
    return $stmt->fetch();
}
