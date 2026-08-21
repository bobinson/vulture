<?php
$modules = ['csv' => 'modules/csv.php', 'pdf' => 'modules/pdf.php'];
$key = $_REQUEST['module'];
include $modules[$key];
