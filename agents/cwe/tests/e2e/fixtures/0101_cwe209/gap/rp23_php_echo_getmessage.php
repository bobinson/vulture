<?php
try { run(); } catch (Exception $e) {
    // EXPECT-NEXT: clean  known-gap php echo getMessage
    echo $e->getMessage();
}
