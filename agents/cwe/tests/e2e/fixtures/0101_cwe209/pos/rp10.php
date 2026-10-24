<?php
try { run(); } catch (\Exception $e) {
  // EXPECT-NEXT: finding
  $response->getBody()->write($e->getTraceAsString());
}
