<?php
try { run(); } catch (\Exception $ex) {
  // EXPECT-NEXT: finding  php held-out
  $response->getBody()->write($ex->getMessage());
}
