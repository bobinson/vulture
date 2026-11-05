<?php
try { run(); } catch (\Exception $ex) {
  // EXPECT-NEXT: clean  php held-out clean
  $response->getBody()->write(json_encode(['error' => $ex->getCode()]));
}
