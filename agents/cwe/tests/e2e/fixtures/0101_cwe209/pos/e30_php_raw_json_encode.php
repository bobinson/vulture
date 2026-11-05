<?php
try { run(); } catch (\Throwable $ex) {
  // EXPECT-NEXT: finding  php raw json encode
  $response->getBody()->write(json_encode(['error' => (string) $ex]));
}
