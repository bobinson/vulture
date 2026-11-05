<?php
function toPublicMessage(Throwable $e): string {
  return $e->getMessage();
}
try { run(); } catch (\Exception $ex) {
  $response->getBody()->write(toPublicMessage($ex)); // EXPECT: finding tp-php-defined-public-renders
}
