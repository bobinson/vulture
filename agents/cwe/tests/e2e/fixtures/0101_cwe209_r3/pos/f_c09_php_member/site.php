<?php
class LedgerController {
  private function load($id) {
    $o = new Outcome();
    try { $this->store->read($id); } catch (Exception $e) { $o->error = $e->getMessage(); }
    return $o;
  }
  public function show($request, $response, $id) {
    $outcome = $this->load($id);
    return $response->json(['error' => $outcome->error]); // EXPECT: finding tp
  }
}
