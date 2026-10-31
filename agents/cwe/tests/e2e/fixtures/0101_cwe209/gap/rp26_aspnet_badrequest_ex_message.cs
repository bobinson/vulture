class Ctl {
  IActionResult Get() {
    try { Run(); } catch (Exception ex) {
      // EXPECT-NEXT: clean  known-gap aspnet BadRequest ex Message
      return BadRequest(ex.Message);
    }
    return Ok();
  }
}
