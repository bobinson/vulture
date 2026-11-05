void handle(Response& res) {
  try { run(); } catch (const std::exception& e) {
    // EXPECT-NEXT: finding  cpp res write e what
    res.write(e.what());
  }
}
