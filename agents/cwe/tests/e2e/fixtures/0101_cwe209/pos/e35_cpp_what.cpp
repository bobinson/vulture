void h(Response& res) {
  try { run(); } catch (const std::exception& ex) {
    // EXPECT-NEXT: finding  cpp what
    res.write(ex.what());
  }
}
