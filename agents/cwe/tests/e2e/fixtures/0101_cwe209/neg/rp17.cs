class A { void M() { try { Run(); } catch (Exception ex) {
    // EXPECT-NEXT: clean
    Console.WriteLine(ex.ToString());
} } }
