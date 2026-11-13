package org.sample.ledger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LedgerStore {
    private static final String BASE = "/var/app/ledgers";

    public Path find(String fileName) {
        Path p = Paths.get(BASE, fileName); // EXPECT: finding check=cwe.input_validation.path_traversal
        if (!Files.exists(p)) { // EXPECT: finding check=cwe.input_validation.path_traversal
            throw new IllegalArgumentException("no such ledger");
        }
        return p;
    }
}
