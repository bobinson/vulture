package org.sample.ledger;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LedgerController {
    private final LedgerStore store = new LedgerStore();

    @GetMapping("/ledgers/{name}")
    public ResponseEntity<Resource> get(@PathVariable String name) {
        return ResponseEntity.ok(new FileSystemResource(store.find(name)));
    }
}
