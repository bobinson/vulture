package org.sample.gallery;

import java.io.File;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GalleryController {
    private final GalleryShelf shelf = new GalleryShelf();

    @GetMapping("/gallery")
    public ResponseEntity<Resource> picture(@RequestParam String name) throws Exception {
        File file = shelf.lookup(name);
        return ResponseEntity.ok(new FileSystemResource(file));
    }
}
