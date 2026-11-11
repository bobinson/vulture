package org.sample.gallery;

import java.io.File;
import java.io.FileNotFoundException;

public class GalleryShelf {
    private final File root = new File("/srv/gallery");

    /** The stored picture for a client-supplied name. */
    public File lookup(String fileName) throws FileNotFoundException {
        File candidate = new File(root, fileName); // EXPECT: finding check=cwe.input_validation.path_traversal
        if (!candidate.exists()) {
            throw new FileNotFoundException(fileName);
        }
        return candidate;
    }
}
