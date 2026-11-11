<?php
function present($filePath) {
    return is_file($filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
}
function meta($fileName) {
    return stat($fileName); // EXPECT: finding check=cwe.input_validation.path_traversal
}
