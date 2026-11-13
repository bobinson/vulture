package svc

import "os"

func Present(filePath string) bool {
	_, err := os.Stat(filePath) // EXPECT: finding check=cwe.input_validation.path_traversal
	return err == nil
}
