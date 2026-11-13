package svc

import "os"

func open(p string) (*os.File, error) { return os.Open(p) }
