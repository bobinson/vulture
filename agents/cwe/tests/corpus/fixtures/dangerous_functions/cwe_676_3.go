package sample

import "unsafe"

func ptr(p *int) uintptr {
	return uintptr(unsafe.Pointer(p))
}
