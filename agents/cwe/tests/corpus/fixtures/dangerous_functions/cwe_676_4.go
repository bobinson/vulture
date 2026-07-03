package sample

import "unsafe"

func size(x int64) uintptr {
	return unsafe.Sizeof(x)
}
