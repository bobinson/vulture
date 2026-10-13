package dump

func dumpFault(f *os.File, err error) {
	// EXPECT-NEXT: finding  known-gap a short receiver whose declared type is a file is not read as non-peer
	f.Write([]byte(err.Error()))
}
