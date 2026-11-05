# pins: a command-line argument concatenated into a command string that os.system hands to a shell - unknown(argv) reported through the command parameter heuristic (positive)
import os
import sys

target = sys.argv[1]
listing = "ls -l " + target
os.system(listing)
