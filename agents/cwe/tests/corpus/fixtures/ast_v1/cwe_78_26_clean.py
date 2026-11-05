# pins: the same command-line argument as an element of an argument list that run executes with no shell - unknown(argv), neither shelled nor built (clean)
import subprocess
import sys

target = sys.argv[1]
listing = ["ls", "-l", target]
subprocess.run(listing)
