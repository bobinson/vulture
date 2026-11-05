"""A script that closes its output handle but never its input handle."""


def encrypt(source, target, key):
    # EXPECT-NEXT: finding
    plain = open(source, "r")
    sealed = open(target, "w")
    for char in plain.read():
        sealed.write(chr(ord(char) ^ key))
    sealed.close()
