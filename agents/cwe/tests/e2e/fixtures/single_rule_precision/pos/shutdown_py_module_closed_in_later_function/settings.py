# EXPECT-NEXT: finding
handle = open("settings.txt", encoding="utf-8")
SETTINGS = handle.read()


def shutdown():
    handle.close()
