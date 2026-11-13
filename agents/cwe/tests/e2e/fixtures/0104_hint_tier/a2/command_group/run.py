import os
import subprocess


def run_script(file_path):
    # EXPECT-NEXT: finding check=cwe.injection.command SINKS=7_12_17
    subprocess.run("sh " + file_path, shell=True)


def show_file(file_name):
    # EXPECT-NEXT: clean check=cwe.injection.command
    os.system("cat " + file_name)


def pack_file(file_path):
    # EXPECT-NEXT: clean check=cwe.injection.command
    os.popen("gzip " + file_path)
