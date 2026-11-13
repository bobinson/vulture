import os
import subprocess


def run_command(cmd):
    # EXPECT-NEXT: finding check=cwe.injection.command HINT=command_param
    subprocess.call(cmd, shell=True)
    # EXPECT-NEXT: finding check=cwe.injection.command HINT=command_param
    os.system("ls " + cmd)
