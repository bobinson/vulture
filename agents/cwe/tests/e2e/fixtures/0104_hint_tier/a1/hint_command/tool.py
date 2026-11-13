import os
import subprocess


def run_tool(file_path):
    # EXPECT-NEXT: finding check=cwe.injection.command HINT=param_hint
    subprocess.call("cat " + file_path, shell=True)
    # EXPECT-NEXT: finding check=cwe.injection.command HINT=param_hint
    os.system("wc " + file_path)
    # EXPECT-NEXT: finding check=cwe.input_validation.path_traversal HINT=param_hint
    return open(file_path).read()
