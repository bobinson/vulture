import subprocess


def transcode(file_name):
    # EXPECT-NEXT: finding check=cwe.injection.command
    subprocess.run(f"ffmpeg -i in/{file_name} out/{file_name}.mp4", shell=True, check=True)
