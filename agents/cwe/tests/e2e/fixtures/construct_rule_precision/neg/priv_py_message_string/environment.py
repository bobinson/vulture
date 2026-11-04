def root_user_finding(file_path, i):
    return {
        "title": "Container runs as root user",  # EXPECT: clean
        "description": f"Dockerfile {file_path.name} runs as root",  # EXPECT: clean
        "line_start": i,
    }
