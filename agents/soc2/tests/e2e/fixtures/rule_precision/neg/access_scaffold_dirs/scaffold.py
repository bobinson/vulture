from pathlib import Path


def create_resource_dirs(skill_dir: Path, skill_name: str, resources: list[str]) -> None:
    for resource in resources:
        (skill_dir / skill_name / resource).mkdir(parents=True, exist_ok=True)


def delete_build_dirs(root: Path) -> None:
    for path in root.glob("build-*"):
        path.rmdir()
