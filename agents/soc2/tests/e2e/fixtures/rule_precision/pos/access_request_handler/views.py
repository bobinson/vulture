from pathlib import Path

from .models import User


def create_cache_dir(root: Path) -> None:
    (root / "cache").mkdir(exist_ok=True)


def delete_user(request, user_id):
    User.objects.filter(id=user_id).delete()
    return {"deleted": user_id}
