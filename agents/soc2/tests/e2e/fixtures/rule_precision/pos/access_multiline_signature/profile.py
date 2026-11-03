from .store import save


def update_profile(
    current_user: object,
    changes: dict[str, str],
) -> None:
    save(current_user.id, changes)
