from .store import hash_password, save_hash


def update_password(username: str, new_password: str) -> None:
    save_hash(username, hash_password(new_password))
