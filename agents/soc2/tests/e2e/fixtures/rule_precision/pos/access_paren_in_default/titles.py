from .store import save_title


def update_title(text, close=")", request=None):
    save_title(text + close)
