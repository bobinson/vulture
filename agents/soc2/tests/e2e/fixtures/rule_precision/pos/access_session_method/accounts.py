class AccountService:
    def __init__(self, store):
        self.store = store

    def update_email(self, session, new_email: str) -> None:
        self.store.set_email(session.account_id, new_email)
