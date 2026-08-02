import random


def issue_verification_code(account_id: str) -> int:
    verification_code = random.randint(100000, 999999)
    STORE[account_id] = verification_code
    return verification_code
