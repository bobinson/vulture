import random

GREETINGS = ("hello", "hey", "hi")


def pick_greeting() -> str:
    greeting = random.choice(GREETINGS)
    return greeting.capitalize()
