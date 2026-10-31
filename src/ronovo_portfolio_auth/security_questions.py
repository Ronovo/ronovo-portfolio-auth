"""Security questions for password resets."""
from typing import Optional

QUESTIONS = [
    "What is your favorite movie?",
    "What is your favorite book?",
    "What is your favorite TV show?",
    "What is your favorite video game?",
    "What is your favorite board game?",
    "What is your favorite card game?",
    "What is your favorite tabletop RPG?",
    "What is your favorite fictional character?",
    "What is your favorite song?",
    "What is your favorite band or musician?",
    "What is your favorite food?",
    "What is your favorite dessert?",
    "What is your favorite ice cream flavor?",
    "What is your favorite pizza topping?",
    "What is your favorite drink?",
    "What is your favorite animal?",
    "What is your favorite color?",
    "What is your favorite season?",
    "What is your favorite holiday?",
    "What is your favorite sport to watch?",
    "What is your favorite number?",
    "What is your favorite word?",
    "What was the first video game you played?",
    "What was the first game console you owned?",
    "What was your dream job as a child?",
    "What would you name a pet dragon?",
    "What would you name a boat?",
    "What would you name a tavern?",
    "Where would you go on a dream vacation?",
    "Who is your favorite video game character?",
]
MAX_ANSWER_LENGTH = 100
MAX_RESET_FAILURES = 5
RESET_LOCK_SECONDS = 15 * 60


def normalize_answer(answer) -> str:
    return " ".join(str(answer or "").lower().split())


def problem(question, answer) -> Optional[str]:
    """What is wrong with a question and answer being set, or None when they are fine"""
    if question not in QUESTIONS:
        return "Pick a security question."
    normalized = normalize_answer(answer)
    if not normalized:
        return "Answer your security question."
    if len(normalized) > MAX_ANSWER_LENGTH:
        return f"Keep the security answer to {MAX_ANSWER_LENGTH} characters or fewer."
    return None
