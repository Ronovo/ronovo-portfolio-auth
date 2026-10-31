from ronovo_portfolio_auth import security_questions as sq


def test_the_list_has_thirty_distinct_questions():
    assert len(sq.QUESTIONS) == 30
    assert len(set(sq.QUESTIONS)) == 30
    assert all(q.endswith("?") for q in sq.QUESTIONS)


def test_answers_are_compared_without_case_or_spacing():
    assert sq.normalize_answer("  Blue   Whale ") == "blue whale"
    assert sq.normalize_answer(None) == ""


def test_problem_checks_the_question_and_answer():
    assert sq.problem("Made up?", "x") == "Pick a security question."
    assert sq.problem(sq.QUESTIONS[0], "   ") == "Answer your security question."
    assert sq.problem(sq.QUESTIONS[0], "x" * (sq.MAX_ANSWER_LENGTH + 1)).startswith("Keep the security answer")
    assert sq.problem(sq.QUESTIONS[0], "Blue") is None
