import pytest

from ronovo_portfolio_auth.login_limiter import LockedOut, LoginLimiter


def test_a_right_password_clears_the_count():
    limiter = LoginLimiter(max_failures=2)
    assert limiter.attempt("Player", lambda: False) is False
    assert limiter.attempt("player", lambda: True) is True
    assert limiter.attempt("PLAYER", lambda: False) is False
    assert limiter.attempt("player", lambda: False) is False


def test_too_many_wrong_passwords_lock_the_name_out():
    limiter = LoginLimiter(max_failures=2, lock_seconds=60)
    limiter.attempt("player", lambda: False)
    limiter.attempt("player", lambda: False)
    with pytest.raises(LockedOut, match="Wait a minute"):
        limiter.attempt("player", lambda: True)
    assert limiter.attempt("other", lambda: True) is True


def test_the_lock_ends_after_lock_seconds(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("ronovo_portfolio_auth.login_limiter.time.monotonic", lambda: now[0])
    limiter = LoginLimiter(max_failures=1, lock_seconds=60)
    limiter.attempt("player", lambda: False)
    with pytest.raises(LockedOut):
        limiter.attempt("player", lambda: True)
    now[0] += 61
    assert limiter.attempt("player", lambda: True) is True
