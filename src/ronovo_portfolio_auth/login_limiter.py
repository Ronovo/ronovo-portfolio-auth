"""Locks a username out for a while after too many wrong passwords in a row."""
import threading
import time
from typing import Callable

MAX_FAILURES = 5
LOCK_SECONDS = 60


class LockedOut(Exception):
    """The username is locked out. The message is shown to the player."""

    def __init__(self):
        super().__init__("Too many wrong passwords. Wait a minute and try again.")


class LoginLimiter:
    """Counts wrong passwords per username in memory, so it limits each server process separately."""

    def __init__(self, max_failures: int = MAX_FAILURES, lock_seconds: float = LOCK_SECONDS):
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._failures: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def attempt(self, username: str, check: Callable[[], bool]) -> bool:
        """Runs check(), the password check, and returns its result. Raises LockedOut instead while the username
        is locked. Each try is counted before check() runs, so tries sent at the same moment can't all slip in
        under the limit."""
        key = username.lower()
        with self._lock:
            failures, locked_until = self._failures.get(key, (0, 0.0))
            if time.monotonic() < locked_until or failures >= self.max_failures:
                raise LockedOut()
            self._failures[key] = (failures + 1, 0.0)
        valid = check()
        with self._lock:
            if valid:
                self._failures.pop(key, None)
            elif self._failures.get(key, (0, 0.0))[0] >= self.max_failures:
                self._failures[key] = (0, time.monotonic() + self.lock_seconds)
        return valid
