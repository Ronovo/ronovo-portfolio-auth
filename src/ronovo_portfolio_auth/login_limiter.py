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
    """Counts wrong passwords per username in memory, so it limits each server process separately. A username's
    count is forgotten lock_seconds after its last wrong password, or when its lock ends."""

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
            now = time.monotonic()
            self._failures = {k: entry for k, entry in self._failures.items() if entry[1] > now}
            failures = self._failures.get(key, (0, 0.0))[0]
            if failures >= self.max_failures:
                raise LockedOut()
            self._failures[key] = (failures + 1, now + self.lock_seconds)
        valid = check()
        with self._lock:
            if valid:
                self._failures.pop(key, None)
            elif key in self._failures and self._failures[key][0] >= self.max_failures:
                self._failures[key] = (self.max_failures, time.monotonic() + self.lock_seconds)
        return valid
