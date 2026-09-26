from __future__ import annotations
"""
Hunter Runtime — File System Utilities
Provides atomic persistence operations and POSIX file locking to prevent state corruption.
"""

import fcntl
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


class LockTimeoutError(TimeoutError):
    """Raised when file lock acquisition times out."""
    pass


class FileLock:
    """
    POSIX advisory file lock (fcntl.flock) with timeout and context manager support.
    Safely coordinates concurrent processes writing to mission state and logs.
    """

    def __init__(self, lock_path: Path | str, timeout: float = 10.0, poll_interval: float = 0.05) -> None:
        self.lock_path = Path(lock_path)
        self.timeout = float(timeout)
        self.poll_interval = float(poll_interval)
        self._fd: int | None = None

    def acquire(self) -> None:
        if self.lock_path.is_symlink():
            raise PermissionError(f"Symlink detected at lock path: {self.lock_path}")

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT, 0o600)

        start_time = time.monotonic()
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._fd = fd
                return
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() - start_time >= self.timeout:
                    os.close(fd)
                    raise LockTimeoutError(
                        f"Timed out acquiring lock on {self.lock_path} after {self.timeout}s"
                    ) from exc
                time.sleep(self.poll_interval)

    def release(self) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()


def atomic_write_json(target_path: Path, data: dict[str, Any]) -> None:
    """
    Write JSON data atomically to target_path.

    Writes to a temporary file first, then os.replace() to the target.
    This guarantees that the target file is either fully updated or
    left intact if the process crashes mid-write.
    """
    if target_path.is_symlink():
        raise PermissionError(f"Symlink detected at target path: {target_path}")
    target_path = target_path.resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Use a temp file in the same directory to ensure they are on the same filesystem,
    # which is required for os.replace to be atomic.
    fd, temp_path_str = tempfile.mkstemp(dir=target_path.parent, prefix=".tmp-", suffix=".json")
    temp_path = Path(temp_path_str)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())

        # os.replace is atomic on POSIX and Windows
        os.replace(temp_path, target_path)

    except Exception:
        # Cleanup the temp file if something went wrong before the replace
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
