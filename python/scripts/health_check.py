from __future__ import annotations

import argparse
import time
import urllib.request
from dataclasses import dataclass


@dataclass
class CheckResult:
    ok: bool
    status: int | None
    elapsed: float
    error: str | None = None


def check(url: str, timeout: float = 2.0, retries: int = 2) -> CheckResult:
    """Perform a lightweight HTTP GET with retries and timing."""
    start = time.monotonic()
    attempts = 0
    last_error: Exception | None = None
    while attempts <= retries:
        attempts += 1
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return CheckResult(True, int(resp.getcode()), time.monotonic() - start)
        except Exception as exc:  # broad to keep CLI resilient
            last_error = exc
            if attempts > retries:
                break
            time.sleep(0.1)
    return CheckResult(False, None, time.monotonic() - start, str(last_error))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HTTP health check")
    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--retries", type=int, default=2)
    args = parser.parse_args(argv)
    result = check(args.url, timeout=args.timeout, retries=args.retries)
    print(
        f"ok={result.ok} status={result.status} "
        f"elapsed={result.elapsed:.3f}s error={result.error}"
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

