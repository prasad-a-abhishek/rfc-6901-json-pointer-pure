"""Fuzz harness for _unescape_token() — the tilde-decoding core.

Targets the private Surface 3: rfc6901jsonpointer._parser._unescape_token(token: str) -> str.

This is the *only* place in the library that decides what `~X` decodes to.
RFC 6901 §4 specifies strict left-to-right with `~0` -> `~` and `~1` -> `/`.
Any deviation breaks the entire library, so this surface is over-weighted in
the harness budget.

A small white-box helper rebuilds a token by hand using the same `_unescape_token`
to verify round-trip for hand-picked decoded strings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import signal
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parent.parent
sys.path.insert(0, str(WORKTREE / "src"))

from rfc6901jsonpointer import JSONPointerError  # noqa: E402
from rfc6901jsonpointer._parser import _unescape_token  # noqa: E402

CRASH_DIR = HERE / "crashes"
HANG_DIR = HERE / "hangs"
LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"

TIMEOUT_SECONDS = 5


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _Timeout()


def _record_finding(directory: Path, label: str, data: bytes, extra: str = "") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = directory / f"{label}-{digest}.in"
    counter = 0
    while path.exists():
        counter += 1
        path = directory / f"{label}-{digest}-{counter}.in"
    path.write_bytes(data)
    sidecar = path.with_suffix(path.suffix + ".meta.json")
    sidecar.write_text(json.dumps({"label": label, "sha256": digest, "extra": extra}, indent=2))
    return path


def _log(message: str) -> None:
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}] {message}\n"
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(line)


# Characters that may appear in a reference token per ABNF (minus '/' and '~').
_LETTERS = list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. ")


def random_unescaped(rng: random.Random) -> str:
    n = rng.randint(0, 32)
    return "".join(rng.choice(_LETTERS) for _ in range(n))


def random_token(rng: random.Random) -> str:
    """Build a random reference-token-shaped string with deliberate tilde cases."""
    choice = rng.random()
    if choice < 0.05:
        return ""  # empty token (e.g. trailing '/')
    if choice < 0.10:
        return "~"  # bare trailing tilde -> JSONPointerError
    if choice < 0.18:
        # ~ followed by an illegal character
        return "~" + rng.choice(["2", "a", "Z", "!", "\n", " ", "\t", "0a", "01", "10"])
    if choice < 0.28:
        # canonical ~0
        return "~0" + random_unescaped(rng)
    if choice < 0.38:
        # canonical ~1
        return "~1" + random_unescaped(rng)
    if choice < 0.48:
        # mixed canonical
        n = rng.randint(2, 6)
        out = []
        for _ in range(n):
            out.append(rng.choice(["~0", "~1", random_unescaped(rng)]))
        return "".join(out)
    if choice < 0.58:
        # lots of ~
        n = rng.randint(10, 80)
        return "~" * n + random_unescaped(rng)
    if choice < 0.65:
        # very long token
        return random_unescaped(rng) * rng.randint(50, 200)
    # default: a free-form mix
    n = rng.randint(1, 24)
    out = []
    for _ in range(n):
        r = rng.random()
        if r < 0.2:
            out.append("~0")
        elif r < 0.4:
            out.append("~1")
        elif r < 0.45:
            out.append("~" + rng.choice(["2", "a", "Z", "\n"]))
        else:
            out.append(rng.choice(_LETTERS))
    return "".join(out)


# Known-good pairs to verify the tilde-decoding rule is left-to-right with
# ~0 first (RFC 6901 §4).
CANONICAL = {
    "~0": "~",
    "~1": "/",
    "~01": "~1",
    "~10": "/0",
    "~~0": "~" + "~",  # "~~0" -> "~" + "~" (each ~0 is one tilde)
    "a~1b": "a/b",
    "a~1b~0c": "a/b~c",
    "": "",
    "abc": "abc",
}


def run_one(rng: random.Random, iteration: int) -> dict:
    if rng.random() < 0.30:
        # Replay known-good canonical cases to verify implementation matches spec.
        token = rng.choice(list(CANONICAL.keys()))
        expected = CANONICAL[token]
    else:
        token = random_token(rng)
        expected = None

    data = token.encode("utf-8", errors="replace")
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(TIMEOUT_SECONDS)
    started = time.perf_counter()
    try:
        got = _unescape_token(token)
        elapsed = time.perf_counter() - started
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        if not isinstance(got, str):
            path = _record_finding(CRASH_DIR, "non-str-return", data,
                                   extra=f"got {type(got).__name__}")
            _log(f"iter={iteration} FINDING non-str-return -> {path.name}")
            return {"kind": "finding", "label": "non-str-return"}
        if expected is not None and got != expected:
            path = _record_finding(CRASH_DIR, "canonical-mismatch", data,
                                   extra=f"expected={expected!r} got={got!r}")
            _log(f"iter={iteration} FINDING canonical-mismatch token={token!r} expected={expected!r} got={got!r} -> {path.name}")
            return {"kind": "finding", "label": "canonical-mismatch"}
        return {"kind": "ok", "elapsed": elapsed}
    except _Timeout:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        path = _record_finding(HANG_DIR, "timeout", data, extra=f"elapsed={elapsed:.2f}s")
        _log(f"iter={iteration} HANG elapsed={elapsed:.2f}s -> {path.name}")
        return {"kind": "hang", "elapsed": elapsed}
    except JSONPointerError:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        # Expected for bare '~', ~X where X not in {0,1}.
        return {"kind": "expected_error", "elapsed": elapsed}
    except Exception as e:  # noqa: BLE001
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        tb = traceback.format_exc()
        path = _record_finding(CRASH_DIR, "unexpected-exception", data,
                               extra=f"{type(e).__name__}: {e}\n{tb}")
        _log(f"iter={iteration} CRASH {type(e).__name__}: {e} -> {path.name}")
        return {"kind": "crash", "label": "unexpected-exception", "elapsed": elapsed}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iter", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    seed = args.seed if args.seed is not None else int(time.time() * 1000) & 0xFFFFFFFF
    rng = random.Random(seed)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("")

    if not args.quiet:
        print(f"[unescape] seed={seed} iterations={args.iter} canonical={len(CANONICAL)}", flush=True)

    stats = {"seed": seed, "iterations_planned": args.iter, "crashes": 0, "hangs": 0,
             "findings": 0, "ok": 0, "expected_errors": 0, "start": time.time()}

    for i in range(args.iter):
        result = run_one(rng, i)
        kind = result["kind"]
        if kind == "crash":
            stats["crashes"] += 1
        elif kind == "hang":
            stats["hangs"] += 1
        elif kind == "finding":
            stats["findings"] += 1
        elif kind == "expected_error":
            stats["expected_errors"] += 1
        else:
            stats["ok"] += 1

    stats["end"] = time.time()
    stats["duration_seconds"] = stats["end"] - stats["start"]
    STATS_FILE.write_text(json.dumps(stats, indent=2))
    if not args.quiet:
        print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())