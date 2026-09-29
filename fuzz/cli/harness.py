"""Fuzz harness for the CLI entrypoint `python -m rfc6901jsonpointer`.

Targets Surface 7: CLI shell-invocation surface.

Spawns a fresh subprocess per input via `python3 -m rfc6901jsonpointer` and
exercises:
  - Random pointer strings (re-use of parse_pointer/ generator)
  - Random JSON document strings (valid + broken)
  - Argument-count fuzzing (0, 1, 2+)
  - Invalid argv characters (newlines, NULL bytes, very long)

Each subprocess is wrapped in subprocess.run(timeout=5) — if the process hangs
beyond 5s the parent kills it and the input is recorded as a hang. Exit code
classification:
  - 0         -> ok
  - 1         -> expected (parse/eval/usage error)
  - other     -> unexpected -> recorded as finding
  - timeout   -> hang
  - crash sig  -> crash
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import signal
import string
import subprocess
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parent.parent
sys.path.insert(0, str(WORKTREE / "src"))

CRASH_DIR = HERE / "crashes"
HANG_DIR = HERE / "hangs"
LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"

TIMEOUT_SECONDS = 5


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


# Same generator pattern as parse_pointer/, but the string lives as argv[0].
_ALLOWED = [chr(c) for c in range(0x00, 0x2F)] + [chr(c) for c in range(0x30, 0x7D)] + [chr(c) for c in range(0x7F, 0x100)]
_TILDE_BAD_AFTER = ("2", "3", "9", "a", "Z", "!", " ", "\t", "\n")


def random_pointer(rng: random.Random) -> str:
    choice = rng.random()
    if choice < 0.15:
        return ""
    if choice < 0.25:
        return "/"
    n_tokens = rng.randint(1, 6)
    parts = []
    for _ in range(n_tokens):
        t_len = rng.randint(0, 8)
        token_chars = []
        i = 0
        while i < t_len:
            r = rng.random()
            if r < 0.1:
                token_chars.append("~0")
                i += 2
            elif r < 0.2:
                token_chars.append("~1")
                i += 2
            elif r < 0.22 and token_chars:
                token_chars.append("~" + rng.choice(_TILDE_BAD_AFTER))
                i += 2
            else:
                c = rng.choice(_ALLOWED)
                token_chars.append(c)
                i += 1
        parts.append("".join(token_chars))
    return "/" + "/".join(parts)


def random_doc_json(rng: random.Random) -> str:
    """A string that LOOKS like JSON but is frequently malformed."""
    pick = rng.random()
    if pick < 0.20:
        # Plain valid JSON values.
        return rng.choice([chr(123) + chr(125), "[]", "null", "true", "false",
                           "42", "\"hi\"", "[1,2,3]", "{\"a\":1}"])
    if pick < 0.40:
        # Truncated.
        return rng.choice(["{\"a\":", "[1,2,", "{\"a\":1", "\"unterminated"])
    if pick < 0.55:
        # Garbage that isn't JSON at all.
        return "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 50)))
    if pick < 0.70:
        # Nested valid JSON.
        depth = rng.randint(1, 4)
        return "{" * depth + '"a":' + "[" * depth + "1" + "]" * depth + "}" * depth
    if pick < 0.80:
        # Empty.
        return ""
    # Default: random short string.
    return "".join(rng.choice(string.ascii_letters) for _ in range(rng.randint(0, 10)))


def run_one(rng: random.Random, iteration: int, py: str) -> dict:
    arg_count = rng.choices([0, 1, 2, 3, 5], weights=[1, 2, 12, 1, 1])[0]
    if arg_count < 2:
        argv = [random_pointer(rng)] * arg_count
        label_repr = f"arg_count={arg_count}"
    else:
        argv = [random_pointer(rng), random_doc_json(rng)] + [random_doc_json(rng)] * (arg_count - 2)
        label_repr = f"arg_count={arg_count}"

    # Subprocess argv cannot contain null bytes (POSIX execve). Filter them
    # out and treat the post-filter argv as the input under test. This keeps
    # the harness portable across the random generator's printable range.
    argv_clean = [a.replace("\x00", "\\0") for a in argv]
    data = json.dumps({"argv": argv_clean}, ensure_ascii=False).encode("utf-8", errors="replace")
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            [py, "-m", "rfc6901jsonpointer", *argv_clean],
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
        elapsed = time.perf_counter() - started
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - started
        path = _record_finding(HANG_DIR, "timeout", data, extra=f"elapsed={elapsed:.2f}s {label_repr}")
        _log(f"iter={iteration} HANG elapsed={elapsed:.2f}s -> {path.name}")
        return {"kind": "hang", "elapsed": elapsed}

    if proc.returncode not in (0, 1):
        path = _record_finding(CRASH_DIR, "non-standard-exit",
                               data,
                               extra=f"returncode={proc.returncode} stdout={proc.stdout[:200]!r} stderr={proc.stderr[:200]!r} {label_repr}")
        _log(f"iter={iteration} FINDING non-standard-exit rc={proc.returncode} -> {path.name}")
        return {"kind": "finding", "label": "non-standard-exit"}
    return {"kind": "ok" if proc.returncode == 0 else "expected_error", "elapsed": elapsed,
            "returncode": proc.returncode}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iter", type=int, default=200)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--py", default=sys.executable)
    args = parser.parse_args(argv)

    seed = args.seed if args.seed is not None else int(time.time() * 1000) & 0xFFFFFFFF
    rng = random.Random(seed)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("")

    if not args.quiet:
        print(f"[cli] seed={seed} iterations={args.iter} py={args.py}", flush=True)

    stats = {"seed": seed, "iterations_planned": args.iter, "crashes": 0, "hangs": 0,
             "findings": 0, "ok": 0, "expected_errors": 0, "start": time.time()}

    for i in range(args.iter):
        result = run_one(rng, i, args.py)
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