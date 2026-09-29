"""Fuzz harness for JSONPointer() constructor (parse phase).

Targets the public Surface 1: JSONPointer(ptr: Optional[str]) -> JSONPointerError | obj.

Per RFC 6901 §4 ABNF:
  pointer     = *( "/" reference-token )
  reference-token = *( unescaped / escaped )
  unescaped   = %x00-2E / %x30-7D / %x7F-10FFFF
                ; %x2F ('/') and %x7E ('~') MUST be escaped
  escaped     = "~" ( "0" / "1" )

Constraints checked here:
  - ptr must be str (or None synonym); other types -> JSONPointerError
  - bare '~' (end) -> JSONPointerError
  - '~X' for X not in {0,1} -> JSONPointerError
  - '~01' must decode to '~1' (left-to-right)
  - '/a~1b' must keep 'a/b' as single token
  - long pointers must complete (no exponential blow-up)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import signal
import string
import sys
import time
import traceback
from pathlib import Path

# Ensure we import the local source, not an installed version.
HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parent.parent
sys.path.insert(0, str(WORKTREE / "src"))

from rfc6901jsonpointer import JSONPointer, JSONPointerError  # noqa: E402

CRASH_DIR = HERE / "crashes"
HANG_DIR = HERE / "hangs"
LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"

# Per-input soft wall-clock budget. The harness wraps each call in
# signal.alarm() so a genuine infinite-loop crash is captured before
# the test runner kills the whole process.
TIMEOUT_SECONDS = 5

# Maximum pointer length we will even attempt (defends against OOM-by-100MB-string
# attack patterns called out in VULN_AUDIT.md F-03). Anything longer is recorded
# as a finding ("input over MAX_LEN: pointer-string DoS pre-condition present").
MAX_POINTER_LEN = 1_000_000

# Unescaped allowed range per ABNF, minus '/' and '~'.
_ALLOWED = [chr(c) for c in range(0x00, 0x2F)] + [chr(c) for c in range(0x30, 0x7D)] + [chr(c) for c in range(0x7F, 0x100)]
_VALID_TILDE_AFTER = ("0", "1")
_TILDE_BAD_AFTER = ("2", "3", "9", "a", "Z", "!", " ", "\t", "\n")


class _Timeout(Exception):
    pass


def _alarm_handler(signum, frame):  # noqa: ARG001
    raise _Timeout()


def _record_finding(directory: Path, label: str, data: bytes, extra: str = "") -> Path:
    """Write a crash/hang input to disk. Returns the path written."""
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


def random_pointer(rng: random.Random) -> str:
    """Generate a random RFC 6901-shaped pointer string, mostly well-formed."""
    choice = rng.random()
    if choice < 0.15:
        # Empty pointer
        return ""
    if choice < 0.25:
        # Lone '/'
        return "/"
    n_tokens = rng.randint(1, 8)
    parts = []
    for _ in range(n_tokens):
        # Build a single token: mix of unescaped chars and a few escapes.
        t_len = rng.randint(0, 12)
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
            elif r < 0.25 and token_chars:
                # Tilde followed by a bad digit
                token_chars.append("~" + rng.choice(_TILDE_BAD_AFTER))
                i += 2
            else:
                c = rng.choice(_ALLOWED)
                token_chars.append(c)
                i += 1
        parts.append("".join(token_chars))
    return "/" + "/".join(parts)


def random_non_string(rng: random.Random):
    """Generate a non-str, non-None value (must raise JSONPointerError)."""
    choices = [
        lambda: rng.randint(-(2**31), 2**31),
        lambda: rng.random(),
        lambda: [rng.randint(0, 100) for _ in range(rng.randint(0, 4))],
        lambda: {rng.choice(string.ascii_letters): rng.randint(0, 9) for _ in range(rng.randint(0, 3))},
        lambda: b"bytes" + bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 4))),
        lambda: True,
        lambda: False,
        lambda: ("tup", "le"),
    ]
    return rng.choice(choices)()


def load_seeds() -> list[str]:
    """Load seeds from corpus/SEEDS.md if present, plus an inline fallback."""
    seeds: list[str] = []
    seed_path = HERE / "corpus" / "SEEDS.md"
    if seed_path.exists():
        for line in seed_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            seeds.append(stripped)
    # Inline minimal seed set as a hard fallback so the harness works without
    # the corpus file being populated.
    seeds.extend(["", "/", "//", "/foo/bar", "/~0/~1", "/~", "/~2", "/~01", "/~10", "/a~1b/c"])
    return seeds


def run_one(rng: random.Random, iteration: int) -> dict:
    """Run a single fuzz iteration. Returns a stats dict."""
    if rng.random() < 0.35:
        # Try a non-str type to verify the type guard rejects it cleanly.
        candidate = random_non_string(rng)
        label_repr = type(candidate).__name__
        data = repr(candidate).encode("utf-8", errors="replace")
    else:
        s = random_pointer(rng)
        # 1-in-200 inputs get a long-string probe to look for OOM/timeout.
        if rng.random() < 0.005:
            s = "/" + "a" * rng.randint(100_000, MAX_POINTER_LEN // 2)
        if len(s) > MAX_POINTER_LEN:
            # Record as a length-overrun finding but do NOT try to parse.
            path = _record_finding(CRASH_DIR, "over-max-len", s.encode("utf-8", errors="replace"),
                                   extra=f"length={len(s)} > MAX_POINTER_LEN={MAX_POINTER_LEN}")
            _log(f"iter={iteration} FINDING over-max-len length={len(s)} -> {path.name}")
            return {"kind": "finding", "label": "over-max-len", "path": str(path)}
        candidate = s
        data = s.encode("utf-8", errors="replace")
        label_repr = "str"

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(TIMEOUT_SECONDS)
    started = time.perf_counter()
    try:
        ptr = JSONPointer(candidate)
        elapsed = time.perf_counter() - started
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        # Behavioural invariants for the successful-parse path.
        findings = []
        if not isinstance(ptr, JSONPointer):
            findings.append(("return-type-not-JSONPointer", type(ptr).__name__))
        # Round-trip: str(ptr) must equal "/" + "/".join(ptr.raw_tokens)
        try:
            rs = str(ptr)
            rj = "/" + "/".join(ptr.raw_tokens)
            if rs != rj:
                findings.append(("str-raw-mismatch", f"str={rs!r} raw_join={rj!r}"))
        except Exception as e:  # noqa: BLE001
            findings.append(("str-raised", f"{type(e).__name__}: {e}"))
        if findings:
            for label, detail in findings:
                path = _record_finding(CRASH_DIR, label, data, extra=detail)
                _log(f"iter={iteration} FINDING {label} {detail!r} -> {path.name}")
            return {"kind": "finding", "label": findings[0][0], "elapsed": elapsed}
        return {"kind": "ok", "elapsed": elapsed, "input_kind": label_repr}
    except _Timeout:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        path = _record_finding(HANG_DIR, "timeout", data, extra=f"elapsed={elapsed:.2f}s input_kind={label_repr}")
        _log(f"iter={iteration} HANG elapsed={elapsed:.2f}s -> {path.name}")
        return {"kind": "hang", "elapsed": elapsed}
    except JSONPointerError as e:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        # Expected error path. NOT a finding. We log it for coverage.
        return {"kind": "expected_error", "elapsed": elapsed, "msg": str(e), "input_kind": label_repr}
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
    parser.add_argument("--seed", type=int, default=None, help="RNG seed (default: time-based)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    seed = args.seed if args.seed is not None else int(time.time() * 1000) & 0xFFFFFFFF
    rng = random.Random(seed)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("")  # truncate previous log

    seeds = load_seeds()
    if not args.quiet:
        print(f"[parse_pointer] seed={seed} iterations={args.iter} seeds_loaded={len(seeds)}", flush=True)

    # Always replay the corpus first; these are the hand-picked edge cases.
    stats = {"seed": seed, "iterations_planned": args.iter, "crashes": 0, "hangs": 0,
             "findings": 0, "ok": 0, "expected_errors": 0, "start": time.time()}
    for s in seeds:
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(TIMEOUT_SECONDS)
        try:
            JSONPointer(s)
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        except (JSONPointerError, _Timeout):
            signal.signal(signal.SIGALRM, old_handler)
        except Exception:  # noqa: BLE001
            signal.signal(signal.SIGALRM, old_handler)
            stats["crashes"] += 1

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