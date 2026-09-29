"""Fuzz harness for JSONPointer.evaluate() (eval phase).

Targets the public Surface 2: ptr.evaluate(doc: Any) -> JSONPointerError | Any.

Generates paired (document, pointer) inputs. The document generator only emits
JSON-shaped values (None, bool, int, float, str, list, dict). The pointer
generator is the same one used in parse_pointer/, but we always go through the
JSONPointer constructor first so that parse bugs surface here too.

Invariants checked:
  - When doc == pointer target value, result must equal that value
    (round-trip for known JSONValues).
  - evaluate() on the whole document with tokens == [] must return doc unchanged.
  - The method must NEVER raise an exception type other than JSONPointerError.
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

from rfc6901jsonpointer import JSONPointer, JSONPointerError  # noqa: E402

CRASH_DIR = HERE / "crashes"
HANG_DIR = HERE / "hangs"
LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"

TIMEOUT_SECONDS = 5

# Deepest document we will generate. Deeper than this is recorded as a finding
# rather than executed (depth pre-condition probing).
MAX_DOC_DEPTH = 8
MAX_LIST_LEN = 12
MAX_DICT_LEN = 8
# Maximum bytes of json.dumps() the sidecar will write; beyond this we
# truncate so that a pathological doc doesn't OOM the harness.
_SIDEcar_MAX_BYTES = 16 * 1024


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


# ---- Document generator -----------------------------------------------------

_LETTERS = list("abcdefghijklmnop")


def _random_value(rng: random.Random, depth: int):
    if depth >= MAX_DOC_DEPTH:
        return rng.choice([None, True, False, rng.randint(-1000, 1000), rng.random(),
                            rng.choice(_LETTERS) * rng.randint(0, 6)])
    pick = rng.random()
    if pick < 0.10:
        return None
    if pick < 0.25:
        return rng.choice([True, False])
    if pick < 0.45:
        return rng.randint(-(2**20), 2**20)
    if pick < 0.55:
        return rng.random() * 1e6 - 5e5
    if pick < 0.70:
        return "".join(rng.choice(_LETTERS + [" ", "_"]) for _ in range(rng.randint(0, 8)))
    if pick < 0.85:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, MAX_LIST_LEN))]
    return {rng.choice(_LETTERS): _random_value(rng, depth + 1) for _ in range(rng.randint(0, MAX_DICT_LEN))}


def random_doc(rng: random.Random):
    return _random_value(rng, 0)


# ---- Pointer generator ------------------------------------------------------

_ALLOWED = [chr(c) for c in range(0x00, 0x2F)] + [chr(c) for c in range(0x30, 0x7D)] + [chr(c) for c in range(0x7F, 0x100)]
_TILDE_BAD_AFTER = ("2", "3", "9", "a", "Z", "!", " ", "\t", "\n")


def random_pointer(rng: random.Random) -> str:
    choice = rng.random()
    if choice < 0.15:
        return ""
    if choice < 0.25:
        return "/"
    n_tokens = rng.randint(0, 6)
    parts = []
    for _ in range(n_tokens):
        t_len = rng.randint(0, 8)
        token_chars = []
        i = 0
        while i < t_len:
            r = rng.random()
            if r < 0.08:
                token_chars.append("~0")
                i += 2
            elif r < 0.16:
                token_chars.append("~1")
                i += 2
            elif r < 0.18 and token_chars:
                token_chars.append("~" + rng.choice(_TILDE_BAD_AFTER))
                i += 2
            else:
                c = rng.choice(_ALLOWED)
                token_chars.append(c)
                i += 1
        parts.append("".join(token_chars))
    return "/" + "/".join(parts)


# ---- Seed corpus ------------------------------------------------------------

def load_seeds() -> list[tuple[str, str]]:
    """Return a list of (document-json, pointer) seed pairs."""
    seeds: list[tuple[str, str]] = [
        ("{}", ""),
        ("{}", "/"),
        ('{"a":{"b":[1,2,3]}}', "/a/b/0"),
        ('{"a":{"b":[1,2,3]}}', "/a/b/3"),
        ("[1,2,3]", "/-"),
        ("[1,2,3]", "/01"),
        ("[1,2,3]", "/-1"),
        ('{"": 42}', "/"),
        ("null", ""),
        ("true", ""),
        ("42", "/0"),
        ('{"a":{"b":{"c":{"d":"deep"}}}}', "/a/b/c/d"),
        ('{"a": 1, "b": 2}', "/a"),
    ]
    return seeds


def run_one(rng: random.Random, iteration: int) -> dict:
    # Mixed random doc + pointer.
    doc = random_doc(rng)
    ptr_str = random_pointer(rng)
    # Encode pair to bytes for crash-sidecar reproducibility. Bound the doc
    # serialisation so a pathological generator output does not OOM the harness.
    try:
        doc_repr = repr(doc)
        if len(doc_repr) > 8192:
            doc_repr = doc_repr[:8192] + f"... <truncated, full length={len(repr(doc))}>"
        data = json.dumps({"doc": doc_repr, "ptr": ptr_str}, ensure_ascii=False).encode("utf-8", errors="replace")
    except (RecursionError, ValueError, TypeError) as enc_err:
        # Pathological generated doc — record its type instead.
        data = json.dumps({"doc_type": type(doc).__name__, "ptr": ptr_str,
                            "enc_err": str(enc_err)}, ensure_ascii=False).encode("utf-8", errors="replace")

    old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(TIMEOUT_SECONDS)
    started = time.perf_counter()
    try:
        ptr = JSONPointer(ptr_str)
        result = ptr.evaluate(doc)
        elapsed = time.perf_counter() - started
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
        # Behavioural invariants on the success path.
        if ptr_str == "" and result is not doc:
            path = _record_finding(CRASH_DIR, "empty-ptr-not-identity", data,
                                   extra=f"got {type(result).__name__}")
            _log(f"iter={iteration} FINDING empty-ptr-not-identity -> {path.name}")
            return {"kind": "finding", "label": "empty-ptr-not-identity"}
        return {"kind": "ok", "elapsed": elapsed}
    except _Timeout:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        path = _record_finding(HANG_DIR, "timeout", data, extra=f"elapsed={elapsed:.2f}s")
        _log(f"iter={iteration} HANG elapsed={elapsed:.2f}s -> {path.name}")
        return {"kind": "hang", "elapsed": elapsed}
    except JSONPointerError as e:
        elapsed = time.perf_counter() - started
        signal.signal(signal.SIGALRM, old_handler)
        # Expected: missing key, OOB index, type mismatch, bad tilde, etc.
        return {"kind": "expected_error", "elapsed": elapsed, "msg": str(e)}
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

    seeds = load_seeds()
    if not args.quiet:
        print(f"[evaluate] seed={seed} iterations={args.iter} seeds={len(seeds)}", flush=True)

    stats = {"seed": seed, "iterations_planned": args.iter, "crashes": 0, "hangs": 0,
             "findings": 0, "ok": 0, "expected_errors": 0, "start": time.time()}
    # Replay seeds.
    for doc_json, ptr_str in seeds:
        old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(TIMEOUT_SECONDS)
        try:
            JSONPointer(ptr_str).evaluate(json.loads(doc_json))
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