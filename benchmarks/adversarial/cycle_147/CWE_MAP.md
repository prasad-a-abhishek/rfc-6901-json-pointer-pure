# CWE MAP — rfc-6901-json-pointer-pure (cycle_147/adversary/01)

**Methodology:**
- Each surface enumerated in `SURFACES.md` was analyzed against the MITRE CWE catalog (https://cwe.mitre.org/).
- Mapping prioritizes CWEs that match an actual code path (not just hypothetical risks). "N/A" entries below indicate a CWE was considered and dismissed with a reason.
- Severity baseline: Critical = unauthenticated RCE / data exfiltration, High = DoS / logic-error data corruption, Medium = degraded robustness / spec non-conformance, Low = code-quality / future-proofing, Info = documentation / design choice.

---

## CWE-20 — Improper Input Validation

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 1 (constructor) | **YES — robust** | `_parser.py` line 157 `isinstance(ptr, str)` check; lines 65–68 leading-`/` check; lines 96–114 tilde pair check | Constructor explicitly rejects non-str input, missing-`/` prefixes, and malformed tildes with a structured `JSONPointerError`. No `ValueError`/`TypeError` leaks (verified by V3.8 fuzz). |
| 2 (evaluate) | **YES — robust** | `_parser.py` lines 216–217 (`doc is None`), 226–229 (missing key), 249–253 (OOB index), 232–236 (`-` sentinel), 244–248 (leading-zero) | Every documented failure mode of RFC 6901 evaluation has an explicit guard. |
| 7 (CLI) | **YES — partial** | `__main__.py` lines 26–29 (argv count), 35–39 (json.loads), 43–46 (JSONPointer construction), 49–53 (evaluate) | CLI wraps all exceptions with exit-code-1 + stderr. `json.JSONDecodeError` is the only "raw" exception not wrapped as `JSONPointerError` (acceptable since JSON is a separate input domain from pointer). |

**Verdict:** Input validation is strong across all entry points. The `JSONPointer` class is **total over arbitrary input** (Invariant 21 satisfied, confirmed by QA V3.8 — 11 hostile inputs, 0 uncaught exceptions).

**No finding.**

---

## CWE-22 — Path Traversal

| Surface | Applicable? | Notes |
|---------|-------------|-------|
| 1, 2, 7 | **N/A** | RFC 6901 JSON Pointer is an **in-document** reference syntax, NOT a filesystem path. The library performs **no filesystem I/O** (no `open()`, no `os.path.join`, no `pathlib` operations). The CLI takes JSON as a string argument on argv, not as a file path. A `JSONPointer("/etc/passwd")` simply looks up the key `etc` in object `passwd` — which doesn't exist in any well-formed JSON doc. |

**Verdict:** No path-traversal vector exists. The only place `sys` is imported is `__main__.py` for `sys.stderr`/`sys.stdout`/`sys.argv`/`sys.exit`. No `os` or `pathlib` imports anywhere in `src/`.

**No finding.**

---

## CWE-125 — Out-of-bounds Read

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 2 (evaluate) | **YES — robust** | `_parser.py` lines 249–253 (`idx < 0 or idx >= len(current)`) | Explicit bounds check before subscripting the list. Dict-key lookup uses `in current` (line 226) — `KeyError` cannot be raised. |
| 3, 4, 5 (parse internals) | **YES — robust** | `_parser.py` lines 28, 98, 110–114 | Every index access is guarded by `i + 1 < len(token)` / `i + 1 >= len(token)` checks before reading the next char. |

**Verdict:** No OOB read is possible. The evaluation loop is iterative with explicit bounds; the parse loop is a finite state machine that never indexes past `len(ptr)`.

**No finding.**

---

## CWE-190 — Integer Overflow or Wraparound

**N/A.** Python integers are arbitrary-precision (PEP 237). `int(token)` at line 238 will not overflow regardless of magnitude. `len(current)` at line 249 returns a Python int, which is also arbitrary-precision.

**No finding.**

---

## CWE-209 — Information Exposure Through Error Messages

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 2 (evaluate) | **MEDIUM finding** | `_parser.py` lines 227–228, 240–242, 250–252, 256–258 | Error messages include `{token!r}` (the offending token), `{type(current).__name__}` (the parent type), and `{idx}` (the parsed index). |

**Risk analysis:**
- Token values are user-controlled (they came from the pointer string). If an application logs `JSONPointerError` to a public log (e.g. via the CLI's `sys.stderr.write`), an attacker could fingerprint internal JSON document structure by probing pointers and observing which errors leak `key not found in object` vs `cannot index into a str`.
- However, the token itself is supplied by the caller — they're not learning anything they didn't already supply.
- The `{type(current).__name__}` leak IS a real concern: by probing `/a/b/c/d` against an unknown document, an attacker can map the type tree by observing whether the failure message contains `cannot index into a list` vs `cannot index into a str`. This is a low-severity side channel for adversarial JSON-document probing.

**Severity:** **Low** (information leak, requires attacker control of the pointer string AND log access to stderr/exception messages).

**Recommendation (informational, not required to ship):**
- Consider adding a `{type(current).__name__}` redaction mode (`JSONPointer(..., reveal_types=False)`).
- OR document in README "Error messages may reveal parent type at failure point — do not log to public channels if the document structure is sensitive."

---

## CWE-400 — Uncontrolled Resource Consumption

| Surface | Applicable? | Notes |
|---------|-------------|-------|
| 1 (constructor) | **LOW finding** | Two-pass parse (`_parse_pointer_raw` + `_parse_pointer`) doubles the CPU/memory cost of parse for every pointer. A 10K-token pointer allocates 20K string slots across both passes. |

**Analysis:**
- `tests/test_fuzz.py::TestFuzz::test_fuzz_very_long_pointer` (line 219–224) verifies 200-token pointers parse fine. `test_fuzz_very_long_token` (line 226–232) verifies a 10K-char single-token pointer parses fine.
- No explicit length cap on pointer input. An attacker (or buggy caller) could pass a 100MB pointer string and force ~200MB of allocation across both passes.
- The evaluation loop is iterative and proportional to `len(tokens)` × per-token dict/list ops. A 100K-token pointer against a deeply-nested doc is bounded by Python's list/dict lookup time but allocates proportionally.

**Severity:** **Low** (no hard cap; no practical DoS vector in normal use; adversarial attacker would need to control the pointer string and the target Python process).

**Recommendation (informational):**
- Add a `max_tokens` guard (`JSONPointer(ptr, max_tokens=10000)`) for untrusted-input scenarios.
- OR document the lack of cap in README Limitations.

---

## CWE-682 — Incorrect Calculation

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 3 (`_unescape_token`) | **YES — correctly handled** | `_parser.py` lines 25–42 (left-to-right state machine) | Decodes `~0` → `~` and `~1` → `/` in input order. RFC 6901 §4 is explicit: "Evaluation of each reference token begins with decoding any escaped character sequence. This is performed in two steps: first, any occurrence of the sequence '~1' is replaced with '/'; second, any remaining occurrence of '~0' is replaced with '~'." The implementation does this in one pass left-to-right, which is **equivalent** to the two-step RFC process because `~0` and `~1` are non-overlapping once `~1` is consumed. |
| 4 (`_parse_pointer`) | **YES — correctly handled** | `_parser.py` lines 79–95 (separator detection) | The tokenizer correctly treats `/` preceded by `~` (i.e., the `~` of an in-progress `~1` pair) as part of the current token. Verified by `test_complex_escape_single_token` (test_parser.py line 131–134). |

**Verdict:** All calculation logic is RFC 6901 §4 compliant. Confirmed by QA V3.2 (`/~0~1` → `["~/"]`, `/~01` → `["~1"]` — both PASS).

**No finding.**

---

## CWE-703 — Improper Check or Handling of Exceptional Conditions

| Surface | Applicable? | Notes |
|---------|-------------|-------|
| 1 (constructor) | **MEDIUM finding** | `_parser.py` lines 169–172, 178–181: the constructor wraps every non-`JSONPointerError` exception with `except Exception as e: raise JSONPointerError(f"...failed: {e}") from e`. This **masks** internal bugs (e.g. an unexpected `AttributeError` from a future refactor) behind a generic "parsing failed" message. While this satisfies Invariant 21 from the user's perspective, it makes debugging harder for library maintainers. |

**Severity:** **Low/Medium** (maintainability / future-bug-masking).

**Recommendation (informational):**
- Consider narrowing the catch to expected exceptions only (`ValueError`, `IndexError`), OR
- Add a `JSONPointerInternalError` subclass for genuinely-unexpected exceptions, OR
- Log the original traceback before wrapping (would help post-mortem debugging without breaking the public contract).

---

## CWE-704 — Incorrect Type Conversion or Cast

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 2 (evaluate) | **YES — correctly handled** | `_parser.py` line 238 (`idx = int(token)`) followed by line 244 (`if str(idx) != token`) | The leading-zero reject works by comparing the int→str round-trip with the original token. This correctly catches `"01"`, `"007"`, `"+0"` (RFC 6901 §4 ABNF allows only `[0-9]+`). |

**Verdict:** Type conversion is RFC-compliant. No silent int truncation (Python ints are unbounded).

**No finding.**

---

## CWE-754 — Improper Check for Unusual or Exceptional Conditions

| Surface | Applicable? | Notes |
|---------|-------------|-------|
| 1 (constructor) | **N/A** | The constructor does no type conversion on user input — only structural validation (isinstance, leading `/`, tilde pairs). |
| 2 (evaluate) | **YES — correctly handled** | `_parser.py` line 238 `int(token)` raises `ValueError` on non-integer tokens; the surrounding `try`/`except` (line 237–243) catches it and raises `JSONPointerError`. No silent NaN/inf — Python's `int("inf")` raises `ValueError`, `int(float("nan"))` raises `ValueError`. |

**Verdict:** Unusual input conditions are surfaced as `JSONPointerError`.

**No finding.**

---

## CWE-754 (variant) — RecursionError

**N/A.** The implementation uses iterative loops in both parse (line 77–117) and evaluate (line 224–259). No recursion means no `RecursionError` regardless of nesting depth. This is a deliberate design win — `tests/test_fuzz.py::test_fuzz_deeply_nested_structures` confirms 10-level pointer against 6-level nested doc parses fine.

---

## CWE-1284 — Improper Validation of Specified Quantity in Input

| Surface | Applicable? | Code reference | Notes |
|---------|-------------|----------------|-------|
| 2 (evaluate, array index) | **YES — correctly handled** | `_parser.py` lines 244–253 (leading-zero reject, sign reject via `idx < 0`, bounds reject via `idx >= len(current)`) | RFC 6901 §4 ABNF: `array-index = "0" / (("1"-"9") *DIGIT)`. Implementation enforces this via `str(idx) != token` plus `idx >= 0`. |

**Verdict:** Array-index bounds are RFC-compliant. No integer underflow/overflow possible (Python int).

**No finding.**

---

## CWE-1339 — Insufficient Precision or Accuracy

**N/A.** Python ints are exact (arbitrary precision). JSON serializes ints without precision loss (verified by `test_evaluate_returns_primitive` — `JSONPointer("/a/b/c").evaluate({"a":{"b":{"c":42}}})` → `42`). For very large ints (10^100), the int round-trips through `json.dumps(result, ensure_ascii=False)` (CLI line 57) without truncation.

**No finding.**

---

## CWE-1281 — Sequence of Processor Instructions Leads to Unexpected Behavior (algorithmic)

| Surface | Applicable? | Notes |
|---------|-------------|-------|
| 1, 4, 5 | **LOW finding** | The token-splitting logic in `_parse_pointer` (lines 77–117) and `_parse_pointer_raw` (lines 310–337) is **byte-identical except for the final unescape step**. Two parallel implementations of the same state machine = **algorithm duplication risk**. A bug fix in one would not propagate to the other unless both are updated in lockstep. The current state shows them in sync, but this is a maintenance hazard. |

**Severity:** **Low** (no current bug; future risk).

**Recommendation (informational):**
- Refactor to a single `_split_tokens(ptr) -> List[str]` helper that both parse functions call, with the unescape as a separate step.

---

## Summary table — CWE mapping

| CWE | Surfaces | Status | Finding? |
|-----|----------|--------|----------|
| CWE-20 (input validation) | 1, 2, 7 | Robust | No |
| CWE-22 (path traversal) | — | N/A | No |
| CWE-125 (OOB read) | 2, 3, 4, 5 | Robust | No |
| CWE-190 (int overflow) | — | N/A (Python) | No |
| CWE-209 (info exposure) | 2 | Token + type name in error | **Low** (F-02) |
| CWE-400 (resource consumption) | 1 | No length cap | **Low** (F-03) |
| CWE-682 (incorrect calc) | 3, 4 | RFC-compliant | No |
| CWE-703 (improper exception) | 1 | Swallows `Exception` | **Low** (F-04) |
| CWE-704 (type conversion) | 2 | RFC-compliant | No |
| CWE-754 (unusual conditions) | 2 | Robust | No |
| CWE-1281 (algorithmic duplication) | 4, 5 | Parallel impls | **Low** (F-01) |
| CWE-1284 (quantity validation) | 2 | RFC-compliant | No |
| CWE-1339 (precision) | — | N/A (Python) | No |

**Total CWEs considered:** 13
**CWEs with findings:** 4 (CWE-209, CWE-400, CWE-703, CWE-1281) — all Low severity
**Total findings surfaced:** 4 Low (see VULN_AUDIT.md for full descriptions)