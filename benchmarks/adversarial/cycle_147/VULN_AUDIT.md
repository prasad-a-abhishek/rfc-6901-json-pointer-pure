# VULN AUDIT — rfc-6901-json-pointer-pure (cycle_147/adversary/01)

**Audit date:** 2026-09-29
**Auditor:** @default (cycle_147/adversary/01, workstream card 1 of 5)
**Commit audited:** 6599817 (`qa: 14/14 sub-checks PASS + 123/123 pytest + honesty audit`)
**Branch:** `wt/cycle147-adversary-01`
**Library version:** 0.1.0
**Scope:** All 8 attack surfaces enumerated in `SURFACES.md`; all public API functions in `src/rfc6901jsonpointer/`; CLI entrypoint.

---

## Executive summary

| Metric | Value |
|--------|-------|
| **Surfaces enumerated** | 8 (above target of 4–7 by 1; the brief's incorrect assumption of a 3-class exception hierarchy inflated the count when corrected) |
| **CWEs considered** | 13 |
| **CWEs with findings** | 4 |
| **Critical findings** | **0** |
| **High findings** | **0** |
| **Medium findings** | **0** |
| **Low findings** | 4 (F-01, F-02, F-03, F-04) |
| **Info findings** | 1 (F-05 — README doc bug, carried from QA) |
| **Total findings** | **5** (all Low/Info) |
| **Verdict** | **CLEAN** (no Critical or High findings; all findings are advisory for future hardening) |

The library is **safe to ship at v0.1.0**. All findings are advisory for future versions; none block the v0.1.0 release.

---

## Methodology

1. **Source enumeration.** Read all 5 files in `src/rfc6901jsonpointer/` (`__init__.py` 7 LOC, `_parser.py` 340 LOC, `_errors.py` 19 LOC, `_compat.py` 5 LOC, `__main__.py` 65 LOC; total 436 LOC). Traced every public symbol from `__init__.py` line 7 (`__all__ = ["JSONPointer", "JSONPointerError", "__version__"]`) to its definition.
2. **Surface enumeration.** Mapped 8 attack surfaces (see `SURFACES.md`). Corrected the orchestrator brief's listing — `parse_pointer(s) -> list[str]` and `evaluate(doc, pointer)` do NOT exist as top-level functions. The real public API is the `JSONPointer` class.
3. **CWE mapping.** For each surface, applied 13 relevant CWEs from the MITRE catalog (CWE-20, CWE-22, CWE-125, CWE-190, CWE-209, CWE-400, CWE-682, CWE-703, CWE-704, CWE-754, CWE-1281, CWE-1284, CWE-1339). See `CWE_MAP.md`.
4. **Threat modeling.** Applied STRIDE-lite per surface (see `THREAT_MODEL.md`). Identified the realistic threat actors (external HTTP API callers, local CLI users) and attack goals (DoS, info disclosure, logic error).
5. **Test gap analysis.** Mapped 14 acceptance criteria (derived from QA V3.1–V3.14) to 123 pytest cases + 16 fuzz tests + manual QA evidence. See `TEST_GAPS.md`.
6. **Cross-references:**
   - **RFC 6901 §4 ABNF:** https://www.rfc-editor.org/rfc/rfc6901.txt (referenced in SPEC.md; confirmed for tilde-unescape order)
   - **RFC 6901 §5 examples:** Same RFC, used in QA V3.5 verification
   - **MITRE CWE catalog:** https://cwe.mitre.org/data/definitions/[N].html
   - **Wikipedia JSON Pointer:** https://en.wikipedia.org/wiki/JSON_Pointer (for `-` sentinel semantics)

---

## Findings

### F-01 — Algorithm duplication between `_parse_pointer` and `_parse_pointer_raw` (CWE-1281)

**Severity:** Low
**Surface:** Surfaces 4 & 5 (parse internals)
**Code:** `_parser.py` lines 46–123 (`_parse_pointer`) and lines 293–340 (`_parse_pointer_raw`)

**Description:** The token-splitting logic is implemented twice with identical state-machine behavior. The only difference is that `_parse_pointer` calls `_unescape_token` on each accumulated token after the split; `_parse_pointer_raw` skips that step. Both have the same `while i < len(ptr)` loop with `if ch == '/'` / `elif ch == '~'` / `else` branches.

**Risk:** A future bug fix to one would not propagate to the other unless both are updated in lockstep. Currently the two implementations are in sync (verified by `TestRoundTrip::test_raw_tokens_preserves_input` which exercises the round-trip).

**Recommendation (advisory):** Refactor to a single `_split_tokens(ptr) -> List[str]` helper that both functions call, with the unescape as a separate step. Out of scope for v0.1.0; track for v0.2.0.

**Blocking ship?** No.

---

### F-02 — Type-tree fingerprinting via error message content (CWE-209)

**Severity:** Low
**Surface:** Surface 2 (`evaluate` method)
**Code:** `_parser.py` lines 227–228, 240–242, 250–252, 256–258

**Description:** Error messages include `{token!r}` (the offending token, attacker-controlled), `{type(current).__name__}` (the parent type — `dict`/`list`/`str`/`int`/`bool`), `{idx}` (parsed array index), and `len(current)` (array length). An attacker with visibility into log output (e.g., a multi-tenant service that logs exceptions) could probe the document structure by submitting varied pointers and observing error message variants.

**Concrete attack pattern:**
```
Submit /a/0 → "Token 0 ('a'): key not found"        (key 'a' missing)
Submit /a → success → returns {"b": [...]}          (key 'a' exists, value is object)
Submit /a/0 → "Token 1 ('0'): cannot index into a list"  (parent is list)
Submit /a/0/0 → "Token 2 ('0'): array index out of bounds for array of length 3"
```
After 4 probes, attacker knows: `doc.a` is a list of length 3.

**Risk:** Low. Requires attacker control of pointer strings AND host logging to attacker-visible channels. Typical deployments log exceptions to internal observability, not public channels.

**Recommendation (advisory):**
- Document in README "Error messages may reveal parent type at failure point — do not log to public channels if document structure is sensitive."
- OR add a `JSONPointer(reveal_types=False)` constructor flag that replaces `{type(current).__name__}` with `<redacted>`.

**Blocking ship?** No.

---

### F-03 — No length cap on pointer input (CWE-400)

**Severity:** Low
**Surface:** Surface 1 (`JSONPointer` constructor)
**Code:** `_parser.py` lines 154–181 (no `len(ptr) > MAX_POINTER_LEN` check)

**Description:** The constructor has no explicit cap on pointer length. An attacker who can supply arbitrary pointer strings to the host application could trigger memory pressure by submitting a 100MB pointer string. The two-pass parse (raw + decoded) would allocate ~200MB of intermediate string data.

**Concrete attack pattern:**
```
ptr = "/" + "a" * 100_000_000  # 100MB
JSONPointer(ptr)  # allocates ~200MB during parse, returns successfully
```

**Risk:** Low. Requires attacker control of pointer strings AND no upstream input length cap (HTTP servers typically cap at 1MB–10MB). The allocation is bounded by the input length.

**Recommendation (advisory):**
- Add a `max_tokens` constructor argument (`JSONPointer(ptr, max_tokens=10_000)`) for untrusted-input scenarios.
- OR document the lack of cap in README Limitations.

**Blocking ship?** No.

---

### F-04 — Constructor swallows `Exception` (CWE-703)

**Severity:** Low
**Surface:** Surface 1 (`JSONPointer` constructor)
**Code:** `_parser.py` lines 169–172, 178–181

**Description:**
```python
try:
    self._raw_tokens = _parse_pointer_raw(ptr)
except JSONPointerError:
    raise
except Exception as e:
    raise JSONPointerError(f"Pointer parsing failed: {e}") from e
```

The `except Exception as e` wrapper masks every non-`JSONPointerError` exception (e.g., a future `AttributeError` from a refactor) behind a generic "Pointer parsing failed" message. While this satisfies Invariant 21 from the user's perspective (no raw exception leaks), it makes library maintenance harder — internal bugs become invisible.

**Risk:** Low. Not exploitable; affects only maintainability and future-bug detectability.

**Recommendation (advisory):**
- Narrow the catch to expected exception types (`ValueError`, `IndexError`, `UnicodeDecodeError`).
- OR add a separate `JSONPointerInternalError(JSONPointerError)` subclass for genuinely-unexpected exceptions, so callers can `except JSONPointerError` for user-input errors but `except JSONPointerInternalError` for bugs.
- OR log the original traceback to `warnings.warn` before re-raising (preserves public contract while preserving debuggability).

**Blocking ship?** No.

---

### F-05 — README Quick Start comment is incorrect (doc-only, NOT a code bug)

**Severity:** Info
**Surface:** Surface 6 (`__repr__` / documentation)
**Code:** `README.md` line 26

**Description:**
```python
result = ptr.evaluate(doc)   # → "z"
```

The comment claims the implementation returns `"z"`, but `JSONPointer("/a/b/0").evaluate({"a": {"b": ["x", "y", "z"]}})` correctly returns `"x"` (index 0 of the array). The implementation is RFC 6901 §4 correct; the documentation is wrong.

**Origin:** This finding was originally surfaced by QA (cycle_147/qa, V3.13 honesty audit) and tracked in QA_REPORT.md lines 196–207. It is a documentation bug, not a code bug.

**Recommendation:**
- Patch README line 26 from `# → "z"` to `# → "x"`.
- This patch can be applied independently of the V0.1.0 ship (does not affect functionality, install, or tests).

**Blocking ship?** No. Could be patched in a v0.1.1 docs-fix release.

---

## Findings explicitly NOT raised

The following were considered and dismissed:

- **CWE-22 (Path Traversal):** No filesystem I/O exists. JSON Pointer is in-document, not filesystem. N/A.
- **CWE-125 (OOB Read):** Every list subscript and dict key access has explicit bounds/key-presence check. N/A.
- **CWE-190 (Integer Overflow):** Python ints are arbitrary-precision. N/A.
- **CWE-682 (Incorrect Calculation):** Tilde-unescape is RFC 6901 §4 compliant (verified by V3.2). N/A.
- **CWE-704 (Incorrect Type Conversion):** Leading-zero reject via `str(idx) != token` is RFC-compliant. N/A.
- **CWE-754 (Unusual Conditions):** Every unusual input (`None`, non-int, non-str) is caught and converted to `JSONPointerError`. N/A.
- **CWE-1284 (Quantity Validation):** Array-index bounds correctly enforced (`idx < 0` AND `idx >= len(current)` both rejected). N/A.
- **CWE-1339 (Precision):** Python int round-trip is exact for arbitrary precision. N/A.

---

## Severity-ranked findings table

| Finding | Severity | CWE | Surface | Code ref | Blocks ship? |
|---------|----------|-----|---------|----------|--------------|
| F-01 | Low | CWE-1281 | Parse internals | `_parser.py` L46–123, L293–340 | No |
| F-02 | Low | CWE-209 | `evaluate()` | `_parser.py` L227–258 | No |
| F-03 | Low | CWE-400 | `JSONPointer()` ctor | `_parser.py` L154–181 | No |
| F-04 | Low | CWE-703 | `JSONPointer()` ctor | `_parser.py` L169–172, L178–181 | No |
| F-05 | Info | (doc bug) | README | `README.md` L26 | No |

**Total: 0 Critical, 0 High, 0 Medium, 4 Low, 1 Info.**

---

## Test gap summary

- **14 ACs total** (derived from QA V3.1–V3.14)
- **9 ACs fully covered** by automated pytest tests (AC-1 through AC-9, the algorithm-correctness ACs)
- **5 ACs with partial/manual coverage** (AC-10 through AC-14, the meta-requirements for install/dep/secret/honesty/distinctness)
- **0 ACs with zero coverage** — every AC has at least manual QA evidence
- **123 automated pytest cases** + 16 fuzz tests = 139 total test cases
- **1 known doc bug** (F-05, carried from QA)

No cycle-blocking test gap. See `TEST_GAPS.md` for full mapping.

---

## Recommendations summary

| Priority | Recommendation | Blocks ship? |
|----------|----------------|--------------|
| None blocking | All findings are Low/Info; safe to ship as v0.1.0 | — |
| Suggested for v0.1.1 | Fix README L26 comment (`# → "x"` instead of `# → "z"`) | No |
| Suggested for v0.2.0 | Refactor parse internals to share `_split_tokens()` helper (F-01) | No |
| Optional | Document error-message info-disclosure in README Limitations (F-02) | No |
| Optional | Add `max_tokens` constructor arg (F-03) | No |
| Optional | Narrow constructor's `except Exception` to specific types (F-04) | No |

---

## Audit summary

**All 5 findings are Low or Info severity.** Zero Critical, zero High, zero Medium findings.

---

## References

- `SURFACES.md` — 8 enumerated attack surfaces
- `CWE_MAP.md` — 13 CWE entries mapped, 4 with findings
- `THREAT_MODEL.md` — STRIDE-lite analysis per surface
- `TEST_GAPS.md` — 14-AC mapping to 139 test cases
- `QA_REPORT.md` (cycle_147/qa, commit 6599817) — 14/14 sub-checks PASS reference
- RFC 6901 — JSON Pointer (https://www.rfc-editor.org/rfc/rfc6901.txt)
- MITRE CWE catalog (https://cwe.mitre.org/)

---

VERDICT: CLEAN