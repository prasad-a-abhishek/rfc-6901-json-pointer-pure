# THREAT MODEL — rfc-6901-json-pointer-pure (cycle_147/adversary/01)

**Methodology:** STRIDE-lite per surface (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Only realistic threat actors and attack paths are documented — this is a pure-Python data-structure library, not a network-facing service, so the threat model is correspondingly narrow.

**Trust boundary:** The library runs **in-process** with the calling application. The attacker is anyone who can supply a pointer string or a JSON document to the calling application's public API. There is no separate user-vs-admin role distinction — the pointer string IS the input.

---

## Surface 1 — `JSONPointer(ptr)` constructor

**Attacker:** A caller who can supply arbitrary pointer strings to the host application (e.g., an HTTP API that takes a `?path=` query param and returns `JSONPointer(path).evaluate(req.body_json)`).

**Attack goals:**
- **DoS via oversized input:** Supply a 100MB pointer string; force ~200MB of allocation across the two-pass parse. **Likelihood:** Low (host apps typically cap input length at the HTTP layer). **Impact:** Low–Medium (process memory pressure; OOM possible if no upstream cap).
- **Information disclosure via error message:** Supply a malformed pointer (e.g. `~~`); observe `JSONPointerError(f"Invalid trailing tilde in pointer: {ptr!r}")` (line 113). The `{ptr!r}` echoes the FULL attacker-supplied input back. If the host logs this to stderr, the attacker confirms their input reached the parser. **Likelihood:** Low. **Impact:** Negligible (they already know their input).
- **DoS via malformed tilde handling:** `~~` triggers `JSONPointerError` early (line 110–114) — fail-fast, not slow-fail. No slow DoS vector.

**What they'd achieve:** Memory pressure (DoS) at worst. No code execution, no data exfiltration, no logic error.

**Mitigations already in place:**
- Two exception wrappers (line 169–172, 178–181) ensure no raw exception escapes.
- No `eval`, no `re.compile` from user input, no `__import__`, no `pickle.loads`.

**Residual risk:** Low.

---

## Surface 2 — `ptr.evaluate(doc)` method

**Attacker:** Same trust boundary as Surface 1 — caller controls the pointer string. The `doc` is typically attacker-supplied (the calling application loads JSON from an untrusted source and asks the library to resolve a path inside it).

**Attack goals:**
- **Information disclosure via type probing:** By submitting varied pointers (e.g., `/a/b/c/d` vs `/a/0/1`) and observing which `JSONPointerError` variant is raised, the attacker can map the **type tree** of the document:
  - `cannot index into a str` → parent was string
  - `cannot index into a list` → parent was list
  - `key not found in object` → parent was dict
  - `array index N out of bounds for array of length M` → reveals ARRAY LENGTH
  This is a **side channel** that leaks document structure. **Likelihood:** Medium (only if the host application logs error messages to a public channel). **Impact:** Low to Medium depending on document sensitivity (could fingerprint an internal user-record schema, etc.).
- **DoS via deep pointer traversal:** Submit a 100K-token pointer against a deeply-nested JSON doc; force O(N) iterations. **Likelihood:** Low (host caps input). **Impact:** Low (linear, not exponential).
- **Logic error via misinterpretation:** Submit `/01` against an array — implementation correctly raises `JSONPointerError` (line 244–248). No silent type coercion. **Likelihood:** N/A. **Impact:** None (RFC-compliant).
- **Buffer overrun via very large int:** `int("9"*100000)` succeeds (Python arbitrary-precision); `current[idx]` would OOB-raise before subscripting. **Likelihood:** Very Low (host would have to omit input length cap AND attacker would have to align pointer with array size). **Impact:** None (raises `JSONPointerError`).

**What they'd achieve:** Type-tree fingerprinting at worst. No code execution, no data corruption, no privilege escalation.

**Mitigations already in place:**
- Every traversal step has explicit type-dispatch (line 225, 231, 255) and bounds/key-presence checks.
- Evaluation is iterative (line 224–259), not recursive — no stack overflow risk.

**Residual risk:** Low (info disclosure via error message).

---

## Surface 3 — `_unescape_token` (internal)

**Attacker:** Indirect via Surface 1 (cannot call directly; private function).

**Attack goals:**
- **Spec non-conformance:** If the unescape order were wrong (`~1` decoded before `~0`), an input of `/~01` would decode to `"/1"` instead of the correct `"~1"`. The implementation is RFC-correct (left-to-right, `~0` consumed in input order, equivalent to RFC's two-step process). **Likelihood:** N/A. **Impact:** None.

**What they'd achieve:** Nothing — surface is internal and verified by tests + fuzz.

**Mitigations already in place:**
- Tests at `TestTildeUnescape` cover `~01`, `~10`, `~0~1`, `~~`, `~2`, `~3`, `~9`, trailing `~`.
- QA V3.2 row for `/~01` → `["~1"]` PASS.

**Residual risk:** None.

---

## Surface 4 — `_parse_pointer` (internal)

**Attacker:** Indirect via Surface 1.

**Attack goals:**
- **Splitter bug:** If the `~` / `/` state machine miscounted, an attacker could craft a pointer that resolves to a different token than intended (e.g., `/a~1/b` accidentally splitting into `["a~", "b"]` instead of `["a/b"]`). **Likelihood:** N/A (algorithm verified by `test_complex_escape_single_token`, V3.1, V3.2 fuzz). **Impact:** None.

**What they'd achieve:** Nothing.

**Residual risk:** None.

---

## Surface 5 — `_parse_pointer_raw` (internal)

**Attacker:** Indirect via Surface 1; reaches this function when caller reads `ptr.raw_tokens`.

**Attack goals:** Same as Surface 4 — splitter bug. **Likelihood:** N/A (algorithm duplicates Surface 4; verified by `TestRoundTrip::test_raw_tokens_preserves_input`).

**Residual risk:** Low — the **duplication** between Surface 4 and Surface 5 is a maintenance risk, not an exploitable bug today. See VULN_AUDIT.md Finding F-01.

---

## Surface 6 — `tokens`/`raw_tokens`/`__str__`/etc (public properties)

**Attacker:** Indirect via Surface 1; reaches these via `ptr.tokens` / `ptr.raw_tokens` / `str(ptr)` / `repr(ptr)` / `ptr1 == ptr2`.

**Attack goals:**
- **Re-encoding bug:** If `__str__` did `'/' → ~1` before `'~' → ~0`, then `str(JSONPointer("/a/b"))` would re-emit `"/a~1b"` correctly, but the **inverse direction** of nested escapes could fail. The implementation does `~` → `~0` FIRST, then `/` → `~1`, which is the correct order (verified by `test_roundtrip_with_escaped_slash`, `test_str_reconstruction_*`). **Likelihood:** N/A. **Impact:** None.
- **Hash collision:** `__hash__` uses `hash(tuple(self._tokens))`. Two pointers with different raw representations but identical decoded tokens would hash identically. Currently impossible because raw representations map 1:1 to decoded tokens. **Likelihood:** N/A. **Impact:** None.

**What they'd achieve:** Nothing.

**Residual risk:** None.

---

## Surface 7 — CLI (`python -m rfc6901jsonpointer`)

**Attacker:** Local user with shell access (the CLI is invoked as a subprocess from the caller's command line).

**Attack goals:**
- **Argument injection:** The CLI uses `sys.argv[1:]` directly. An attacker with shell access could pass `--help` or other flags — but the CLI ignores unknown flags (it just calls `JSONPointer(argv[0])` and `json.loads(argv[1])` unconditionally). **Likelihood:** Low (already has shell). **Impact:** None.
- **JSON-injection:** argv[1] is fed to `json.loads`. Malformed JSON → `json.JSONDecodeError` → stderr + exit 1. No injection vector. **Likelihood:** N/A. **Impact:** None.
- **Subshell injection via result:** `json.dumps(result, ensure_ascii=False)` writes to stdout (line 57). Result is attacker-controlled JSON content, but stdout is not re-interpreted by a shell. **Likelihood:** N/A. **Impact:** None.
- **DoS via massive argv:** argv size is limited by the OS (typically ARG_MAX ~ 128KB–2MB depending on platform). Beyond that, the kernel rejects. **Likelihood:** Very Low. **Impact:** Negligible.

**What they'd achieve:** Local shell access (which they already have).

**Mitigations already in place:**
- argv count check (line 26–29)
- explicit `json.JSONDecodeError` catch (line 37–39)
- explicit `JSONPointerError` catch (line 44–46, 51–53)
- output-encode catch (line 59–61)

**Residual risk:** None.

---

## Surface 8 — `JSONPointerError` exception

**Attacker:** Indirect — sees `JSONPointerError` only if they have visibility into the host's log output or stderr.

**Attack goals:**
- **Information disclosure via message content:** Error messages include token value, parent type, and array length (see Surface 2 analysis). **Likelihood:** Medium. **Impact:** Low (already analyzed).

**What they'd achieve:** Document-structure fingerprinting (see Surface 2).

**Residual risk:** Low (same as Surface 2).

---

## Trust boundary summary

```
┌─────────────────────────────────────────────────────────┐
│  HOST APPLICATION (trusted)                              │
│   - Calls JSONPointer(ptr) with attacker-supplied ptr    │
│   - Calls ptr.evaluate(doc) with host-controlled doc     │
│   - Catches JSONPointerError                             │
└────────────────────────┬────────────────────────────────┘
                         │ JSONPointerError (control flow)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  LIBRARY (in-process)                                    │
│   - Parses ptr string (Surface 1, 3, 4, 5)               │
│   - Walks doc (Surface 2, 8)                             │
│   - Returns value or raises                              │
└─────────────────────────────────────────────────────────┘
```

**No network boundary, no filesystem boundary, no privilege boundary.** The library inherits the host's trust posture entirely.

---

## Threat-actor profile summary

| Actor | Capability | Realistic attack | Max impact |
|-------|------------|------------------|------------|
| External (HTTP query param) | Supply pointer string | Type-tree fingerprinting via error messages | Low (info leak) |
| External (HTTP query param) | Supply pointer string | Memory pressure via oversized input | Low (DoS, host caps input) |
| Local user (shell) | Invoke CLI | None (already has shell) | None |
| Internal bug (future refactor) | Modify code | Parser-bug regression | Mitigated by 123 tests |

**Overall residual risk: Low.** No exploitable Critical or High findings.

---

## Conclusion

The library's threat surface is minimal because:
1. It operates in-process with no I/O.
2. The algorithm is well-specified (RFC 6901 §4 + §5) and exhaustively tested (123 tests including 16 fuzz cases).
3. Invariant 21 (total over arbitrary input) is enforced at every public boundary.
4. The implementation uses iterative loops (no recursion → no stack overflow).

The only realistic residual risks are **Low** severity:
- Type-tree fingerprinting via error message content (CWE-209).
- No length cap on pointer input (CWE-400).
- Exception swallowing in constructor (CWE-703).
- Algorithm duplication between `_parse_pointer` and `_parse_pointer_raw` (CWE-1281).

None of these warrant blocking the ship.