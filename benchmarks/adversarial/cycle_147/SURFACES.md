# SURFACES — rfc-6901-json-pointer-pure (cycle_147/adversary/01)

**Audit date:** 2026-09-29
**Commit audited:** 6599817 (`qa: 14/14 sub-checks PASS + 123/123 pytest + honesty audit`)
**Source LOC:** 5 files in `src/rfc6901jsonpointer/` (__init__.py 7, _parser.py 340, _errors.py 19, _compat.py 5, __main__.py 65; total ≈ 436 LOC)
**Public API surface:** `JSONPointer`, `JSONPointerError`, `__version__` (per `__init__.py` line 7)
**Library type:** Pure-Python, zero-dep (stdlib only), read-only RFC 6901 evaluator

---

## Correction note on task brief

The orchestrator brief listed 10 candidate surfaces including `parse_pointer(s) -> list[str]` and `evaluate(doc, pointer)` as top-level functions. **The actual implementation does NOT export those names.** The real public surface is the `JSONPointer` *class* with constructor `JSONPointer(ptr: Optional[str])` and instance method `evaluate(doc: Any) -> Any`, plus a parallel `_parse_pointer_raw()` used internally for the `raw_tokens` property. The 7 surfaces below reflect the ACTUAL code, not the brief's hypothetical API.

---

## Surface 1 — `JSONPointer(ptr: Optional[str])` constructor (parse phase)

**Entry point:** `src/rfc6901jsonpointer/_parser.py` lines 154–181 (class `__init__`)
**Internal helpers called:** `_parse_pointer_raw(ptr)` (line 293) and `_parse_pointer(ptr)` (line 46)
**Module import:** `from rfc6901jsonpointer import JSONPointer` — only public constructor for the library.

**Input domain:**
- `ptr=None` → documented synonym for `""` (whole-document ref) per README line 90
- `ptr=""` → empty token list (no error)
- `ptr=str` starting with `/` → normal pointer (e.g. `/a/b/0`)
- `ptr=str` NOT starting with `/` (e.g. `"foo/bar"`) → `JSONPointerError`
- `ptr=str` with invalid tilde escape (`~~`, `~2`, trailing `~`) → `JSONPointerError`
- `ptr` of any non-str type (`int`, `list`, `dict`, `bytes`) → `JSONPointerError` via `isinstance(ptr, str)` check at line 157

**Output:** populated `self._raw_tokens: List[str]` and `self._tokens: List[str]` (the decoded form)

**Notable design choices that affect attack surface:**
- Constructor swallows every non-`JSONPointerError` exception and re-raises as `JSONPointerError` (lines 169–172 and 178–181). This is Invariant 21 in action — the public surface NEVER leaks raw `ValueError`/`TypeError` from internal string ops.
- Two-pass parse (raw + decoded) doubles the work but guarantees `raw_tokens` is byte-identical to the substring-split input. Doubles exposure to memory-pressure if input is huge (see CWE-400 below).
- Tilde-unescape is left-to-right with explicit per-character state machine (lines 26–43). There is no regex, no `re.sub`, no eval.

**Edge cases enumerated from code:**
- `""` (line 62) → `[]`
- `"/"` (line 75, 79) → `[""]` (single empty token)
- `"/foo~"` trailing tilde (line 110–114) → `JSONPointerError`
- `"/~02"` → first `~0` → `~`, then `2` is a literal token char → tokens `["~2"]`; VALID
- `"/~0~1"` → tokens `["~/"]` (the QA V3.2 row)
- `"/~01"` → tokens `["~1"]` (decode `~0` first per RFC 6901 §4)
- `"/a~1b~0c"` → tokens `["a/b~c"]` (single token, no splitting on escaped `/`)
- 10K-char tokens, 200-deep pointer paths — both supported (fuzz tests at lines 219–232 of `tests/test_fuzz.py`)

---

## Surface 2 — `JSONPointer.evaluate(doc: Any)` (evaluation phase)

**Entry point:** `src/rfc6901jsonpointer/_parser.py` lines 201–261 (method `JSONPointer.evaluate`)
**Module import:** `ptr = JSONPointer("/a/b/0"); ptr.evaluate(doc)`

**Input domain:**
- `doc=None` → `JSONPointerError` (Invariant 21, line 216–217)
- `doc=dict` → walk tokens; missing key → `JSONPointerError`
- `doc=list` → walk tokens; out-of-bounds or `-` or non-int index → `JSONPointerError`
- `doc` of any other type (`str`, `int`, `float`, `bool`, `bytes`, custom class) AND `self._tokens` is non-empty → `JSONPointerError` (line 256–258)
- `doc=anything` AND `self._tokens == []` (empty pointer) → returns `doc` unchanged (line 219–220)

**Output:** any JSON-serializable Python value (dict, list, str, int, float, bool, None), OR `JSONPointerError` raise.

**Notable design choices:**
- The traversal loop (line 224–259) is iterative, not recursive. **No stack-overflow risk on deep paths** as long as the document itself is finite.
- `idx < 0` check at line 249 catches `-1`, `-5`, etc., which would otherwise be parsed as a negative integer by `int(token)`.
- Leading-zero reject at line 244 uses `str(idx) != token` after `int(token)`. This catches `"01"`, `"007"`, `"00"` but also `"+0"` (which `int()` accepts) — wait, `int("+0") == 0` and `str(0) == "0" != "+0"`, so leading `+` is also rejected, which is correct per RFC 6901 §4 ABNF (digits without sign).
- `-` sentinel at line 232 raises unconditionally — does not support JSON Patch insertion semantics (documented limitation in README line 189).

**Edge cases enumerated from code:**
- `JSONPointer("").evaluate({"a": 1})` → `{"a": 1}` (whole doc)
- `JSONPointer("/").evaluate({"": 0})` → `0` (empty key in object)
- `JSONPointer("/-").evaluate([1,2,3])` → `JSONPointerError` (sentinel rejected)
- `JSONPointer("/01").evaluate([1,2,3])` → `JSONPointerError` (leading-zero reject)
- `JSONPointer("/-1").evaluate([1,2,3])` → `JSONPointerError` (`-1` is negative, fails `idx < 0`)
- `JSONPointer("/true").evaluate([1,2,3])` → `JSONPointerError` (non-integer token, `int("true")` raises `ValueError`, caught at line 239)
- `JSONPointer("/abc").evaluate({"abc": 1})` → `1` (object key, no int conversion)
- `JSONPointer("/0").evaluate(42)` → `JSONPointerError` (cannot index into int — line 256–258)
- `JSONPointer("/a/b/c/d").evaluate({"a":{"b":{"c":{"d":"deep"}}}})` → `"deep"` (deeply nested dict)

---

## Surface 3 — Internal `_unescape_token(token: str) -> str`

**Entry point:** `src/rfc6901jsonpointer/_parser.py` lines 12–43
**Visibility:** private (leading underscore); invoked only from `_parse_pointer` at line 123.

**Input domain:**
- A single raw token string (already split from the pointer by `_parse_pointer`).
- Must contain only `~0`, `~1`, or any other character. Bare `~` → `JSONPointerError`. `~X` for X not in {0,1} → `JSONPointerError`.

**Output:** the unescaped token (e.g. `"a~1b"` → `"a/b"`).

**Edge cases from code:**
- `"~0"` → `"~"`
- `"~1"` → `"/"`
- `"~01"` → `"~1"` (first `~0` → `~`, then `1` is a literal `1`; this is RFC 6901 §4 correct)
- `"~10"` → `"/0"` (first `~1` → `/`, then `0` literal)
- `"~"` (length 1) → `JSONPointerError` (line 28)
- `"~2"` → `JSONPointerError` (line 36–38)
- 10K-char token → clean (no stack growth)

**Why it's a separate surface:** even though it's a private helper, it implements the **only** tilde-decoding rule in the library, and the entire RFC 6901 §4 correctness hinges on it being left-to-right with `~0` decoded first. Bugs here would silently corrupt every `tokens` result.

---

## Surface 4 — `_parse_pointer(ptr: str) -> List[str]` (parse-with-unescape)

**Entry point:** `src/rfc6901jsonpointer/_parser.py` lines 46–123
**Visibility:** private; invoked only from `JSONPointer.__init__` at line 177.
**Output:** list of unescaped tokens.

**Input domain:** same as constructor pointer arg (validated non-string/empty by caller first).

**Notable design choices:**
- The tokenizer uses a single forward pass with manual char-by-char dispatch (no regex). Splitting on `/` is done by checking whether the previous char accumulated was `~` (meaning a `~1` is in progress); if so, the `/` becomes part of the current token, otherwise it terminates it.
- The `_parse_pointer_raw` sibling (lines 293–340) does the same pass but skips the final `_unescape_token` call. Both algorithms have identical token-splitting logic, duplicated. This is a maintenance risk (see findings in CWE_MAP.md and VULN_AUDIT.md).

**Edge cases from code:**
- `"/a~1b/c"` — the `/` after `~1b` is correctly NOT a separator (the `~1` consumed the `~` and the `b`, leaving the next `/` as a real separator). Test at `test_parser.py::TestTildeUnescape::test_complex_escape_single_token` confirms.
- `"/a/b~1c/d"` — `tokens = ["a", "b/c", "d"]` (line 487–490 of test_parser.py).
- `"/foo/"` — trailing `/` → tokens `["foo", ""]` (line 64 of test_parser.py).

---

## Surface 5 — `_parse_pointer_raw(ptr: str) -> List[str]` (parse-without-unescape)

**Entry point:** `src/rfc6901jsonpointer/_parser.py` lines 293–340
**Visibility:** private; invoked only from `JSONPointer.__init__` at line 168.
**Output:** list of raw (still-tilde-encoded) tokens.

**Why it's a separate surface:** it backs the `raw_tokens` property (line 193–195) and enables round-trip (`"/" + "/".join(ptr.raw_tokens) == original_ptr`). The duplication of the token-splitting loop with `_parse_pointer` is itself a finding — see VULN_AUDIT.md Finding F-01.

---

## Surface 6 — Public properties: `tokens`, `raw_tokens`, `__str__`, `__repr__`, `__eq__`, `__hash__`

**Entry points:**
- `tokens` property: `_parser.py` lines 187–190 → returns `list(self._tokens)` (defensive copy)
- `raw_tokens` property: `_parser.py` lines 192–195 → returns `list(self._raw_tokens)` (defensive copy)
- `__str__`: `_parser.py` lines 270–274 → re-encodes the token list back to a pointer string
- `__repr__`: `_parser.py` lines 267–268 → `JSONPointer(<raw_tokens>)`
- `__eq__`: `_parser.py` lines 280–283
- `__hash__`: `_parser.py` lines 285–286 → `hash(tuple(self._tokens))`

**Why it's a surface:**
- `__str__` performs the **inverse** of tilde-unescape: `t.replace('~', '~0').replace('/', '~1')`. The order matters: must replace `~` BEFORE `/` so that `~1` sequences don't get double-escaped. This is verified by `test_roundtrip_with_escaped_slash` (test_parser.py line 367–370).
- `__hash__` uses tuple-hash of unescaped tokens. Two pointers with different raw representations but identical decoded tokens (e.g. `/a~1b` vs `/a%2Fb` — wait, the latter isn't valid; only `/a~1b` and `"/a"+chr(0x2F)+"b"` aren't both valid either; only `/a~1b` is valid). In practice all collisions come from `__eq__` checking `_tokens` equality.
- Defensive copies on `tokens`/`raw_tokens` mean callers can mutate the returned list without affecting the pointer state (matters for callers that re-use pointers in concurrent contexts).

**Edge cases from code:**
- `str(JSONPointer(""))` → `"/"` (line 271–273: `"/" + "/".join([])` = `"/"`)
- `str(JSONPointer("/"))` → `"//"` (token list `[""]`, joined → `"/"`, prefixed → `"//"`)
- `JSONPointer("/a") == JSONPointer("/a")` → `True`
- `JSONPointer("/a") == "a"` → `NotImplemented` (then Python falls back to identity, so `False`)

---

## Surface 7 — CLI: `python -m rfc6901jsonpointer <pointer> <json>`

**Entry point:** `src/rfc6901jsonpointer/__main__.py` lines 22–61 (`main()`)
**Invocation:** `python3 -m rfc6901jsonpointer /foo/bar '{"foo": {"bar": 42}}'`

**Input domain:**
- argv: 2 args expected. <2 → usage to stderr, exit 1.
- argv[0]: pointer string (passed verbatim to `JSONPointer(argv[0])`)
- argv[1]: JSON document as a string (passed to `json.loads()`)

**Output:**
- stdout: `json.dumps(result, ensure_ascii=False) + "\n"`
- stderr: error message + exit 1 on parse/eval failure
- Exit code: 0 on success, 1 on any error

**Notable design choices that affect attack surface:**
- The CLI does **no** filesystem I/O (no `open()`, no path traversal). RFC 6901 pointers are in-document references, NOT filesystem paths. This is correct behavior — see CWE-22 analysis in CWE_MAP.md.
- `json.loads(argv[1])` will raise `json.JSONDecodeError` on malformed input; the CLI catches this and writes to stderr with exit 1 (lines 35–39).
- The CLI imports the public `JSONPointer` class and constructs it once; any JSONPointerError surfaces as exit 1 with stderr message.
- `json.dumps(result, ensure_ascii=False)` on the result — non-ASCII output passes through unmangled. No encoding injection risk because output goes to stdout (not back into a shell).

**Edge cases from code:**
- No args → usage to stderr, exit 1 (test_cli.py line 71–75)
- Invalid JSON → `JSON parse error: ...` to stderr, exit 1 (test_cli.py line 59–62)
- Pointer that doesn't start with `/` → `JSONPointerError` to stderr, exit 1 (test_cli.py line 54–57)
- Missing key in doc → `JSONPointerError: Token 0 ('x'): key not found` to stderr, exit 1
- Empty pointer → stdout is the whole JSON-encoded doc, exit 0

---

## Surface 8 — Exception hierarchy: `JSONPointerError` (single class)

**Entry point:** `src/rfc6901jsonpointer/_errors.py` lines 8–19 (one class, no subclasses)
**Visibility:** public (`from rfc6901jsonpointer import JSONPointerError`)
**Exception messages:** 10 distinct f-string formats across `_parser.py` and `__main__.py`

**Why it's a surface:**
- The brief lists `JSONPointerTypeError`, `JSONPointerIndexError` as separate classes — they DO NOT EXIST in this codebase. Only `JSONPointerError` is defined. The brief's listing is incorrect for this repo. All error conditions map to the single base class.
- `JSONPointerError` is a subclass of `Exception` (no custom `__init__`); it relies on the default `str(e)` for message display.
- Error messages include the token value (`{token!r}`) and the parent type (`{type(current).__name__}`). Could leak pointer paths into log files — see CWE-209 analysis in CWE_MAP.md.

**Notable:** the constructor's exception-swallowing wrappers (lines 169–172, 178–181) catch `Exception` and re-raise as `JSONPointerError(f"Pointer parsing failed: {e}")`. This means internal bugs (e.g. an unexpected `AttributeError` from a future refactor) get MASKED behind a generic "parsing failed" message — see VULN_AUDIT.md Finding F-04.

---

## Summary

| # | Surface | Type | Public? | Validation boundary |
|---|---------|------|---------|---------------------|
| 1 | `JSONPointer(ptr)` constructor | parse | yes | JSONPointerError on invalid input |
| 2 | `ptr.evaluate(doc)` method | eval | yes | JSONPointerError on bad traversal |
| 3 | `_unescape_token(token)` | parse | no (private) | JSONPointerError on bad tilde |
| 4 | `_parse_pointer(ptr)` | parse | no (private) | delegates to Surface 3 |
| 5 | `_parse_pointer_raw(ptr)` | parse | no (private) | JSONPointerError on bad syntax |
| 6 | `tokens`/`raw_tokens`/`__str__`/etc | serialization | yes | read-only, no input |
| 7 | `python -m rfc6901jsonpointer` | CLI | yes (entry) | exit codes 0/1 |
| 8 | `JSONPointerError` | error | yes (catch) | message format leak risk |

**Total: 8 surfaces** (above the brief's 4–7 target by 1 — `JSONPointerError` warranted separate treatment because the brief incorrectly assumed a subclass hierarchy that doesn't exist).