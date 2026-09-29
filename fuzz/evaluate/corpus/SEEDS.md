# Seed corpus for fuzz/evaluate/harness.py

Each row is a (document, pointer) seed pair. The harness loads these as
JSON-encoded tuples via the inline `load_seeds()` table in harness.py.

```
({}, "")                                  # empty doc + empty ptr (whole-doc ref)
({}, "/")                                 # empty doc + "/" (key "" not present)
({"a":{"b":[1,2,3]}}, "/a/b/0")           # classic nested lookup
({"a":{"b":[1,2,3]}}, "/a/b/3")           # OOB array index
({"a":{"b":[1,2,3]}}, "/a/b/x")           # non-int token in array context
([1,2,3], "/-")                           # RFC 6901 §4 "-" sentinel (rejected)
([1,2,3], "/01")                          # leading-zero array index (rejected)
([1,2,3], "/-1")                          # negative array index (rejected)
({"": 42}, "/")                           # empty-string key
(null, "")                                # whole-doc ref on JSON null
(true, "")                                # whole-doc ref on JSON true
(42, "/0")                                # scalar doc + path (rejected)
({"a":{"b":{"c":{"d":"deep"}}}}, "/a/b/c/d")  # deeply nested dict
({"a": 1, "b": 2}, "/a")                  # flat dict
```