# Seed corpus for fuzz/cli/harness.py

Hand-picked CLI invocations covering the standard exit-code matrix.
Each line below is `pointer<TAB>json` (tab-separated for clarity).
The harness randomises argv across (0, 1, 2, 3, 5) args, so any argv
length is reachable. These seeds cover the canonical ones.

```
/foo/bar	{"foo": {"bar": 42}}
/0	[1, 2, 3]
	{"a": 1}
/a/b	{"a": {"b": [1,2,3]}}
/a	{"a": null}
invalid_pointer	{"a": 1}
/a	not-a-json-document
```

The harness also randomly generates truncated / malformed JSON
(`{"a":`, `[1,2,`, `"unterminated`) and verifies the CLI's
`json.JSONDecodeError` handling (exit 1).