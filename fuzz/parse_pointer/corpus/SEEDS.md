# Seed corpus for fuzz/parse_pointer/harness.py

Hand-picked reference inputs that exercise the JSONPointer constructor's
validation surface — empty pointer, lone '/', tilde escapes, leading slash,
non-string types, very long tokens, and the round-trip property.

These are replayed at the start of every fuzz run before random generation,
so each run gets the same baseline coverage. Each line is one raw pointer
string (the harness reads them as str literals).

```
""
"/"
"//"
"/foo/bar"
"/~0/~1"
"/~"
"/~2"
"/~01"
"/~10"
"/a~1b/c"
"/a/b/0"
"/a/b/c/d/e/f"
"/foo/"
"/-"
"/01"
"/-1"
"/~0~1"
"/a~1b~0c"
"/000"
"/+0"
"/+1"
"/\t"
"/ "
"/a/b/c"
```