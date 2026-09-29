from rfc6901jsonpointer import JSONPointer

tests = [
    ("/a~01", ["~1"]),          # ~0→~, 1 stays → ~1
    ("/a~10", ["/0"]),          # ~1→/, 0 stays → /0
    ("/a~~0b", ["a~0b"]),        # ~~→~, 0→0, b→b
    ("/a~1b~0c~1d", ["a/b~c/d"]), # ~1→/, ~0→~, ~1→/, tokens are split on /
    ("/a~1b~0c~1", ["a/b", "c/"]),
    ("/~0", ["~"]),
    ("/~1", ["/"]),
    ("/a~~", ["a~"]),            # ~~→~, nothing after
]

for ptr_str, expected in tests:
    try:
        ptr = JSONPointer(ptr_str)
        result = ptr.tokens
        status = "OK" if result == expected else f"FAIL: got {result}"
    except Exception as e:
        status = f"ERROR: {e}"
    print(f"{ptr_str:25s} expected={expected!s:25s}  {status}")
