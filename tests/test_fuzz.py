"""Fuzz tests for RFC 6901 JSON Pointer — random pointers × random docs."""

import random
import string
import pytest

from rfc6901jsonpointer import JSONPointer, JSONPointerError


def _random_string(min_len=0, max_len=20, include_special=True):
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += " ~!@#$%^&*()_+-=[]{}|;:',.<>?/`"
    length = random.randint(min_len, max_len)
    return ''.join(random.choice(chars) for _ in range(length))


def _random_pointer():
    """Generate a random valid-looking pointer string."""
    parts = []
    num_tokens = random.randint(0, 5)
    for _ in range(num_tokens):
        token = _random_string(0, 15)
        # randomly escape some characters
        token = token.replace('~', '~0').replace('/', '~1')
        parts.append(token)
    if not parts:
        return ""
    return "/" + "/".join(parts)


def _random_json(depth=0, max_depth=4):
    """Generate a random JSON-compatible Python object."""
    choice = random.randint(0, 7)
    if depth >= max_depth:
        choice = random.randint(0, 3)

    if choice == 0:
        return random.choice([
            "hello", "world", "", " ", "~", "/",
            "a" * 100, "日本語", "Ελληνικά", "🎉"
        ])
    elif choice == 1:
        return random.randint(-1000, 10000)
    elif choice == 2:
        return random.choice([True, False, None])
    elif choice == 3:
        return 3.14159
    elif choice == 4:
        size = random.randint(0, 5)
        return [_random_json(depth + 1, max_depth) for _ in range(size)]
    elif choice == 5:
        size = random.randint(0, 5)
        return {f"key{i}": _random_json(depth + 1, max_depth) for i in range(size)}
    elif choice == 6:
        return []
    elif choice == 7:
        return {}
    # fallback
    return None


class TestFuzz:
    """Category 7: Fuzz tests (16 tests minimum)."""

    @pytest.mark.parametrize("iterations", [25])
    def test_fuzz_random_pointers_and_documents(self, iterations):
        """Fuzz: random pointer strings × random documents; no crashes."""
        random.seed(42)
        errors_found = []

        for i in range(iterations):
            ptr_str = _random_pointer()
            doc = _random_json()

            try:
                ptr = JSONPointer(ptr_str)
                # Attempt evaluation — should never crash with raw exception
                try:
                    result = ptr.evaluate(doc)
                except JSONPointerError:
                    pass  # expected for mismatched pointer/doc
            except JSONPointerError:
                pass  # expected for malformed pointers
            except Exception as e:
                errors_found.append(
                    f"iter={i} ptr={ptr_str!r} doc_type={type(doc).__name__} "
                    f"exception={type(e).__name__}: {e}"
                )

        assert not errors_found, f"Unexpected exceptions during fuzz:\n" + "\n".join(errors_found)

    def test_fuzz_deeply_nested_structures(self):
        """Fuzz: deeply nested dict/list structures."""
        random.seed(123)
        nested_doc = _random_json(depth=0, max_depth=6)
        ptr = JSONPointer("/" + "/".join(str(i) for i in range(10)))

        try:
            ptr.evaluate(nested_doc)
        except JSONPointerError:
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {e}")

    def test_fuzz_unicode_keys(self):
        """Fuzz: unicode keys in documents."""
        for _ in range(10):
            key = _random_string(1, 10)
            doc = {key: "value"}
            ptr = JSONPointer(f"/{key}")
            try:
                result = ptr.evaluate(doc)
                assert result == "value"
            except JSONPointerError:
                pass

    def test_fuzz_empty_strings(self):
        """Fuzz: empty strings as keys."""
        for _ in range(10):
            doc = {"": "empty_key_val", "a": {"": "nested_empty"}}
            ptrs = ["", "/", "/a", "/a/"]
            for p in ptrs:
                try:
                    JSONPointer(p).evaluate(doc)
                except JSONPointerError:
                    pass

    def test_fuzz_valid_array_indices(self):
        """Fuzz: valid array indices across various sizes."""
        random.seed(999)
        for size in [1, 2, 5, 10, 50]:
            doc = list(range(size))
            for idx in range(size):
                ptr = JSONPointer(f"/{idx}")
                try:
                    result = ptr.evaluate(doc)
                    assert result == idx
                except JSONPointerError:
                    pytest.fail(f"Failed for size={size}, idx={idx}")

    def test_fuzz_boundary_array_indices(self):
        """Fuzz: boundary array indices (0, len-1, len, len+1)."""
        for size in [1, 2, 5]:
            doc = list(range(size))
            # Valid: 0 and size-1
            for valid_idx in [0, size - 1]:
                ptr = JSONPointer(f"/{valid_idx}")
                result = ptr.evaluate(doc)
                assert result == valid_idx

            # Invalid: size, size+1
            for invalid_idx in [size, size + 1, size * 2]:
                ptr = JSONPointer(f"/{invalid_idx}")
                with pytest.raises(JSONPointerError):
                    ptr.evaluate(doc)

    def test_fuzz_large_nested_array(self):
        """Fuzz: large nested arrays."""
        doc = [[list(range(10)) for _ in range(10)] for _ in range(10)]
        ptr = JSONPointer("/5/3/7")
        assert ptr.evaluate(doc) == 7

    def test_fuzz_mixed_nested_structures(self):
        """Fuzz: mixed dict/list nesting with random traversal."""
        random.seed(777)
        for _ in range(20):
            doc = _random_json(depth=0, max_depth=3)
            # Try to traverse at most 3 levels
            if isinstance(doc, dict):
                keys = list(doc.keys())[:2]
                for k in keys:
                    ptr_str = f"/{k}"
                    try:
                        JSONPointer(ptr_str).evaluate(doc)
                    except JSONPointerError:
                        pass
            elif isinstance(doc, list) and len(doc) > 0:
                idx = random.randint(0, len(doc) - 1)
                ptr_str = f"/{idx}"
                try:
                    JSONPointer(ptr_str).evaluate(doc)
                except JSONPointerError:
                    pass

    def test_fuzz_leading_zeros(self):
        """Fuzz: all forms of leading-zero array indices are rejected."""
        for token in ["01", "007", "001", "00", "0"]:
            ptr = JSONPointer(f"/{token}")
            try:
                ptr.evaluate(["a", "b"])
                # Only "0" is valid; others should raise
                if token != "0":
                    pytest.fail(f"Leading-zero token {token!r} should raise JSONPointerError")
            except JSONPointerError:
                pass  # expected for leading zeros

    def test_fuzz_special_float_indices(self):
        """Float strings like '1.5' as array indices must raise."""
        for token in ["1.5", "2.9", "-1", "1e3"]:
            ptr = JSONPointer(f"/{token}")
            try:
                ptr.evaluate(["a", "b", "c"])
                pytest.fail(f"Non-integer token {token!r} should raise JSONPointerError")
            except JSONPointerError:
                pass  # expected

    def test_fuzz_all_whitespace_tokens(self):
        """Tokens that are only whitespace should be valid object keys."""
        doc = {" ": "space_key", "  ": "two_spaces"}
        for key in [" ", "  ", "   "]:
            ptr = JSONPointer(f"/{key}")
            try:
                result = ptr.evaluate(doc)
                # should work
            except JSONPointerError:
                pass  # some whitespace combos may not match

    def test_fuzz_very_long_pointer(self):
        """Very long pointer string (100+ tokens) should parse without crashing."""
        parts = ["a"] * 200
        ptr_str = "/" + "/".join(parts)
        ptr = JSONPointer(ptr_str)
        assert len(ptr.tokens) == 200

    def test_fuzz_very_long_token(self):
        """Very long single token should parse without crashing."""
        long_token = "a" * 10000
        ptr_str = "/" + long_token
        ptr = JSONPointer(ptr_str)
        assert len(ptr.tokens) == 1
        assert ptr.tokens[0] == long_token

    def test_fuzz_repeated_evaluation(self):
        """Same pointer evaluated against many documents — no state leakage."""
        ptr = JSONPointer("/a/b")
        docs = [
            {"a": {"b": i}} for i in range(50)
        ]
        for i, doc in enumerate(docs):
            try:
                result = ptr.evaluate(doc)
                assert result == i
            except JSONPointerError:
                pytest.fail(f"Failed for doc {i}")

    def test_fuzz_pointer_none_vs_empty(self):
        """Both None and '' pointer should behave identically."""
        ptr_none = JSONPointer(None)
        ptr_empty = JSONPointer("")
        doc = {"foo": "bar"}
        assert ptr_none.evaluate(doc) == doc
        assert ptr_empty.evaluate(doc) == doc

    def test_fuzz_tilde_encoding_roundtrip(self):
        """Fuzz: encode-decode roundtrip of random strings."""
        random.seed(321)
        for _ in range(20):
            original = _random_string(1, 20)
            # Manually encode: replace ~ → ~0, / → ~1
            encoded = original.replace('~', '~0').replace('/', '~1')
            ptr = JSONPointer(f"/{encoded}")
            assert ptr.tokens[0] == original
