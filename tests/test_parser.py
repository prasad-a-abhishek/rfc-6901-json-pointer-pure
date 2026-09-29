"""Unit + integration tests for RFC 6901 JSON Pointer parser."""

import pytest

from rfc6901jsonpointer import JSONPointer, JSONPointerError


# ======================================================================
# 1. TOKENISATION BASIC
# ======================================================================

class TestTokenisationBasic:
    def test_empty_pointer_none(self):
        ptr = JSONPointer(None)
        assert ptr.tokens == []
        assert ptr.raw_tokens == []

    def test_empty_pointer_empty_string(self):
        ptr = JSONPointer("")
        assert ptr.tokens == []
        assert ptr.raw_tokens == []

    def test_single_slash_only(self):
        ptr = JSONPointer("/")
        assert ptr.tokens == [""]
        assert ptr.raw_tokens == [""]

    def test_single_key(self):
        ptr = JSONPointer("/a")
        assert ptr.tokens == ["a"]
        assert ptr.raw_tokens == ["a"]

    def test_two_keys(self):
        ptr = JSONPointer("/a/b")
        assert ptr.tokens == ["a", "b"]
        assert ptr.raw_tokens == ["a", "b"]

    def test_key_and_array_index(self):
        ptr = JSONPointer("/a/0")
        assert ptr.tokens == ["a", "0"]
        assert ptr.raw_tokens == ["a", "0"]

    def test_array_end_sentinel(self):
        ptr = JSONPointer("/a/-")
        assert ptr.tokens == ["a", "-"]
        assert ptr.raw_tokens == ["a", "-"]

    def test_multiple_array_indices(self):
        ptr = JSONPointer("/a/0/b/1")
        assert ptr.tokens == ["a", "0", "b", "1"]

    def test_empty_key(self):
        ptr = JSONPointer("/a//b")
        assert ptr.tokens == ["a", "", "b"]

    def test_deeply_nested(self):
        ptr = JSONPointer("/a/b/c/d/e")
        assert ptr.tokens == ["a", "b", "c", "d", "e"]

    def test_leading_slash_only(self):
        ptr = JSONPointer("/")
        assert ptr.tokens == [""]

    def test_trailing_slash(self):
        ptr = JSONPointer("/foo/")
        assert ptr.tokens == ["foo", ""]


# ======================================================================
# 2. TILDE-UNESCAPE
# ======================================================================

class TestTildeUnescape:
    def test_tilde_zero_decodes_tilde(self):
        ptr = JSONPointer("/a~0b")
        assert ptr.tokens == ["a~b"]

    def test_tilde_one_decodes_slash(self):
        ptr = JSONPointer("/a~1b")
        assert ptr.tokens == ["a/b"]

    def test_double_tilde_invalid(self):
        # RFC 6901: '~' MUST be followed by 0 or 1. '~~' is invalid.
        with pytest.raises(JSONPointerError):
            JSONPointer("/a~~")

    def test_double_tilde_invalid_in_middle(self):
        # '~0~' is valid '~0' then invalid bare '~'
        with pytest.raises(JSONPointerError):
            JSONPointer("/a~0~")

    def test_tilde_zero_one_sequence(self):
        # ~01: decode ~0 to ~, then 1 stays as 1 → "~1"
        ptr = JSONPointer("/~01")
        assert ptr.tokens == ["~1"]

    def test_tilde_one_zero_sequence(self):
        # ~10: decode ~1 to /, then 0 stays as 0 → "/0"
        ptr = JSONPointer("/~10")
        assert ptr.tokens == ["/0"]

    def test_multiple_escapes_single_token(self):
        # a~1b~0c = "a/b~c" (single token, no unescaped /)
        ptr = JSONPointer("/a~1b~0c")
        assert ptr.tokens == ["a/b~c"]

    def test_trailing_tilde_invalid(self):
        with pytest.raises(JSONPointerError):
            JSONPointer("/foo~")

    def test_tilde_two_invalid(self):
        with pytest.raises(JSONPointerError):
            JSONPointer("/foo~2")

    def test_tilde_three_invalid(self):
        with pytest.raises(JSONPointerError):
            JSONPointer("/foo~3")

    def test_tilde_nine_invalid(self):
        with pytest.raises(JSONPointerError):
            JSONPointer("/foo~9")

    def test_bare_tilde_via_escape(self):
        ptr = JSONPointer("/~0")
        assert ptr.tokens == ["~"]

    def test_slash_in_key_via_escape(self):
        ptr = JSONPointer("/a~1b")
        assert ptr.tokens == ["a/b"]

    def test_complex_escape_single_token(self):
        # a~1b~0c~1 = "a/b~c/" (single token)
        ptr = JSONPointer("/a~1b~0c~1")
        assert ptr.tokens == ["a/b~c/"]

    def test_empty_after_tilde(self):
        ptr = JSONPointer("/~1")
        assert ptr.tokens == ["/"]


# ======================================================================
# 3. OBJECT KEY DISPATCH
# ======================================================================

class TestObjectKeyDispatch:
    def test_simple_string_key(self):
        ptr = JSONPointer("/foo")
        assert ptr.evaluate({"foo": "bar"}) == "bar"

    def test_unicode_key(self):
        ptr = JSONPointer("/Japanese")
        assert ptr.evaluate({"Japanese": "OK"}) == "OK"

    def test_numeric_string_key(self):
        ptr = JSONPointer("/123")
        assert ptr.evaluate({"123": "number_key"}) == "number_key"

    def test_key_with_special_chars(self):
        ptr = JSONPointer("/a.b.c")
        assert ptr.evaluate({"a.b.c": "dot_key"}) == "dot_key"

    def test_missing_key_raises(self):
        ptr = JSONPointer("/nonexistent")
        with pytest.raises(JSONPointerError):
            ptr.evaluate({"existing": 1})

    def test_deeply_nested_key(self):
        ptr = JSONPointer("/a/b/c/d")
        doc = {"a": {"b": {"c": {"d": "deep"}}}}
        assert ptr.evaluate(doc) == "deep"

    def test_key_with_empty_string(self):
        ptr = JSONPointer("/")
        assert ptr.evaluate({"": "empty_key_value"}) == "empty_key_value"

    def test_key_in_list_item(self):
        ptr = JSONPointer("/0/foo")
        doc = [{"foo": "first"}, {"foo": "second"}]
        assert ptr.evaluate(doc) == "first"

    def test_key_not_in_list_item(self):
        ptr = JSONPointer("/1/bar")
        doc = [{"foo": "first"}, {"bar": "second_item"}]
        assert ptr.evaluate(doc) == "second_item"

    def test_empty_doc_with_key(self):
        ptr = JSONPointer("/foo")
        with pytest.raises(JSONPointerError):
            ptr.evaluate({})


# ======================================================================
# 4. ARRAY INDEX DISPATCH
# ======================================================================

class TestArrayIndexDispatch:
    def test_zero_index(self):
        ptr = JSONPointer("/0")
        assert ptr.evaluate(["a", "b", "c"]) == "a"

    def test_positive_index(self):
        ptr = JSONPointer("/2")
        assert ptr.evaluate(["a", "b", "c"]) == "c"

    def test_out_of_bounds_raises(self):
        ptr = JSONPointer("/5")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b", "c"])

    def test_leading_zero_rejected(self):
        # RFC 6901: "01" is NOT valid; "10" is valid
        ptr = JSONPointer("/01")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_ten_is_valid(self):
        ptr = JSONPointer("/10")
        doc = list(range(20))
        assert ptr.evaluate(doc) == 10

    def test_array_end_sentinel_read_raises(self):
        ptr = JSONPointer("/-")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b", "c"])

    def test_negative_index_raises(self):
        ptr = JSONPointer("/-1")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_non_integer_index_raises(self):
        ptr = JSONPointer("/abc")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_mixed_array_object(self):
        ptr = JSONPointer("/1/name")
        doc = [{"id": 1}, {"name": "second"}]
        assert ptr.evaluate(doc) == "second"

    def test_nested_array(self):
        ptr = JSONPointer("/0/1")
        doc = [["a", "b"], ["c", "d"]]
        assert ptr.evaluate(doc) == "b"


# ======================================================================
# 5. END-TO-END EVALUATE (RFC 6901 SECTION 5)
# ======================================================================

class TestEvaluateRFC6901Section5:
    def test_rfc6901_empty_pointer(self):
        ptr = JSONPointer("")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == doc

    def test_rfc6901_foo(self):
        ptr = JSONPointer("/foo")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == ["bar", "baz"]

    def test_rfc6901_foo_0(self):
        ptr = JSONPointer("/foo/0")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == "bar"

    def test_rfc6901_empty_key(self):
        ptr = JSONPointer("/")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == 0

    def test_rfc6901_escaped_slash(self):
        # "/a~1b" means key "a/b" in the document
        ptr = JSONPointer("/a~1b")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == 1

    def test_rfc6901_foo_1(self):
        ptr = JSONPointer("/foo/1")
        doc = {"foo": ["bar", "baz"], "": 0, "a/b": 1}
        assert ptr.evaluate(doc) == "baz"

    def test_nested_object_access(self):
        ptr = JSONPointer("/a/b/c")
        doc = {"a": {"b": {"c": "deep_value"}}}
        assert ptr.evaluate(doc) == "deep_value"

    def test_array_in_object_in_array(self):
        ptr = JSONPointer("/0/a/1")
        doc = [{"a": ["x", "y"]}, {"a": ["p", "q"]}]
        assert ptr.evaluate(doc) == "y"

    def test_whole_array_access(self):
        ptr = JSONPointer("/data")
        doc = {"data": [1, 2, 3]}
        assert ptr.evaluate(doc) == [1, 2, 3]

    def test_whole_nested_array_item(self):
        ptr = JSONPointer("/items/0")
        doc = {"items": [{"name": "first"}, {"name": "second"}]}
        assert ptr.evaluate(doc) == {"name": "first"}

    def test_evaluate_list_at_root(self):
        ptr = JSONPointer("/0")
        assert ptr.evaluate(["first", "second"]) == "first"

    def test_evaluate_empty_key_in_nested(self):
        ptr = JSONPointer("/a/")
        doc = {"a": {"": "empty_key_value"}}
        assert ptr.evaluate(doc) == "empty_key_value"

    def test_key_with_slash_escaped(self):
        ptr = JSONPointer("/a~1b/c~1d")
        doc = {"a/b": {"c/d": "value"}}
        assert ptr.evaluate(doc) == "value"

    def test_tilde_escaped_key_literal_tilde(self):
        ptr = JSONPointer("/a~0b")
        doc = {"a~b": "value"}
        assert ptr.evaluate(doc) == "value"

    def test_evaluate_returns_primitive(self):
        ptr = JSONPointer("/a/b/c")
        doc = {"a": {"b": {"c": 42}}}
        assert ptr.evaluate(doc) == 42

    def test_evaluate_returns_bool(self):
        ptr = JSONPointer("/flag")
        doc = {"flag": True}
        assert ptr.evaluate(doc) is True

    def test_evaluate_returns_null(self):
        ptr = JSONPointer("/nulled")
        doc = {"nulled": None}
        assert ptr.evaluate(doc) is None

    def test_evaluate_returns_empty_object(self):
        ptr = JSONPointer("/empty")
        doc = {"empty": {}}
        assert ptr.evaluate(doc) == {}

    def test_evaluate_returns_empty_array(self):
        ptr = JSONPointer("/blanks")
        doc = {"blanks": []}
        assert ptr.evaluate(doc) == []

    def test_escaped_slash_and_escaped_tilde_mixed(self):
        ptr = JSONPointer("/a~1b~0c")
        doc = {"a/b~c": "found"}
        assert ptr.evaluate(doc) == "found"


# ======================================================================
# 6. ROUND-TRIP
# ======================================================================

class TestRoundTrip:
    def test_raw_tokens_preserves_input(self):
        raw = "/foo/bar"
        ptr = JSONPointer(raw)
        assert "/" + "/".join(ptr.raw_tokens) == raw

    def test_roundtrip_simple(self):
        ptr = JSONPointer("/a/b/c")
        assert ptr.tokens == ["a", "b", "c"]

    def test_roundtrip_with_escaped_slash(self):
        ptr = JSONPointer("/a~1b")
        assert ptr.tokens == ["a/b"]
        assert str(ptr) == "/a~1b"

    def test_str_reconstruction(self):
        ptr = JSONPointer("/foo")
        assert str(ptr) == "/foo"

    def test_str_reconstruction_with_slash_key(self):
        ptr = JSONPointer("/a~1b")
        assert str(ptr) == "/a~1b"

    def test_str_reconstruction_complex(self):
        ptr = JSONPointer("/a/b~1c~0d")
        # a, b/c~d
        assert ptr.tokens == ["a", "b/c~d"]

    def test_equality(self):
        ptr1 = JSONPointer("/a/b")
        ptr2 = JSONPointer("/a/b")
        assert ptr1 == ptr2

    def test_equality_different(self):
        ptr1 = JSONPointer("/a/b")
        ptr2 = JSONPointer("/a/c")
        assert ptr1 != ptr2


# ======================================================================
# 7. EDGE CASES / ERROR PATHS
# ======================================================================

class TestEdgeCases:
    def test_none_document_raises(self):
        ptr = JSONPointer("/foo")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(None)

    def test_none_pointer(self):
        ptr = JSONPointer(None)
        assert ptr.evaluate({"anything": 1}) == {"anything": 1}

    def test_integer_pointer_string(self):
        ptr = JSONPointer("/123")
        assert ptr.evaluate({"123": "numeric_key"}) == "numeric_key"

    def test_index_string_not_integer(self):
        ptr = JSONPointer("/abc")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b", "c"])

    def test_primitive_root_with_tokens(self):
        ptr = JSONPointer("/foo")
        with pytest.raises(JSONPointerError):
            ptr.evaluate("string_root")

    def test_boolean_as_array_index(self):
        ptr = JSONPointer("/true")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_pointer_to_entire_list(self):
        ptr = JSONPointer("/items")
        doc = {"items": [1, 2, 3]}
        assert ptr.evaluate(doc) == [1, 2, 3]

    def test_cannot_index_into_string(self):
        ptr = JSONPointer("/0")
        with pytest.raises(JSONPointerError):
            ptr.evaluate("abc")

    def test_number_not_indexable(self):
        ptr = JSONPointer("/0")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(42)

    def test_empty_key_at_end(self):
        ptr = JSONPointer("/foo/")
        assert ptr.evaluate({"foo": {"": "empty_key_inside"}}) == "empty_key_inside"

    def test_correct_nesting_array_object(self):
        # [[{"a": [{"b": "found"}]}]]
        # path: /0/0/a/0/b
        ptr = JSONPointer("/0/0/a/0/b")
        doc = [[{"a": [{"b": "found"}]}]]
        assert ptr.evaluate(doc) == "found"

    def test_index_beyond_list_raises(self):
        ptr = JSONPointer("/10")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_negative_array_index_raises(self):
        ptr = JSONPointer("/-5")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_unsupported_type_raises(self):
        ptr = JSONPointer("/0")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(3.14)

    def test_invalid_pointer_type_passed(self):
        with pytest.raises(JSONPointerError):
            JSONPointer(123)

    def test_invalid_pointer_list(self):
        with pytest.raises(JSONPointerError):
            JSONPointer(["a", "b"])

    def test_pointer_must_start_with_slash(self):
        with pytest.raises(JSONPointerError):
            JSONPointer("foo/bar")

    def test_array_sentinel_minus_not_integer(self):
        ptr = JSONPointer("/-")
        with pytest.raises(JSONPointerError):
            ptr.evaluate(["a", "b"])

    def test_tokenize_escaped_slash_in_second_token(self):
        # /a/b~1c/d = ["a", "b/c", "d"]
        ptr = JSONPointer("/a/b~1c/d")
        assert ptr.tokens == ["a", "b/c", "d"]

    def test_unicode_in_key(self):
        ptr = JSONPointer("/中文")
        doc = {"中文": "Chinese"}
        assert ptr.evaluate(doc) == "Chinese"
