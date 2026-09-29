"""RFC 6901 JSON Pointer parser — pure stdlib, zero deps."""

from typing import Any, List, Optional

from ._errors import JSONPointerError


# ---------------------------------------------------------------------------
# Tokenisation
# ---------------------------------------------------------------------------

def _unescape_token(token: str) -> str:
    """Decode tilde-escapes in a single reference token.

    Per RFC 6901 Section 4:
      ~1  → /
      ~0  → ~

    Evaluation order: scan left-to-right; each '~' is followed by 0 or 1.
    Any other character after '~' (including end-of-string) is invalid.
    """
    result = []
    i = 0
    while i < len(token):
        ch = token[i]
        if ch == '~':
            if i + 1 >= len(token):
                raise JSONPointerError(f"Invalid tilde escape at end of token: {token!r}")
            nxt = token[i + 1]
            if nxt == '0':
                result.append('~')
            elif nxt == '1':
                result.append('/')
            else:
                raise JSONPointerError(
                    f"Invalid tilde escape '~{nxt}' in token: {token!r}"
                )
            i += 2
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


# ---------------------------------------------------------------------------
# JSONPointer
# ---------------------------------------------------------------------------

class JSONPointer:
    """RFC 6901 JSON Pointer — pure stdlib, zero deps.

    A JSON Pointer is a string of tokens separated by '/' that references a
    specific value within a JSON document (RFC 6901).

    Args:
        ptr: Pointer string. None or "" → empty token list (whole document).
             Must start with '/' (or be empty). Invalid syntax raises
             JSONPointerError.

    Token syntax:
      - Part before first '/' (if any) is ignored (pointers always start '/')
      - Each subsequent '/' separates a reference token
      - '~1' decodes to '/', '~0' decodes to '~'
      - Tokens are decoded left-to-right; '~01' → '~' then '1' → '~1' not '/1'

    Example:
        >>> ptr = JSONPointer("/a/b/0")
        >>> ptr.evaluate({"a": {"b": ["x", "y"]}})
        'x'
    """

    __slots__ = ('_raw_tokens', '_tokens')

    def __init__(self, ptr: Optional[str]) -> None:
        if ptr is None:
            ptr = ""
        if not isinstance(ptr, str):
            raise JSONPointerError(f"Pointer must be str, got {type(ptr).__name__}")
        self._raw_tokens: List[str] = []
        self._tokens: List[str] = []

        # Empty string is valid (refers to whole document)
        if ptr == "":
            return

        # Must start with '/'
        if not ptr.startswith('/'):
            raise JSONPointerError(
                f"JSON pointer must start with '/' or be empty, got: {ptr!r}"
            )

        # Split on '/'
        raw_tokens = ptr.split('/')

        # First element after split(''/a/b'') is '' (empty string before first /)
        # We already verified ptr starts with '/', so raw_tokens[0] == ''
        # Skip the leading empty token.
        self._raw_tokens = raw_tokens[1:]

        # Decode each token
        try:
            self._tokens = [_unescape_token(t) for t in self._raw_tokens]
        except JSONPointerError:
            raise
        except Exception as e:
            raise JSONPointerError(f"Token parsing failed: {e}") from e

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def tokens(self) -> List[str]:
        """Unescaped reference tokens (decoded, ready for document traversal)."""
        return list(self._tokens)

    @property
    def raw_tokens(self) -> List[str]:
        """Reference tokens BEFORE tilde-unescaping (still contain '~0'/'~1')."""
        return list(self._raw_tokens)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, doc: Any) -> Any:
        """Evaluate this pointer against a JSON document.

        Args:
            doc: A JSON-compatible document (dict, list, or primitive).
                 None raises JSONPointerError (Invariant 21).

        Returns:
            The referenced value.

        Raises:
            JSONPointerError: If doc is None, a token resolves to a missing
                key, an out-of-bounds array index, or the '-' sentinel
                is used in a context that requires a specific value.
        """
        if doc is None:
            raise JSONPointerError("Document is None; cannot evaluate pointer")

        # Empty token list → whole document
        if not self._tokens:
            return doc

        current: Any = doc

        for i, token in enumerate(self._tokens):
            if isinstance(current, dict):
                if token not in current:
                    raise JSONPointerError(
                        f"Token {i!r} ({token!r}): key not found in object"
                    )
                current = current[token]
            elif isinstance(current, list):
                # RFC 6901 Section 4: '-' is the array end sentinel (out-of-bounds)
                if token == '-':
                    raise JSONPointerError(
                        f"Token {i!r} ('-'): array end sentinel cannot be used "
                        "for reading; use a non-negative index instead"
                    )
                # Parse as non-negative integer
                try:
                    idx = int(token)
                except ValueError:
                    raise JSONPointerError(
                        f"Token {i!r} ({token!r}): cannot use non-integer token "
                        f"{token!r} to index into array"
                    )
                # RFC 6901: leading zeros not allowed (e.g., "01" is invalid)
                if str(idx) != token:
                    raise JSONPointerError(
                        f"Token {i!r} ({token!r}): leading zeros in array index "
                        f"are not allowed per RFC 6901; got {idx}"
                    )
                if idx < 0 or idx >= len(current):
                    raise JSONPointerError(
                        f"Token {i!r} ({token!r}): array index {idx} out of bounds "
                        f"for array of length {len(current)}"
                    )
                current = current[idx]
            else:
                raise JSONPointerError(
                    f"Token {i!r} ({token!r}): cannot index into a {type(current).__name__}; "
                    "only dict and list are valid JSON Pointer targets"
                )

        return current

    # ------------------------------------------------------------------
    # String representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return f"JSONPointer({self.raw_tokens!r})"

    def __str__(self) -> str:
        return "/" + "/".join(
            t.replace('~', '~0').replace('/', '~1')
            for t in self._tokens
        )

    # ------------------------------------------------------------------
    # Equality
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JSONPointer):
            return NotImplemented
        return self._tokens == other._tokens

    def __hash__(self) -> int:
        return hash(tuple(self._tokens))
