"""RFC 6901 JSON Pointer parser — pure stdlib, zero deps."""

from typing import Any, List, Optional

from ._errors import JSONPointerError


# ---------------------------------------------------------------------------
# Tokenisation — split on unescaped '/' then unescape each token
# ---------------------------------------------------------------------------

def _unescape_token(token: str) -> str:
    """Decode tilde-escapes in a single reference token.

    Per RFC 6901 Section 4:
      ~1  → /
      ~0  → ~

    Characters are decoded strictly left-to-right; each '~' MUST be
    immediately followed by '0' or '1'. Any other character after '~'
    (or a bare '~' at end of string) raises JSONPointerError.
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


def _parse_pointer(ptr: str) -> List[str]:
    """Parse a pointer string into unescaped reference tokens.

    The key challenge: we must split on UNESCAPED '/' only.
    For example '/a~1b/c~1d' → single token 'a/b/c/d' because
    the '~1' within the first segment encodes a literal '/'.

    Algorithm:
    1. Scan the string left to right.
    2. Accumulate characters into the current token.
    3. When we encounter a '/':
       - If it is preceded by '~' (i.e., it is a '~1' escape sequence),
         it is PART of the current token (represents literal '/').
       - Otherwise it is a separator → finalize current token, start new one.
    4. After the scan, unescape each accumulated raw token.
    """
    if ptr == "":
        return []

    if not ptr.startswith('/'):
        raise JSONPointerError(
            f"JSON pointer must start with '/' or be empty, got: {ptr!r}"
        )

    tokens: List[str] = []
    current = []
    i = 0

    # Skip leading '/' — we already validated it exists
    i = 1

    while i < len(ptr):
        ch = ptr[i]
        if ch == '/':
            # Check if this '/' is escaped (i.e., preceded by '~')
            # We need to look at the raw token built so far (current)
            # to see if the last character is an unprocessed '~'
            # But careful: '~1' as a pair means the '/' is escaped.
            # We can look back: if current ends with '~', this '/' is escaped.
            if current and current[-1] == '~':
                # The '~' at current[-1] is waiting to be paired with next char
                # Since next char is '/', this is '~1' → escaped '/' → part of token
                # Don't treat as separator; just append '/'
                current.append('/')
                i += 1
            else:
                # This '/' is a separator → finalize current token
                tokens.append(''.join(current))
                current = []
                i += 1
        elif ch == '~':
            # Check if next char makes it '~0' or '~1'
            if i + 1 < len(ptr):
                nxt = ptr[i + 1]
                if nxt in ('0', '1'):
                    # Valid escape pair; append both characters to current token
                    current.append('~')
                    current.append(nxt)
                    i += 2
                else:
                    # '~X' where X is not 0 or 1 → invalid
                    raise JSONPointerError(
                        f"Invalid tilde escape '~{nxt}' in pointer: {ptr!r}"
                    )
            else:
                # Trailing '~' with no following character
                raise JSONPointerError(
                    f"Invalid trailing tilde in pointer: {ptr!r}"
                )
        else:
            current.append(ch)
            i += 1

    # Append the final token (last segment, or whole pointer if no separators)
    tokens.append(''.join(current))

    # Now unescape each token
    return [_unescape_token(t) for t in tokens]


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
      - '~1' decodes to '/', '~0' decodes to '~'
      - Tokens are decoded left-to-right; '~01' → '~' then '1' → '~1' not '/1'
      - A '/' may be encoded inside a token via '~1' — it does NOT split

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

        if ptr == "":
            return

        # Parse to get raw tokens first (for raw_tokens property)
        try:
            self._raw_tokens = _parse_pointer_raw(ptr)
        except JSONPointerError:
            raise
        except Exception as e:
            raise JSONPointerError(f"Pointer parsing failed: {e}") from e

        # Parse again for unescaped tokens (share the same algorithm
        # but with unescaping)
        try:
            self._tokens = _parse_pointer(ptr)
        except JSONPointerError:
            raise
        except Exception as e:
            raise JSONPointerError(f"Token unescaping failed: {e}") from e

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
                if token == '-':
                    raise JSONPointerError(
                        f"Token {i!r} ('-'): array end sentinel cannot be used "
                        "for reading; use a non-negative index instead"
                    )
                try:
                    idx = int(token)
                except ValueError:
                    raise JSONPointerError(
                        f"Token {i!r} ({token!r}): cannot use non-integer token "
                        f"{token!r} to index into array"
                    )
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


# ---------------------------------------------------------------------------
# Raw token extraction (for raw_tokens property)
# ---------------------------------------------------------------------------

def _parse_pointer_raw(ptr: str) -> List[str]:
    """Extract raw tokens WITHOUT unescaping (for raw_tokens property).

    Same algorithm as _parse_pointer but without the tilde decoding.
    """
    if ptr == "":
        return []

    if not ptr.startswith('/'):
        raise JSONPointerError(
            f"JSON pointer must start with '/' or be empty, got: {ptr!r}"
        )

    tokens: List[str] = []
    current = []
    i = 1  # skip leading '/'

    while i < len(ptr):
        ch = ptr[i]
        if ch == '/':
            if current and current[-1] == '~':
                current.append('/')
                i += 1
            else:
                tokens.append(''.join(current))
                current = []
                i += 1
        elif ch == '~':
            if i + 1 < len(ptr):
                nxt = ptr[i + 1]
                if nxt in ('0', '1'):
                    current.append('~')
                    current.append(nxt)
                    i += 2
                else:
                    raise JSONPointerError(
                        f"Invalid tilde escape '~{nxt}' in pointer: {ptr!r}"
                    )
            else:
                raise JSONPointerError(
                    f"Invalid trailing tilde in pointer: {ptr!r}"
                )
        else:
            current.append(ch)
            i += 1

    tokens.append(''.join(current))
    return tokens
