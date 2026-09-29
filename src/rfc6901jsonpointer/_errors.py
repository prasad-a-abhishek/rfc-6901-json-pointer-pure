"""Total error type for RFC 6901 JSON Pointer.

Invariant 21: ALL invalid input (None, malformed, out-of-range, missing)
raises JSONPointerError — NEVER ValueError / TypeError / AttributeError.
"""


class JSONPointerError(Exception):
    """Raised on any invalid RFC 6901 pointer operation.

    Covers:
    - Invalid pointer syntax (not starting with '/' or empty string)
    - Invalid tilde escape sequences (trailing '~', '~2', '~3', etc.)
    - Document is None or missing required structure
    - Missing object key
    - Out-of-bounds array index
    - Array '-' sentinel when insertion is attempted
    """
    pass
