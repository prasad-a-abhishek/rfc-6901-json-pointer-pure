"""rfc6901jsonpointer — Zero-dependency pure-Python RFC 6901 JSON Pointer parser."""

from ._errors import JSONPointerError
from ._parser import JSONPointer

__version__ = "0.1.0"
__all__ = ["JSONPointer", "JSONPointerError", "__version__"]
