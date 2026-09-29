"""CLI for RFC 6901 JSON Pointer evaluator.

Usage:
    python -m rfc6901jsonpointer <pointer> <json_document>

Arguments:
    pointer       RFC 6901 pointer string (e.g. /foo/bar or "")
    json_document JSON document to evaluate against (as a JSON string)

Examples:
    python -m rfc6901jsonpointer /foo/bar '{"foo": {"bar": 42}}'
    python -m rfc6901jsonpointer /0 '[1, 2, 3]'
    python -m rfc6901jsonpointer "" '{"a": 1}'
"""

import json
import sys

from rfc6901jsonpointer import JSONPointer, JSONPointerError


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) < 2:
        sys.stderr.write("Usage: python -m rfc6901jsonpointer <pointer> <json_document>\n")
        sys.stderr.write("Example: python -m rfc6901jsonpointer /foo/bar '{\"foo\": {\"bar\": 42}}'\n")
        sys.exit(1)

    ptr_str = argv[0]
    json_str = argv[1]

    # Parse JSON document
    try:
        doc = json.loads(json_str)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"JSON parse error: {e}\n")
        sys.exit(1)

    # Parse pointer
    try:
        ptr = JSONPointer(ptr_str)
    except JSONPointerError as e:
        sys.stderr.write(f"JSONPointerError: {e}\n")
        sys.exit(1)

    # Evaluate
    try:
        result = ptr.evaluate(doc)
    except JSONPointerError as e:
        sys.stderr.write(f"JSONPointerError: {e}\n")
        sys.exit(1)

    # Print result as JSON
    try:
        output = json.dumps(result, ensure_ascii=False)
        sys.stdout.write(output + "\n")
    except Exception as e:
        sys.stderr.write(f"Output encoding error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
