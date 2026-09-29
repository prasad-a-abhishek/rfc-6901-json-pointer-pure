# Seed corpus for fuzz/unescape/harness.py

Hand-picked single-token strings used to verify _unescape_token() against
RFC 6901 §4's left-to-right tilde-decoding rule. The harness replays a
larger canonical table (CANONICAL in harness.py) automatically; this file
is the audit-trail copy.

```
~
~0
~1
~01
~10
~~0
a~1b
a~1b~0c
abc
a~0b
~0~1
```