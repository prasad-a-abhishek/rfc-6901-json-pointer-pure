from rfc6901jsonpointer import JSONPointer

# RFC 6901 Section 5 examples
examples = [
    ('/', {'foo': ['bar', 'baz'], '': 0, 'a/b': 1}, 0),
    ('/foo', {'foo': ['bar', 'baz'], '': 0, 'a/b': 1}, ['bar', 'baz']),
    ('/foo/0', {'foo': ['bar', 'baz'], '': 0, 'a/b': 1}, 'bar'),
    ('/a~1b', {'foo': ['bar', 'baz'], '': 0, 'a/b': 1}, 1),
    ('/foo/1', {'foo': ['bar', 'baz'], '': 0, 'a/b': 1}, 'baz'),
]

all_ok = True
for ptr_str, doc, expected in examples:
    ptr = JSONPointer(ptr_str)
    try:
        result = ptr.evaluate(doc)
        status = 'OK' if result == expected else f'FAIL: got {result!r}'
    except Exception as e:
        status = f'ERROR: {e}'
        all_ok = False
    print(f'{ptr_str:20s} => {status}')

print()
print('All OK:', all_ok)
