# Benchmark: rfc6901jsonpointer

**Environment:** Linux 6.12.67-linuxkit, Python 3.11.15
**Methodology:** 50 iterations x workload, mean + P95 in μs.

| Workload | rfc6901jsonpointer (mean μs) | rfc6901jsonpointer (P95 μs) | Ratio |
|----------|-------------------------------|--------------------------------|-------|
| tiny_doc | 1.05 | 2.04 |
| small_doc | 1.45 | 1.46 |
| medium_doc | 1.54 | 1.96 |
| large_doc | 1.67 | 1.96 |
| deep_doc | 3.43 | 3.67 |
| array_doc | 0.97 | 1.04 |
| nested_array_doc | 1.76 | 1.83 |
| escaped_keys | 2.07 | 2.37 |
| unicode_doc | 2.53 | 2.58 |
| all_same_key | 1.89 | 2.0 |

**Grand mean:** rfc6901jsonpointer=1.48μs/call
