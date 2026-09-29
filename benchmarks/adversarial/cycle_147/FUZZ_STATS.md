# cycle_147 / adversary / FUZZ_EXECUTE — Aggregation

> Per-surface fuzz statistics for rfc-6901-json-pointer-pure cycle_147.
> All four harnesses from `fuzz/<surface>/harness.py` executed with
> `--iter 500 --seed 42` (CLI: `--iter 100` per task spec). Reproducible.

## Summary

- **Total iterations:** 1,600 (parse_pointer 500 + evaluate 500 + unescape 500 + cli 100)
- **Total crashes:** 0
- **Total hangs:** 0
- **Total findings:** 0
- **Total wall-clock (sequential):** ~1.64 s
- **Verdict:** CLEAN — no security-relevant findings. Library passes pure-stdlib
  fuzz over all 4 instrumented surfaces.

## Per-surface table

| Surface       | Iterations | OK | Expected errors | Crashes | Hangs | Findings | Elapsed (s) | Notes                                                              |
|---------------|-----------:|---:|----------------:|--------:|------:|---------:|------------:|--------------------------------------------------------------------|
| parse_pointer |        500 | 195 |             305 |       0 |     0 |        0 |       0.108 | JSONPointer() constructor; pointer-string fuzz                     |
| evaluate      |        500 |  64 |             436 |       0 |     0 |        0 |       0.031 | .evaluate() with paired (doc, ptr); doc generator up to depth 8    |
| unescape      |        500 | 339 |             161 |       0 |     0 |        0 |       0.005 | _unescape_token() tilde-decoding core; over-weighted by design     |
| cli           |        100 |   6 |              94 |       0 |     0 |        0 |       1.497 | python -m rfc6901jsonpointer subprocess wrapper; 5 s per-input cap |
| **TOTAL**     | **1,600**  |604 |           **996** |   **0** | **0** |    **0** |   **1.641** |                                                                    |

## ASan / UBSan status

N/A — pure Python stdlib; no C extensions to instrument.

```
"asan": "disabled",
"ubsan": "disabled",
"reason": "pure-Python stdlib — no C extensions to instrument"
```

## Artefact layout

```
fuzz/
├── parse_pointer/
│   ├── harness.py
│   ├── stats.json              ← 500 iter, 0 crashes
│   ├── corpus/SEEDS.md
│   ├── crashes/                ← EMPTY
│   ├── hangs/                  ← EMPTY
│   └── logs/run.log
├── evaluate/
│   ├── harness.py
│   ├── stats.json              ← 500 iter, 0 crashes
│   ├── corpus/SEEDS.md
│   ├── crashes/                ← EMPTY
│   ├── hangs/                  ← EMPTY
│   └── logs/run.log
├── unescape/
│   ├── harness.py
│   ├── stats.json              ← 500 iter, 0 crashes
│   ├── corpus/SEEDS.md
│   ├── crashes/                ← EMPTY
│   ├── hangs/                  ← EMPTY
│   └── logs/run.log
└── cli/
    ├── harness.py
    ├── stats.json              ← 100 iter, 0 crashes
    ├── corpus/SEEDS.md
    ├── crashes/                ← EMPTY
    ├── hangs/                  ← EMPTY
    └── logs/run.log
```

## Reproduction

```bash
cd /root/projects/rfc-6901-json-pointer-pure/.worktrees/t_cycle147-adversary-01

for s in parse_pointer evaluate unescape; do
  ( cd fuzz/$s && python3 harness.py --iter 500 --seed 42 --quiet )
done

( cd fuzz/cli && python3 harness.py --iter 100 --seed 42 --quiet )
```

## Pytest regression after fuzz

```
$ python3 -m pytest -q
123 passed in 0.32s
```

No regression introduced by fuzzing harness imports — they only import
`rfc6901jsonpointer` from `src/`.

## Findings

None. Card 04 (triage) has nothing to do.

## Next card

Card 05 (`FUZZING_REPORT.md` author) should reference this aggregation file
alongside the per-surface `stats.json` snapshots.