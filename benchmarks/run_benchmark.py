#!/usr/bin/env python3
"""Benchmark: rfc6901jsonpointer vs json_pointer (stefankoegl).

Environment: Linux 6.12.67-linuxkit, Python 3.11.15
Methodology: time.perf_counter(), 5 iterations per workload, median result.
"""

import time
import statistics

try:
    from rfc6901jsonpointer import JSONPointer
    OUR_IMPL = "rfc6901jsonpointer"
except ImportError:
    print("SKIP: rfc6901jsonpointer not installed")
    exit(0)

try:
    from json_pointer import JsonPointer
    COMPETITOR_IMPL = "json_pointer (stefankoegl)"
except ImportError:
    COMPETITOR_IMPL = None
    print("NOTE: json_pointer not available; single-impl benchmark only")


def make_doc(depth=3, width=4):
    if depth == 0:
        return "value"
    return {f"k{i}": make_doc(depth - 1, width) for i in range(width)}


all_same_doc = {}
for i in range(10):
    all_same_doc[f"k{i}"] = {f"k{i}": {f"k{i}": i}}


WORKLOADS = [
    # depth=1 → single level dict; pointers only 1 level deep
    ("tiny_doc", make_doc(1, 2), ["/k0", "/k1"]),
    # depth=2 → 2-level dict
    ("small_doc", make_doc(2, 3), ["/k0/k1", "/k1/k2"]),
    # depth=3 → 3-level dict
    ("medium_doc", make_doc(3, 4), ["/k0/k0/k0", "/k1/k2", "/k2/k3"]),
    # depth=4 → 4-level dict
    ("large_doc", make_doc(4, 5), ["/k0/k0/k0", "/k1/k2", "/k3/k4", "/k2/k1/k3"]),
    # depth=6 → 6-level dict
    ("deep_doc", make_doc(6, 2), ["/" + "/".join(["k0"] * 6)]),
    ("array_doc", list(range(100)), [f"/{i}" for i in range(0, 100, 10)]),
    ("nested_array_doc", [[[j for j in range(5)] for _ in range(5)] for _ in range(5)],
        ["/0/0/0", "/2/3/4", "/4/4/4"]),
    ("escaped_keys", {"a/b": {"c~d": "found"}}, ["/a~1b/c~0d"]),
    ("unicode_doc", {"Japanese": {"emoji": "OK"}}, ["/Japanese/emoji"]),
    ("all_same_key", all_same_doc, ["/k0/k0/k0", "/k5/k5/k5"]),
]

ITERATIONS = 50


def benchmark_calls(eval_fn, doc, pointers, iterations=50):
    times = []
    for _ in range(iterations):
        for ptr_str in pointers:
            t0 = time.perf_counter()
            eval_fn(doc, ptr_str)
            times.append(time.perf_counter() - t0)
    return times


def our_eval(doc, ptr_str):
    return JSONPointer(ptr_str).evaluate(doc)


def run():
    print(f"rfc6901jsonpointer benchmark — {ITERATIONS} iterations x workload")
    print(f"Competitor: {COMPETITOR_IMPL or 'none (single-impl baseline)'}")
    print()

    results = []
    our_all_times = []
    comp_all_times = []

    for name, doc, ptrs in WORKLOADS:
        our_times = benchmark_calls(our_eval, doc, ptrs, ITERATIONS)
        our_mean = statistics.mean(our_times) * 1e6
        our_p95 = sorted(our_times)[int(len(our_times) * 0.95)] * 1e6
        our_all_times.extend(our_times)

        row = {
            "workload": name,
            "our_mean": round(our_mean, 2),
            "our_p95": round(our_p95, 2),
            "comp_mean": None,
            "comp_p95": None,
            "ratio": "—",
        }

        if COMPETITOR_IMPL:
            def comp_eval(d, p):
                return JsonPointer(p).evaluate(d)
            comp_times = benchmark_calls(comp_eval, doc, ptrs, ITERATIONS)
            comp_mean = statistics.mean(comp_times) * 1e6
            comp_p95 = sorted(comp_times)[int(len(comp_times) * 0.95)] * 1e6
            comp_all_times.extend(comp_times)
            row["comp_mean"] = round(comp_mean, 2)
            row["comp_p95"] = round(comp_p95, 2)
            row["ratio"] = f"{comp_mean / our_mean:.2f}x"

        results.append(row)
        comp_str = f"  comp={row['comp_mean']}μs" if row["comp_mean"] else ""
        print(f"  {name:25s}  ours={our_mean:7.2f}μs{comp_str}  ratio={row['ratio']}")

    our_grand = statistics.mean(our_all_times) * 1e6
    print()
    print(f"Grand mean: {our_grand:.2f}μs/call")
    if COMPETITOR_IMPL:
        comp_grand = statistics.mean(comp_all_times) * 1e6
        print(f"Competitor grand mean: {comp_grand:.2f}μs/call")
        print(f"Competitor vs ours: {comp_grand/our_grand:.2f}x")

    write_benchmark_md(results, our_grand, comp_all_times if COMPETITOR_IMPL else None)
    print("\nBENCHMARK.md written.")


def write_benchmark_md(results, our_grand, comp_all_times):
    competitor_name = "json_pointer" if COMPETITOR_IMPL else None
    lines = [
        "# Benchmark: rfc6901jsonpointer\n\n",
        "**Environment:** Linux 6.12.67-linuxkit, Python 3.11.15\n",
        f"**Methodology:** 50 iterations x workload, mean + P95 in μs.\n\n",
        "| Workload | rfc6901jsonpointer (mean μs) | rfc6901jsonpointer (P95 μs) | ",
        (f"{competitor_name} (mean μs) | {competitor_name} (P95 μs) | " if competitor_name else ""),
        "Ratio |\n",
        "|----------|-------------------------------|--------------------------------|",
        (f"--------------------------------|-----------------------------------|" if competitor_name else ""),
        "-------|\n",
    ]
    for r in results:
        cm = str(r["comp_mean"]) if r["comp_mean"] else "—"
        cp = str(r["comp_p95"]) if r["comp_p95"] else "—"
        lines.append(
            f"| {r['workload']} | {r['our_mean']} | {r['our_p95']} "
            + (f"| {cm} | {cp} | {r['ratio']} " if r["comp_mean"] else "")
            + "|\n"
        )
    if comp_all_times is not None:
        comp_grand = statistics.mean(comp_all_times) * 1e6
        lines.append(
            f"\n**Grand mean:** rfc6901jsonpointer={our_grand:.2f}μs | "
            f"{competitor_name}={comp_grand:.2f}μs "
            f"(ratio={comp_grand/our_grand:.2f}x)\n"
        )
    else:
        lines.append(f"\n**Grand mean:** rfc6901jsonpointer={our_grand:.2f}μs/call\n")

    with open("BENCHMARK.md", "w") as f:
        f.writelines(lines)


if __name__ == "__main__":
    run()
