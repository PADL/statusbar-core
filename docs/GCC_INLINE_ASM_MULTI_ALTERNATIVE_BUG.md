# GCC miscompiles read-write inline-asm operands with mixed alternatives

**Status:** open upstream (no matching GCC Bugzilla entry found as of 2026-09-21)
**Found:** 2026-09-21, while porting the build to GCC 16 / C++26
**Affects:** `g++ (GCC) 16.2.1 20260819 (Red Hat 16.2.1-2)`, `aarch64-redhat-linux`
**Impact here:** `statusbar::benchmark::do_not_optimize()` — see
[`core/statusbar/benchmark/benchmark.hpp`](../statusbar/benchmark/benchmark.hpp)

## Summary

Given a read-write (`+`) inline-asm operand whose constraint offers *mixed*
memory and register alternatives (`"+m,r"`), GCC drops the store that
initialises the operand. The operand is read-write, so its incoming value is
live by definition; GCC nevertheless treats it as write-only and eliminates the
initialisation as a dead store. The asm then reads uninitialised stack memory.

This is a silent wrong-code bug: it compiles without any diagnostic.

## Reproducer

```cpp
#include <print>
struct Fail {};
template <class T> inline void dno(T& v) { asm volatile("" : "+m,r"(v) : : "memory"); }
static void runner() {
    int value = 42;
    dno(value);
    if (value != 42) { std::println("got {} want {}", value, 42); throw Fail(); }
}
int main() { try { runner(); std::println("OK"); } catch (Fail const&) { std::println("MISCOMPILED"); } }
```

```console
$ g++ -std=c++26 -O1 t.cpp -o t && ./t
got 581175392 want 42
MISCOMPILED
```

The garbage value is whatever happens to be in the stack slot, so it varies
between runs and between build configurations.

## Generated code

`runner()` at `-O1`, with the only difference being the constraint:

| `"+m"` (correct) | `"+m,r"` (miscompiled) |
| --- | --- |
| `mov w0, 42` | *(missing)* |
| `str w0, [sp, 28]` | *(missing)* |
| `ldr w0, [sp, 28]` | `ldr w0, [sp, 28]` |
| `cmp w0, 42` | `cmp w0, 42` |

The `mov`/`str` pair that materialises `value = 42` is simply absent, and the
`ldr` reads an uninitialised slot.

## Affected constraints

Tested with the reproducer above, GCC 16.2.1 aarch64:

| constraint | `-O0` | `-O1` | `-Os` | `-O2` | `-O3` |
| --- | --- | --- | --- | --- | --- |
| `"+m"`    | ok  | ok  | ok  | ok | ok |
| `"+r"`    | ok  | ok  | ok  | ok | ok |
| `"+rm"`   | ok  | ok  | ok  | ok | ok |
| `"+m,m"`  | ok  | ok  | ok  | ok | ok |
| `"+m,r"`  | ok  | **BAD** | **BAD** | ok | ok |
| `"+r,m"`  | rejected at compile time: `impossible constraint in 'asm'` |

Two points worth noting:

* `"+m,m"` is fine, so multiple alternatives are not broken in general — the
  bug needs alternatives that *mix* memory and register.
* `"+rm"` — one alternative accepting either — is fine. The bug is specific to
  the comma-separated multi-alternative form.

`-O2` and `-O3` happen to produce correct code for this reproducer, which makes
the bug easy to miss; in the larger original case (the benchmark test suite) it
reproduced at `-O2` as well. Whether a given frame miscompiles depends on
surrounding code, so the optimisation-level column above is not a reliable
guide — treat `"+m,r"` as unsafe at every level.

The failure also depends on surrounding code in ways that suggest a register
allocation / dead-store-elimination interaction: replacing `std::println` with
`printf` in the reproducer makes it compile correctly.

## Why the code looked like this

Clang wants `"+r,m"` for a `do_not_optimize`-style barrier, and that is what
upstream google/benchmark uses for clang. GCC rejects `"+r,m"` outright for any
type that cannot live in a register, so google/benchmark reverses the
alternatives to `"+m,r"` for GCC. That reversed form is the one this bug hits,
so the widely-copied google/benchmark idiom is affected on this compiler.

## Workaround

Use the single `"m"` alternative on GCC:

```cpp
#if defined(__clang__)
    asm volatile("" : "+r,m"(value) : : "memory");
#elif defined(__GNUC__)
    asm volatile("" : "+m"(value) : : "memory");
#endif
```

`"+m"` is always satisfiable, needs no alternative selection, and is the
stronger barrier: it forces the value to memory and marks it read-written.
`"+rm"` also avoids the bug and lets GCC keep the value in a register where it
can, which is less pessimistic; it is a reasonable alternative if the
forced-to-memory behaviour ever shows up in benchmark timings.

Only read-write operands are affected. The input-only const overload's `"r,m"`
is correct at every optimisation level and was left unchanged.

## Reproducing the original failure

With `"+m,r"` restored in `benchmark.hpp`, the aggregate test suite fails:

```console
$ ctest --preset gcc
99% tests passed, 2 tests failed out of 294
  80 - statusbar/benchmark/benchmark_test (Failed)
 280 - statusbar_all_test (Failed)
```

Six of the twenty benchmark tests fail. Besides the corrupted locals, a counter
incremented inside a benchmark loop reads back as `0` — so benchmark *results*
would be silently wrong, not merely the tests.

## Still to do

* Report upstream to GCC Bugzilla (component `target` or `rtl-optimization`).
* Re-check on a newer GCC before removing the workaround.
* Not yet checked on `x86_64` — this host is aarch64 only.
