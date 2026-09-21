# statusbar-core documentation

The `statusbar-core` package is a set of foundational C++23 modules. Each
module is documented in its own overview file; pick a module to get a
two-minute orientation, then dive into its headers under
`statusbar/<module>/`.

## Module overviews

| Module       | Purpose                                                                             | Link                                       |
|--------------|-------------------------------------------------------------------------------------|--------------------------------------------|
| args         | Declarative CLI argument specification with type-safe binding and shell completion. | [ARGS_MODULE.md](ARGS_MODULE.md)           |
| benchmark    | Micro-benchmark harness with optimization barriers, two timer backends, and stats.  | [BENCHMARK_MODULE.md](BENCHMARK_MODULE.md) |
| bpf          | Raw Ethernet frame capture with kernel-side EtherType filtering via BpfDevice.      | [BPF_MODULE.md](BPF_MODULE.md)             |
| buffer       | Bounds-checked byte-buffer primitives, fluent (de)serializers, field descriptors.   | [BUFFER_MODULE.md](BUFFER_MODULE.md)       |
| colbin       | Append-only mmap-backed columnar binary file format for fixed-width row streams.    | [COLBIN_MODULE.md](COLBIN_MODULE.md)       |
| config       | Cascades TOML files with CLI overrides into typed argument bindings.                | [CONFIG_MODULE.md](CONFIG_MODULE.md)       |
| container    | Generic bounded, zero-heap containers used across protocol state machines.          | [CONTAINER_MODULE.md](CONTAINER_MODULE.md) |
| csv          | RFC 4180 CSV output primitives; generic, with no domain knowledge.                  | [CSV_MODULE.md](CSV_MODULE.md)             |
| ieee         | Network byte-order integer wrappers and IEEE 802 wire-format structs and constants. | [IEEE_MODULE.md](IEEE_MODULE.md)           |
| ip           | Wire-format structs and protocol constants for IPv4, IPv6, UDP, ARP, ICMP, IGMP.    | [IP_MODULE.md](IP_MODULE.md)               |
| itc          | Inter-thread primitives: typed sync, triple buffer, MessagePipe, stop signal.       | [ITC_MODULE.md](ITC_MODULE.md)             |
| net          | Non-blocking async TCP, UDP, and raw Ethernet on a poll()-driven reactor.           | [NET_MODULE.md](NET_MODULE.md)             |
| pcap         | Read/write support for Wireshark pcap/pcapng files plus synthetic-time replay.      | [PCAP_MODULE.md](PCAP_MODULE.md)           |
| realtime     | Hard-realtime utilities: memlock, SCHED_FIFO, affinity, deadline timers, tripwires. | [REALTIME_MODULE.md](REALTIME_MODULE.md)   |
| safe_arith   | Overflow-detecting integer arithmetic helpers wrapping the compiler builtins.       | [SAFE_ARITH_MODULE.md](SAFE_ARITH_MODULE.md)         |
| secure_random| Cryptographic-quality random byte generation (getrandom / arc4random_buf).          | [SECURE_RANDOM_MODULE.md](SECURE_RANDOM_MODULE.md)   |
| sm           | C++23 compile-time finite state machine framework with zero-overhead transitions.   | [SM_MODULE.md](SM_MODULE.md)               |
| stats        | Descriptive statistics, histograms, and lock-free atomic accumulators.              | [STATS_MODULE.md](STATS_MODULE.md)         |
| status       | Foundational error-handling primitive over `std::expected<T, std::error_code>`.     | [STATUS_MODULE.md](STATUS_MODULE.md)       |
| test         | Lightweight self-registering unit-test framework used by every statusbar module.    | [TEST_MODULE.md](TEST_MODULE.md)           |
| toml         | Pure TOML v1.0 parser paired with a typed `Value`/`Array`/`Table` tree.             | [TOML_MODULE.md](TOML_MODULE.md)           |
| tsn          | Time-Sensitive Networking wire-format identifiers (`ClockIdentity`, `StreamId`).    | [TSN_MODULE.md](TSN_MODULE.md)             |
| tui          | Minimal terminal-UI helper: raw mode, ANSI escapes, key reads, SIGWINCH resize.     | [TUI_MODULE.md](TUI_MODULE.md)             |

## Topic guides

In-depth references that go beyond the per-module overviews:

- [DESERIALIZER_GUIDE.md](DESERIALIZER_GUIDE.md) — comprehensive guide to the buffer module's compiled-deserializer API.
- [ERROR_HANDLING_EXAMPLES.md](ERROR_HANDLING_EXAMPLES.md) — patterns for using `Status` and `std::expected` across the codebase.
- [XDP_TCAM.md](XDP_TCAM.md) — design and migration plan for the net module's XDP packet classifier: moving the kernel-side filter to a TCAM interpreter that shares the userspace `CompiledRule` representation.

## Build system

- [BUILD_SYSTEM.md](BUILD_SYSTEM.md) — reference for the shared CMake scripts in `core/cmake/` (toolchain, `statusbar_add_module()`, sanitizers, coverage, fuzzing).
- [GCC_INLINE_ASM_MULTI_ALTERNATIVE_BUG.md](GCC_INLINE_ASM_MULTI_ALTERNATIVE_BUG.md) — GCC 16 wrong-code bug on read-write inline-asm operands with mixed `m`/`r` alternatives, why `do_not_optimize()` is spelled the way it is, and the reproducer.
