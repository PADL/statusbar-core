[← back to module index](README.md)

# mem

Memory helpers that keep allocation and residency under the caller's
control: an allocator-aware `make_unique`, and a read-only file mapping
with page-range locking for real-time readers.

## Overview

`pmr_make_unique<T>(resource, ...)` is `std::make_unique` with the
storage taken from a caller-supplied `std::pmr::memory_resource` and
returned to that same resource on destruction; the deleter carries the
resource, so the `PmrUniquePtr` it returns is self-contained.

`MappedFile` maps a whole file read-only (`mmap` with `PROT_READ`,
`MAP_SHARED`) and lets a non-real-time thread keep a window of it
resident and locked while a real-time thread reads inside that window
without faulting. `lock_range()` locks and reads in the pages covering
a byte range, `unlock_range()` releases them, `advise()` tells the
kernel how the range will be read, and `page_span()` is the page
arithmetic the three share. Nothing is copied: `bytes()` is the file
as the kernel holds it. On Linux `advise()` is `madvise(2)`, not
`posix_madvise(3)`: glibc and musl answer `POSIX_MADV_DONTNEED` with 0
and no system call, so a window that advised `dont_need` behind itself
would keep every page it had passed; `MADV_DONTNEED` drops them. A
range still locked by `lock_range()` refuses `dont_need` (`EINVAL`).

Every `MappedFile` call is a system call and belongs on a non-real-time
thread. The real-time thread only reads `bytes()`, and only where a
`lock_range()` is in force.

## Key types

- `MappedFile` — move-only; `map(fd)` and `open(dir_fd, path)` return
  `StatusValue<MappedFile>`; `bytes()`, `size()`, `valid()`;
  `lock_range()`, `unlock_range()`, `advise()`, `page_span()`;
  `page_size()`. Errors are the `errno` as `Status`. A zero-length file
  is a valid, empty mapping.
- `MappedFile::Advice` — `normal`, `sequential`, `random`, `will_need`,
  `dont_need`.
- `PmrDeleter<T>`, `PmrUniquePtr<T>`, `pmr_make_unique<T>()` — the
  allocator-aware `unique_ptr`.

## Quick example

```cpp
#include "statusbar/mem/mem_mapped_file.hpp"

#include <fcntl.h>

using namespace statusbar;

// Control thread: map once, then keep a window locked ahead of the reader.
auto mapped = mem::MappedFile::open(AT_FDCWD, "capture.wav");
if (!mapped) {
    return 1;
}
size_t const window = mem::MappedFile::page_size() * 64;
if (auto st = mapped->lock_range(0, window); !st) {
    return 1;  // ENOMEM: RLIMIT_MEMLOCK is too small for the window
}
(void)mapped->advise(window, mapped->size() - window, mem::MappedFile::Advice::sequential);

// Real-time thread: read inside the locked window only.
std::span<uint8_t const> const bytes = mapped->bytes();
// ... bytes.subspan(offset, n) for offset + n <= window ...

// Control thread, as the reader advances: lock the next window, unlock the last.
(void)mapped->lock_range(window, window);
(void)mapped->unlock_range(0, window);
```

## Headers

- `mem_mapped_file.hpp` — `MappedFile`.
- `mem_pmr_unique.hpp` — `PmrDeleter`, `PmrUniquePtr`, `pmr_make_unique`.

## Dependencies

- `statusbar::status` — `Status`, `StatusValue`.
- POSIX: `mmap`, `munmap`, `mlock`, `munlock`, `openat`, `fstat`,
  `sysconf`; `madvise(2)` on Linux, `posix_madvise` elsewhere.

## Notes & caveats

- **Timers lock everything.** A `realtime::Timer` calls
  `mlockall(MCL_CURRENT)` when its thread starts unless
  `TimerConfig::lock_memory` is false. That takes in the whole mapping
  and overrides the window; a process that uses `MappedFile` turns it
  off and locks once at startup with `realtime::lock_memory()`.
  `lock_memory(true)` locks later mappings as their pages fault in, so a
  `MappedFile` mapped after it is not read in whole either.
- **Limits.** `mlock` is bounded by `RLIMIT_MEMLOCK` (or needs
  `CAP_IPC_LOCK`); a window that does not fit fails with `ENOMEM`.
- **Ranges are pages.** Every range is widened to the pages that hold
  it and clipped to the file; `page_span()` shows the result. A range
  past the end, or an empty one, is a successful no-op.
- **MAP_SHARED, read-only.** The mapping sees the file as the kernel
  holds it, within the size at the time of the map. Only regular files
  map; anything else is `invalid_argument`.
- **Descriptor.** Neither `map()` nor `open()` keeps the descriptor;
  `open()` closes its own, `map()` leaves the caller's for the caller.

## Further reading

- [REALTIME_MODULE.md](REALTIME_MODULE.md) — `TimerConfig::lock_memory`
  and process-wide locking.
