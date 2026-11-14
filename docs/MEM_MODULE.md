[← back to module index](README.md)

# mem

Memory helpers: an allocator-aware `make_unique` (`pmr_make_unique`) and a
read-only file mapping with page-range locking (`MappedFile`).

## Overview

`pmr_make_unique<T>(resource, ...)` constructs an object in storage from a
caller-supplied `std::pmr::memory_resource` and returns a `PmrUniquePtr<T>`
whose deleter returns it to that resource.

`MappedFile` maps a whole file read-only and shared. A reader of a large file
keeps only a window of it resident: `lock_range()` mlocks the pages covering a
byte range (populating them), `unlock_range()` releases them, and `advise()`
tells the kernel the access pattern. A thread that reads only inside a locked
range never faults on a page, so a real-time thread can read file bytes that
a non-real-time thread keeps locked ahead of it.

## Key types

- `PmrDeleter<T>`, `PmrUniquePtr<T>`, `pmr_make_unique<T>()` — allocator-aware ownership.
- `MappedFile` — move-only read-only mapping: `map(fd)`, `open(dir_fd, path)`,
  `bytes()`, `size()`, `lock_range()`, `unlock_range()`, `advise()`, `page_size()`.
- `MapAdvice` — `normal`, `sequential`, `random`, `will_need`, `dont_need` (posix_madvise(3)).

## Quick example

```cpp
#include "statusbar/mem/mem_mapped_file.hpp"

#include <fcntl.h>

auto mapped = statusbar::mem::MappedFile::open(AT_FDCWD, "intro.wav");
if (!mapped) {
    return statusbar::forward_failure(mapped);
}
(void)mapped->advise(statusbar::mem::MapAdvice::sequential);
if (auto locked = mapped->lock_range(0, 2 * 1024 * 1024); !locked) {
    return locked;  // EPERM or ENOMEM: RLIMIT_MEMLOCK
}
auto const bytes = mapped->bytes();  // the first 2 MiB are resident
```

## Headers

- `statusbar/mem/mem_pmr_unique.hpp` — header-only.
- `statusbar/mem/mem_mapped_file.hpp` — implemented in `mem_mapped_file.cpp`
  (link `statusbar::mem`).

## Dependencies

- **Statusbar modules:** `status`.
- **System / external:** POSIX `mmap(2)`, `mlock(2)`, `munlock(2)`,
  `posix_madvise(3)`, `openat(2)`, `fstat(2)` (Linux and Darwin).

## Notes & caveats

- **Locked pages count against `RLIMIT_MEMLOCK`.** A lock past the limit
  fails with `EPERM` or `ENOMEM`; a daemon raises the limit (systemd
  `LimitMEMLOCK=`). `mlockall(MCL_CURRENT)` before the mapping does not lock it.
- **Ranges are rounded to pages.** Locks are not counted: one `unlock_range()`
  unlocks every page it covers, including pages another locked range shares.
- **The file is mapped at its size when opened.** A file truncated under a
  mapping raises `SIGBUS` on a read past its new end; replace files by
  renaming a new one over the path instead, which leaves the mapping on the
  old inode.
- **One owner thread.** The object is not synchronised; another thread may
  read `bytes()` inside a range the owner keeps locked.
- Every call is a system call: keep them off real-time threads.

## Further reading

- mmap(2), mlock(2), posix_madvise(3).
- [REALTIME_MODULE.md](REALTIME_MODULE.md) — `lock_memory` (mlockall) for a process's own memory.
