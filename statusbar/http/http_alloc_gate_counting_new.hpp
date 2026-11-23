#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// The counting replacement of the whole global operator new family, for the
/// allocation gates.
///
/// INCLUDE THIS FROM EXACTLY ONE TRANSLATION UNIT PER BINARY. It defines the
/// replaceable global allocation functions, and a program may hold one
/// definition of each. The unit test binary gets it from
/// http_alloc_gate_test.cpp, the functional test binary from
/// http_alloc_gate_functional_test.cpp.
///
/// Every replaceable form has to be here, not just the throwing ones. A test
/// binary links every module's tests, and anything in it that allocates
/// through the nothrow forms (libc++'s std::stable_sort temporary buffer, for
/// one) would otherwise get its memory from the runtime's operator new and
/// hand it to our malloc-based operator delete: an alloc-dealloc mismatch
/// under ASan.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

// ---- counting operator new family ------------------------------------------

namespace {
std::atomic<bool> g_alloc_armed{false};
std::atomic<uint64_t> g_alloc_count{0};

void count_allocation() noexcept
{
    if (g_alloc_armed.load(std::memory_order_relaxed)) {
        g_alloc_count.fetch_add(1, std::memory_order_relaxed);
    }
}

/// The nothrow forms' allocators: counted, nullptr on failure. The throwing
/// forms are these plus a std::bad_alloc.
auto counted_malloc(size_t size) noexcept -> void*
{
    count_allocation();
    return std::malloc(size == 0 ? 1 : size);
}

auto counted_aligned_malloc(size_t size, std::align_val_t alignment) noexcept -> void*
{
    count_allocation();
    void* p = nullptr;
    size_t const align = size_t(alignment) < sizeof(void*) ? sizeof(void*) : size_t(alignment);
    if (::posix_memalign(&p, align, size == 0 ? 1 : size) != 0) {
        return nullptr;
    }
    return p;
}
}  // namespace

// NOLINTBEGIN(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,readability-inconsistent-declaration-parameter-name)
auto operator new(size_t size) -> void*
{
    void* p = counted_malloc(size);
    if (p == nullptr) {
        throw std::bad_alloc{};
    }
    return p;
}

auto operator new[](size_t size) -> void*
{
    return ::operator new(size);
}

auto operator new(size_t size, std::align_val_t alignment) -> void*
{
    void* p = counted_aligned_malloc(size, alignment);
    if (p == nullptr) {
        throw std::bad_alloc{};
    }
    return p;
}

auto operator new[](size_t size, std::align_val_t alignment) -> void*
{
    return ::operator new(size, alignment);
}

auto operator new(size_t size, std::nothrow_t const&) noexcept -> void*
{
    return counted_malloc(size);
}
auto operator new[](size_t size, std::nothrow_t const&) noexcept -> void*
{
    return counted_malloc(size);
}
auto operator new(size_t size, std::align_val_t alignment, std::nothrow_t const&) noexcept -> void*
{
    return counted_aligned_malloc(size, alignment);
}
auto operator new[](size_t size, std::align_val_t alignment, std::nothrow_t const&) noexcept -> void*
{
    return counted_aligned_malloc(size, alignment);
}

void operator delete(void* p) noexcept
{
    std::free(p);
}
void operator delete[](void* p) noexcept
{
    std::free(p);
}
void operator delete(void* p, size_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, size_t) noexcept
{
    std::free(p);
}
void operator delete(void* p, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete(void* p, size_t, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete[](void* p, size_t, std::align_val_t) noexcept
{
    std::free(p);
}
void operator delete(void* p, std::nothrow_t const&) noexcept
{
    std::free(p);
}
void operator delete[](void* p, std::nothrow_t const&) noexcept
{
    std::free(p);
}
void operator delete(void* p, std::align_val_t, std::nothrow_t const&) noexcept
{
    std::free(p);
}
void operator delete[](void* p, std::align_val_t, std::nothrow_t const&) noexcept
{
    std::free(p);
}
// NOLINTEND(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory,readability-inconsistent-declaration-parameter-name)
