#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// FlatTrie — a zero-heap trie over caller-provided flat memory, in two
/// phases:
///
/// `FlatTrieBuilder<Key, Leaf>` is the mutable phase. It carves its node
/// and edge arrays out of one caller-provided byte span (stack, static,
/// heap, or mmap-backed — the builder itself never allocates), with the
/// maximum node/edge counts fixed at init time. Insertion keeps each
/// node's children as an intrusive singly-linked list, so an insert is
/// O(children) with no reshuffling; `find`/`match` on the builder walk
/// the same lists linearly.
///
/// `write_image` serializes the builder into the canonical read-only
/// image: a self-describing, offset-based CSR layout (header, per-node
/// child ranges, keys sorted within each range, leaves, and a
/// leaf-presence bitmap). The image contains no pointers and no
/// endianness translation — it is host-native, and the header's magic,
/// version, and key/leaf geometry fields let `FlatTrieView::attach`
/// reject foreign images. Persist it, mmap it back, and attach.
///
/// `FlatTrieView<Key, Leaf>` is the immutable phase: it borrows an image
/// (alignment `image_align`), validates its structure once at attach,
/// and serves `find` (binary search per node) and `match`. `match` takes
/// a span of matcher segments satisfying `TrieMatcher`: a literal
/// matcher is one binary search, a non-literal matcher branches over a
/// node's children filtered by `matches(key)`.
///
/// Key and Leaf must be trivially copyable with alignment <= 8. Node 0
/// is always the root; an empty builder is one root node with no leaf.

#include <algorithm>
#include <bit>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

namespace statusbar::container {

/// One compiled pattern segment for FlatTrieView::match /
/// FlatTrieBuilder::match: either an exact key (`is_literal()` true,
/// compared via `literal_key()`), or a predicate over a node's child
/// keys (`matches`, only consulted when not literal).
template <typename M, typename Key>
concept TrieMatcher = requires(M const m, Key k) {
    { m.is_literal() } -> std::convertible_to<bool>;
    { m.literal_key() } -> std::convertible_to<Key>;
    { m.matches(k) } -> std::convertible_to<bool>;
};

namespace flat_trie_detail {

constexpr auto align_up(size_t at, size_t alignment) noexcept -> size_t
{
    return (at + alignment - 1) & ~(alignment - 1);
}

constexpr uint32_t NO_INDEX = 0xffffffffU;

/// Image header. Geometry fields (sizes and alignments of Key and Leaf)
/// make attach reject an image written by a differently-typed trie.
struct ImageHeader
{
    uint32_t magic;
    uint16_t version;
    uint16_t reserved0;
    uint32_t node_count;
    uint32_t edge_count;
    uint8_t key_size;
    uint8_t key_align;
    uint8_t leaf_size;
    uint8_t leaf_align;
    uint32_t reserved1;
};
static_assert(sizeof(ImageHeader) == 24);

constexpr uint32_t IMAGE_MAGIC = 0x46545249U;  // "FTRI"
constexpr uint16_t IMAGE_VERSION = 1;

constexpr auto present_words(size_t nodes) noexcept -> size_t
{
    return (nodes + 63) / 64;
}

/// The one byte<->object boundary: every array lives at a computed offset
/// inside caller storage or a mapped image, so this is the container's
/// equivalent of a mmap frame cast.
template <typename T>
auto at_offset(std::byte* base, size_t offset) noexcept -> T*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<T*>(base + offset);
}

template <typename T>
auto at_offset(std::byte const* base, size_t offset) noexcept -> T const*
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<T const*>(base + offset);
}

}  // namespace flat_trie_detail

/// Image field offsets for a FlatTrie<Key, Leaf> with the given counts.
/// Layout: header, kids_begin[node_count + 1] (CSR prefix into the edge
/// arrays), leaf-presence bitmap, edge keys (sorted within each node's
/// range), edge children, node leaves.
template <typename Key, typename Leaf>
struct FlatTrieImageLayout
{
    static_assert(std::is_trivially_copyable_v<Key> && alignof(Key) <= 8);
    static_assert(std::is_trivially_copyable_v<Leaf> && alignof(Leaf) <= 8);

    static constexpr size_t image_align = 8;

    size_t kids_begin;
    size_t present;
    size_t edge_key;
    size_t edge_child;
    size_t node_leaf;
    size_t total;

    constexpr FlatTrieImageLayout(size_t node_count, size_t edge_count) noexcept
    {
        using namespace flat_trie_detail;
        size_t at = sizeof(ImageHeader);
        kids_begin = at;
        at += (node_count + 1) * sizeof(uint32_t);
        at = align_up(at, alignof(uint64_t));
        present = at;
        at += present_words(node_count) * sizeof(uint64_t);
        at = align_up(at, alignof(Key));
        edge_key = at;
        at += edge_count * sizeof(Key);
        edge_child = at;
        at += edge_count * sizeof(uint32_t);
        at = align_up(at, alignof(Leaf));
        node_leaf = at;
        at += node_count * sizeof(Leaf);
        total = at;
    }
};

template <typename Key, typename Leaf>
class FlatTrieBuilder
{
    static_assert(std::is_trivially_copyable_v<Key> && alignof(Key) <= 8);
    static_assert(std::is_trivially_copyable_v<Leaf> && alignof(Leaf) <= 8);

  public:
    enum class Insert : uint8_t
    {
        ok,
        exists,  ///< the exact key sequence already has a leaf
        full,    ///< out of node or edge capacity — relocate to grow
    };

    /// Required alignment of the storage span's first byte.
    static constexpr size_t storage_align = 8;

    /// Bytes of storage needed for the given capacities.
    static constexpr auto storage_size(size_t max_nodes, size_t max_edges) noexcept -> size_t
    {
        return layout(max_nodes, max_edges).total;
    }

    /// An empty builder over no storage: zero capacity, only useful as a
    /// moved-from or placeholder state.
    FlatTrieBuilder() noexcept = default;

    /// Carves the arrays out of `storage` (which must be at least
    /// storage_size(max_nodes, max_edges) bytes, aligned to
    /// storage_align) and initializes the root. max_nodes must be >= 1.
    /// The builder borrows the storage; the caller keeps it alive.
    FlatTrieBuilder(std::span<std::byte> storage, size_t max_nodes, size_t max_edges) noexcept
    {
        assert(max_nodes >= 1 && max_nodes < flat_trie_detail::NO_INDEX);
        assert(max_edges < flat_trie_detail::NO_INDEX);
        assert(storage.size() >= storage_size(max_nodes, max_edges));
        assert((std::bit_cast<uintptr_t>(storage.data()) % storage_align) == 0);
        max_nodes_ = uint32_t(max_nodes);
        max_edges_ = uint32_t(max_edges);
        auto const at = layout(max_nodes, max_edges);
        using flat_trie_detail::at_offset;
        auto* base = storage.data();
        edge_key_ = at_offset<Key>(base, at.edge_key);
        node_leaf_ = at_offset<Leaf>(base, at.node_leaf);
        present_ = at_offset<uint64_t>(base, at.present);
        node_head_ = at_offset<uint32_t>(base, at.node_head);
        edge_child_ = at_offset<uint32_t>(base, at.edge_child);
        edge_next_ = at_offset<uint32_t>(base, at.edge_next);
        node_count_ = 0;
        edge_count_ = 0;
        new_node();  // the root
    }

    /// Same, but seeded with the contents of `from` (which must fit the
    /// new capacities) — the relocation path for growing a trie.
    FlatTrieBuilder(std::span<std::byte> storage, size_t max_nodes, size_t max_edges, FlatTrieBuilder const& from) noexcept
        : FlatTrieBuilder(storage, max_nodes, max_edges)
    {
        assert(from.node_count_ <= max_nodes && from.edge_count_ <= max_edges);
        node_count_ = from.node_count_;
        edge_count_ = from.edge_count_;
        std::memcpy(edge_key_, from.edge_key_, edge_count_ * sizeof(Key));
        std::memcpy(node_leaf_, from.node_leaf_, node_count_ * sizeof(Leaf));
        std::memcpy(present_, from.present_, flat_trie_detail::present_words(node_count_) * sizeof(uint64_t));
        std::memcpy(node_head_, from.node_head_, node_count_ * sizeof(uint32_t));
        std::memcpy(edge_child_, from.edge_child_, edge_count_ * sizeof(uint32_t));
        std::memcpy(edge_next_, from.edge_next_, edge_count_ * sizeof(uint32_t));
    }

    [[nodiscard]] auto node_count() const noexcept -> size_t { return node_count_; }
    [[nodiscard]] auto edge_count() const noexcept -> size_t { return edge_count_; }
    [[nodiscard]] auto max_nodes() const noexcept -> size_t { return max_nodes_; }
    [[nodiscard]] auto max_edges() const noexcept -> size_t { return max_edges_; }

    /// Maps the key sequence to a leaf. `exists` when the exact sequence
    /// already has one (first mapping wins); `full` (with the trie
    /// untouched) when finishing the insert could exceed a capacity.
    [[nodiscard]] auto insert(std::span<Key const> keys, Leaf leaf) noexcept -> Insert
    {
        uint32_t node = 0;
        size_t depth = 0;
        while (depth < keys.size()) {
            auto const kid = child_of(node, keys[depth]);
            if (kid == flat_trie_detail::NO_INDEX) {
                break;
            }
            node = kid;
            ++depth;
        }
        auto const missing = keys.size() - depth;
        if (node_count_ + missing > max_nodes_ || edge_count_ + missing > max_edges_) {
            return Insert::full;
        }
        if (missing == 0 && has_leaf(node)) {
            return Insert::exists;
        }
        for (; depth < keys.size(); ++depth) {
            auto const kid = new_node();
            edge_key_[edge_count_] = keys[depth];
            edge_child_[edge_count_] = kid;
            edge_next_[edge_count_] = node_head_[node];
            node_head_[node] = edge_count_;
            ++edge_count_;
            node = kid;
        }
        node_leaf_[node] = leaf;
        present_[node / 64] |= uint64_t(1) << (node % 64);
        return Insert::ok;
    }

    [[nodiscard]] auto find(std::span<Key const> keys) const noexcept -> std::optional<Leaf>
    {
        uint32_t node = 0;
        for (auto const& key : keys) {
            node = child_of(node, key);
            if (node == flat_trie_detail::NO_INDEX) {
                return std::nullopt;
            }
        }
        if (!has_leaf(node)) {
            return std::nullopt;
        }
        return node_leaf_[node];
    }

    /// Visits the leaf of every key sequence matching the pattern at
    /// exact depth (linear child walks — build-time convenience; the
    /// image view is the fast path).
    template <typename Matcher, typename Visit>
        requires TrieMatcher<Matcher, Key>
    void match(std::span<Matcher const> pattern, Visit visit) const
    {
        match_at(0, pattern, 0, visit);
    }

    /// Bytes write_image needs for the current contents.
    [[nodiscard]] auto image_size() const noexcept -> size_t
    {
        return FlatTrieImageLayout<Key, Leaf>(node_count_, edge_count_).total;
    }

    /// Serializes into the canonical read-only image (see
    /// FlatTrieImageLayout). `out` must be at least image_size() bytes,
    /// aligned to FlatTrieImageLayout::image_align. Returns the bytes
    /// written, 0 when `out` is too small or misaligned.
    [[nodiscard]] auto write_image(std::span<std::byte> out) const noexcept -> size_t
    {
        using namespace flat_trie_detail;
        using flat_trie_detail::at_offset;
        FlatTrieImageLayout<Key, Leaf> const at(node_count_, edge_count_);
        if (out.size() < at.total || (std::bit_cast<uintptr_t>(out.data()) % FlatTrieImageLayout<Key, Leaf>::image_align) != 0) {
            return 0;
        }
        auto* base = out.data();
        auto* header = at_offset<ImageHeader>(base, 0);
        *header = ImageHeader{
            .magic = IMAGE_MAGIC,
            .version = IMAGE_VERSION,
            .reserved0 = 0,
            .node_count = node_count_,
            .edge_count = edge_count_,
            .key_size = uint8_t(sizeof(Key)),
            .key_align = uint8_t(alignof(Key)),
            .leaf_size = uint8_t(sizeof(Leaf)),
            .leaf_align = uint8_t(alignof(Leaf)),
            .reserved1 = 0,
        };
        auto* kids_begin = at_offset<uint32_t>(base, at.kids_begin);
        auto* out_key = at_offset<Key>(base, at.edge_key);
        auto* out_child = at_offset<uint32_t>(base, at.edge_child);

        // CSR prefix from per-node child counts, then per-node scatter —
        // a node's edges come only from its own list, so each range fills
        // independently, then sorts by key (tandem insertion sort: the
        // fanout is small and this must not allocate).
        kids_begin[0] = 0;
        for (uint32_t n = 0; n < node_count_; ++n) {
            uint32_t count = 0;
            for (auto e = node_head_[n]; e != NO_INDEX; e = edge_next_[e]) {
                ++count;
            }
            kids_begin[n + 1] = kids_begin[n] + count;
        }
        for (uint32_t n = 0; n < node_count_; ++n) {
            auto cursor = kids_begin[n];
            for (auto e = node_head_[n]; e != NO_INDEX; e = edge_next_[e], ++cursor) {
                out_key[cursor] = edge_key_[e];
                out_child[cursor] = edge_child_[e];
            }
            for (auto i = kids_begin[n] + 1; i < kids_begin[n + 1]; ++i) {
                auto key = out_key[i];
                auto child = out_child[i];
                auto j = i;
                for (; j > kids_begin[n] && key < out_key[j - 1]; --j) {
                    out_key[j] = out_key[j - 1];
                    out_child[j] = out_child[j - 1];
                }
                out_key[j] = key;
                out_child[j] = child;
            }
        }
        std::memcpy(base + at.present, present_, present_words(node_count_) * sizeof(uint64_t));
        std::memcpy(base + at.node_leaf, node_leaf_, node_count_ * sizeof(Leaf));
        return at.total;
    }

  private:
    static constexpr auto layout(size_t max_nodes, size_t max_edges) noexcept
    {
        using namespace flat_trie_detail;
        struct At
        {
            size_t edge_key, node_leaf, present, node_head, edge_child, edge_next, total;
        };
        At at{};
        size_t sz = 0;
        at.edge_key = sz;
        sz += max_edges * sizeof(Key);
        sz = align_up(sz, alignof(Leaf));
        at.node_leaf = sz;
        sz += max_nodes * sizeof(Leaf);
        sz = align_up(sz, alignof(uint64_t));
        at.present = sz;
        sz += present_words(max_nodes) * sizeof(uint64_t);
        at.node_head = sz;
        sz += max_nodes * sizeof(uint32_t);
        at.edge_child = sz;
        sz += max_edges * sizeof(uint32_t);
        at.edge_next = sz;
        sz += max_edges * sizeof(uint32_t);
        at.total = sz;
        return at;
    }

    auto new_node() noexcept -> uint32_t
    {
        auto const n = node_count_++;
        node_head_[n] = flat_trie_detail::NO_INDEX;
        present_[n / 64] &= ~(uint64_t(1) << (n % 64));
        return n;
    }

    [[nodiscard]] auto has_leaf(uint32_t node) const noexcept -> bool { return (present_[node / 64] >> (node % 64)) & 1; }

    [[nodiscard]] auto child_of(uint32_t node, Key const& key) const noexcept -> uint32_t
    {
        for (auto e = node_head_[node]; e != flat_trie_detail::NO_INDEX; e = edge_next_[e]) {
            if (edge_key_[e] == key) {
                return edge_child_[e];
            }
        }
        return flat_trie_detail::NO_INDEX;
    }

    template <typename Matcher, typename Visit>
    void match_at(uint32_t node, std::span<Matcher const> pattern, size_t depth, Visit& visit) const
    {
        if (depth == pattern.size()) {
            if (has_leaf(node)) {
                visit(node_leaf_[node]);
            }
            return;
        }
        auto const& seg = pattern[depth];
        if (seg.is_literal()) {
            auto const kid = child_of(node, Key(seg.literal_key()));
            if (kid != flat_trie_detail::NO_INDEX) {
                match_at(kid, pattern, depth + 1, visit);
            }
            return;
        }
        for (auto e = node_head_[node]; e != flat_trie_detail::NO_INDEX; e = edge_next_[e]) {
            if (seg.matches(edge_key_[e])) {
                match_at(edge_child_[e], pattern, depth + 1, visit);
            }
        }
    }

    Key* edge_key_ = nullptr;
    Leaf* node_leaf_ = nullptr;
    uint64_t* present_ = nullptr;
    uint32_t* node_head_ = nullptr;
    uint32_t* edge_child_ = nullptr;
    uint32_t* edge_next_ = nullptr;
    uint32_t node_count_ = 0;
    uint32_t edge_count_ = 0;
    uint32_t max_nodes_ = 0;
    uint32_t max_edges_ = 0;
};

template <typename Key, typename Leaf>
class FlatTrieView
{
    static_assert(std::is_trivially_copyable_v<Key> && alignof(Key) <= 8);
    static_assert(std::is_trivially_copyable_v<Leaf> && alignof(Leaf) <= 8);

  public:
    static constexpr size_t image_align = FlatTrieImageLayout<Key, Leaf>::image_align;

    /// Borrows and structurally validates an image (magic, version,
    /// key/leaf geometry, in-bounds and root-free child indices, per-node
    /// strictly-sorted keys). nullopt when anything is off — a view never
    /// serves an invalid image. The caller keeps the bytes alive and
    /// unchanged (an mmap-ed image must be a private/read-only mapping).
    [[nodiscard]] static auto attach(std::span<std::byte const> image) noexcept -> std::optional<FlatTrieView>
    {
        using namespace flat_trie_detail;
        if (image.size() < sizeof(ImageHeader) || (std::bit_cast<uintptr_t>(image.data()) % image_align) != 0) {
            return std::nullopt;
        }
        ImageHeader header{};
        std::memcpy(&header, image.data(), sizeof header);
        if (header.magic != IMAGE_MAGIC || header.version != IMAGE_VERSION || header.node_count == 0 ||
            header.key_size != sizeof(Key) || header.key_align != alignof(Key) || header.leaf_size != sizeof(Leaf) ||
            header.leaf_align != alignof(Leaf)) {
            return std::nullopt;
        }
        FlatTrieImageLayout<Key, Leaf> const at(header.node_count, header.edge_count);
        if (image.size() < at.total) {
            return std::nullopt;
        }
        using flat_trie_detail::at_offset;
        FlatTrieView view;
        auto const* base = image.data();
        view.node_count_ = header.node_count;
        view.edge_count_ = header.edge_count;
        view.kids_begin_ = at_offset<uint32_t>(base, at.kids_begin);
        view.present_ = at_offset<uint64_t>(base, at.present);
        view.edge_key_ = at_offset<Key>(base, at.edge_key);
        view.edge_child_ = at_offset<uint32_t>(base, at.edge_child);
        view.node_leaf_ = at_offset<Leaf>(base, at.node_leaf);
        if (view.kids_begin_[0] != 0 || view.kids_begin_[view.node_count_] != view.edge_count_) {
            return std::nullopt;
        }
        for (uint32_t n = 0; n < view.node_count_; ++n) {
            if (view.kids_begin_[n] > view.kids_begin_[n + 1]) {
                return std::nullopt;
            }
            for (auto i = view.kids_begin_[n]; i < view.kids_begin_[n + 1]; ++i) {
                if (view.edge_child_[i] == 0 || view.edge_child_[i] >= view.node_count_) {
                    return std::nullopt;  // a child is never the root
                }
                if (i > view.kids_begin_[n] && !(view.edge_key_[i - 1] < view.edge_key_[i])) {
                    return std::nullopt;  // keys strictly sorted per node
                }
            }
        }
        return view;
    }

    /// A detached view: valid() false, resolves nothing, matches nothing.
    FlatTrieView() noexcept = default;

    [[nodiscard]] auto valid() const noexcept -> bool { return node_count_ != 0; }
    [[nodiscard]] auto node_count() const noexcept -> size_t { return node_count_; }
    [[nodiscard]] auto edge_count() const noexcept -> size_t { return edge_count_; }

    [[nodiscard]] auto find(std::span<Key const> keys) const noexcept -> std::optional<Leaf>
    {
        if (!valid()) {
            return std::nullopt;
        }
        uint32_t node = 0;
        for (auto const& key : keys) {
            node = child_of(node, key);
            if (node == flat_trie_detail::NO_INDEX) {
                return std::nullopt;
            }
        }
        if (!has_leaf(node)) {
            return std::nullopt;
        }
        return node_leaf_[node];
    }

    /// Visits the leaf of every key sequence matching the pattern at
    /// exact depth. Literal matchers are one binary search; non-literal
    /// matchers branch over the node's children filtered by matches().
    template <typename Matcher, typename Visit>
        requires TrieMatcher<Matcher, Key>
    void match(std::span<Matcher const> pattern, Visit visit) const
    {
        if (valid()) {
            match_at(0, pattern, 0, visit);
        }
    }

  private:
    [[nodiscard]] auto has_leaf(uint32_t node) const noexcept -> bool { return (present_[node / 64] >> (node % 64)) & 1; }

    [[nodiscard]] auto child_of(uint32_t node, Key const& key) const noexcept -> uint32_t
    {
        auto const* first = edge_key_ + kids_begin_[node];
        auto const* last = edge_key_ + kids_begin_[node + 1];
        auto const* it = std::lower_bound(first, last, key);
        if (it == last || !(*it == key)) {
            return flat_trie_detail::NO_INDEX;
        }
        return edge_child_[it - edge_key_];
    }

    template <typename Matcher, typename Visit>
    void match_at(uint32_t node, std::span<Matcher const> pattern, size_t depth, Visit& visit) const
    {
        if (depth == pattern.size()) {
            if (has_leaf(node)) {
                visit(node_leaf_[node]);
            }
            return;
        }
        auto const& seg = pattern[depth];
        if (seg.is_literal()) {
            auto const kid = child_of(node, Key(seg.literal_key()));
            if (kid != flat_trie_detail::NO_INDEX) {
                match_at(kid, pattern, depth + 1, visit);
            }
            return;
        }
        for (auto i = kids_begin_[node]; i < kids_begin_[node + 1]; ++i) {
            if (seg.matches(edge_key_[i])) {
                match_at(edge_child_[i], pattern, depth + 1, visit);
            }
        }
    }

    uint32_t const* kids_begin_ = nullptr;
    uint64_t const* present_ = nullptr;
    Key const* edge_key_ = nullptr;
    uint32_t const* edge_child_ = nullptr;
    Leaf const* node_leaf_ = nullptr;
    uint32_t node_count_ = 0;
    uint32_t edge_count_ = 0;
};

}  // namespace statusbar::container
