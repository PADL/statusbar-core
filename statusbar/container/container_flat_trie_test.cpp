// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/container/container_flat_trie.hpp"

#include "statusbar/test/test.hpp"

#include <array>
#include <cstring>
#include <vector>

using statusbar::container::FlatTrieBuilder;
using statusbar::container::FlatTrieImageLayout;
using statusbar::container::FlatTrieView;

namespace {

using Builder = FlatTrieBuilder<std::uint64_t, std::uint32_t>;
using View = FlatTrieView<std::uint64_t, std::uint32_t>;

/// A '#'-style matcher: literal key, any, or any-odd-key.
struct TestMatcher
{
    enum class Kind : std::uint8_t
    {
        literal,
        any,
        any_odd,
    };
    Kind kind = Kind::literal;
    std::uint64_t key = 0;

    [[nodiscard]] auto is_literal() const -> bool { return kind == Kind::literal; }
    [[nodiscard]] auto literal_key() const -> std::uint64_t { return key; }
    [[nodiscard]] auto matches(std::uint64_t k) const -> bool { return kind == Kind::any || (k % 2) == 1; }
};

auto keys(std::initializer_list<std::uint64_t> ks) -> std::vector<std::uint64_t>
{
    return {ks};
}

}  // namespace

TEST(container_flat_trie, builder_on_stack_storage)
{
    // Zero-heap: the whole trie lives in a stack buffer.
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(16, 16)> storage;
    Builder t(storage, 16, 16);
    EXPECT_EQ(t.node_count(), 1U);  // the root
    EXPECT_EQ(t.edge_count(), 0U);

    EXPECT_TRUE(t.insert(keys({1, 2, 3}), 100U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({1, 2, 4}), 101U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({1, 9}), 102U) == Builder::Insert::ok);
    EXPECT_EQ(t.node_count(), 6U);
    EXPECT_EQ(t.edge_count(), 5U);

    // First mapping wins.
    EXPECT_TRUE(t.insert(keys({1, 2, 3}), 999U) == Builder::Insert::exists);
    EXPECT_EQ(*t.find(keys({1, 2, 3})), 100U);
    EXPECT_EQ(*t.find(keys({1, 2, 4})), 101U);
    EXPECT_EQ(*t.find(keys({1, 9})), 102U);

    // Interior nodes and unknown paths resolve to nothing; a prefix node
    // can be mapped later.
    EXPECT_FALSE(t.find(keys({1, 2})).has_value());
    EXPECT_FALSE(t.find(keys({7})).has_value());
    EXPECT_TRUE(t.insert(keys({1, 2}), 103U) == Builder::Insert::ok);
    EXPECT_EQ(*t.find(keys({1, 2})), 103U);
}

TEST(container_flat_trie, capacity_full_leaves_trie_untouched)
{
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(3, 3)> storage;
    Builder t(storage, 3, 3);
    EXPECT_TRUE(t.insert(keys({1, 2}), 1U) == Builder::Insert::ok);  // uses nodes 1,2
    auto const nodes = t.node_count();
    auto const edges = t.edge_count();
    EXPECT_TRUE(t.insert(keys({1, 3, 4}), 2U) == Builder::Insert::full);
    EXPECT_EQ(t.node_count(), nodes);
    EXPECT_EQ(t.edge_count(), edges);
    EXPECT_FALSE(t.find(keys({1, 3, 4})).has_value());

    // Relocation into bigger storage carries everything across.
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(16, 16)> bigger;
    Builder grown(bigger, 16, 16, t);
    EXPECT_EQ(*grown.find(keys({1, 2})), 1U);
    EXPECT_TRUE(grown.insert(keys({1, 3, 4}), 2U) == Builder::Insert::ok);
    EXPECT_EQ(*grown.find(keys({1, 3, 4})), 2U);
}

TEST(container_flat_trie, image_round_trip_and_view)
{
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(32, 32)> storage;
    Builder t(storage, 32, 32);
    // Insert out of order so the image sort matters.
    EXPECT_TRUE(t.insert(keys({5, 7}), 57U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({5, 1}), 51U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({5, 4}), 54U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({2}), 20U) == Builder::Insert::ok);
    EXPECT_TRUE(t.insert(keys({9, 1}), 91U) == Builder::Insert::ok);

    alignas(View::image_align) std::array<std::byte, Builder::storage_size(32, 32)> image_bytes;
    auto const written = t.write_image(image_bytes);
    EXPECT_EQ(written, t.image_size());

    auto view = View::attach(std::span<std::byte const>(image_bytes.data(), written));
    EXPECT_TRUE(view.has_value());
    EXPECT_EQ(view->node_count(), t.node_count());
    EXPECT_EQ(view->edge_count(), t.edge_count());
    EXPECT_EQ(*view->find(keys({5, 7})), 57U);
    EXPECT_EQ(*view->find(keys({5, 1})), 51U);
    EXPECT_EQ(*view->find(keys({5, 4})), 54U);
    EXPECT_EQ(*view->find(keys({2})), 20U);
    EXPECT_EQ(*view->find(keys({9, 1})), 91U);
    EXPECT_FALSE(view->find(keys({5})).has_value());
    EXPECT_FALSE(view->find(keys({5, 2})).has_value());

    // match: literal, any, and predicate segments — on the view AND the
    // builder (same results either side of the freeze).
    auto run = [&](auto const& trie, std::vector<TestMatcher> const& pattern) {
        std::vector<std::uint32_t> hits;
        trie.match(std::span<TestMatcher const>(pattern), [&](std::uint32_t leaf) { hits.push_back(leaf); });
        std::sort(hits.begin(), hits.end());
        return hits;
    };
    std::vector<TestMatcher> any_under_5{{TestMatcher::Kind::literal, 5}, {TestMatcher::Kind::any, 0}};
    std::vector<TestMatcher> odd_under_5{{TestMatcher::Kind::literal, 5}, {TestMatcher::Kind::any_odd, 0}};
    std::vector<TestMatcher> top_any{{TestMatcher::Kind::any, 0}};
    EXPECT_TRUE(run(*view, any_under_5) == (std::vector<std::uint32_t>{51U, 54U, 57U}));
    EXPECT_TRUE(run(*view, odd_under_5) == (std::vector<std::uint32_t>{51U, 57U}));
    EXPECT_TRUE(run(*view, top_any) == (std::vector<std::uint32_t>{20U}));
    EXPECT_TRUE(run(t, any_under_5) == run(*view, any_under_5));
    EXPECT_TRUE(run(t, odd_under_5) == run(*view, odd_under_5));
}

TEST(container_flat_trie, attach_rejects_bad_images)
{
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(8, 8)> storage;
    Builder t(storage, 8, 8);
    EXPECT_TRUE(t.insert(keys({1}), 1U) == Builder::Insert::ok);
    alignas(View::image_align) std::array<std::byte, Builder::storage_size(8, 8)> image;
    auto const written = t.write_image(image);
    EXPECT_TRUE(written > 0);
    auto whole = std::span<std::byte const>(image.data(), written);

    EXPECT_TRUE(View::attach(whole).has_value());
    // Truncated: header alone, or the header promising more than the span.
    EXPECT_FALSE(View::attach(whole.first(8)).has_value());
    EXPECT_FALSE(View::attach(whole.first(written - 1)).has_value());
    // Corrupt magic.
    auto bad = image;
    bad[0] = std::byte{0};
    EXPECT_FALSE(View::attach(std::span<std::byte const>(bad.data(), written)).has_value());
    // A differently-typed trie's image is refused by geometry.
    auto narrow_view = FlatTrieView<std::uint32_t, std::uint32_t>::attach(whole);
    EXPECT_FALSE(narrow_view.has_value());
    // The default view is inert.
    View detached;
    EXPECT_FALSE(detached.valid());
    EXPECT_FALSE(detached.find(keys({1})).has_value());
}

TEST(container_flat_trie, empty_and_root_leaf)
{
    alignas(Builder::storage_align) std::array<std::byte, Builder::storage_size(2, 1)> storage;
    Builder t(storage, 2, 1);
    EXPECT_FALSE(t.find({}).has_value());
    EXPECT_TRUE(t.insert({}, 7U) == Builder::Insert::ok);  // the root itself
    EXPECT_EQ(*t.find({}), 7U);
    EXPECT_TRUE(t.insert({}, 8U) == Builder::Insert::exists);

    alignas(View::image_align) std::array<std::byte, 256> image;
    auto const written = t.write_image(image);
    auto view = View::attach(std::span<std::byte const>(image.data(), written));
    EXPECT_TRUE(view.has_value());
    EXPECT_EQ(*view->find({}), 7U);
}

TEST_MAIN(statusbar_container, container_flat_trie_test)
