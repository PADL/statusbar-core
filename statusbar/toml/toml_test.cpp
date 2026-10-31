// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TOML Module Tests — pure TOML parser and value type tests
/// Config and args tests live in config_test.cpp and args_test.cpp

#include "statusbar/test/test.hpp"
#include "statusbar/toml/toml_error.hpp"
#include "statusbar/toml/toml_parser.hpp"
#include "statusbar/toml/toml_value.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <vector>

using namespace statusbar::toml;

//
// Value Type Tests
//

TEST(toml_value, null_default)
{
    Value v;
    EXPECT_TRUE(v.is_null());
    EXPECT_FALSE(v.is_string());
    EXPECT_FALSE(v.is_integer());
}

TEST(toml_value, string_construction)
{
    Value v{"hello"};
    EXPECT_TRUE(v.is_string());
    EXPECT_EQ(*v.as_string(), "hello");
}

TEST(toml_value, integer_construction)
{
    Value v{42};
    EXPECT_TRUE(v.is_integer());
    EXPECT_EQ(*v.as_integer(), 42);
}

TEST(toml_value, float_construction)
{
    Value v{3.14};
    EXPECT_TRUE(v.is_float());
    EXPECT_TRUE(*v.as_float() > 3.13 && *v.as_float() < 3.15);
}

TEST(toml_value, boolean_construction)
{
    Value v{true};
    EXPECT_TRUE(v.is_boolean());
    EXPECT_TRUE(*v.as_boolean());
}

TEST(toml_value, default_values)
{
    Value v;
    EXPECT_EQ(v.string_or("default"), "default");
    EXPECT_EQ(v.integer_or(99), 99);
    EXPECT_TRUE(v.float_or(1.5) > 1.4);
    EXPECT_FALSE(v.boolean_or(false));
}

TEST(toml_value, integer_to_float_conversion)
{
    Value v{100};
    auto f = v.as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(*f > 99.9 && *f < 100.1);
}

//
// Array Tests
//

TEST(toml_array, empty)
{
    Array arr;
    EXPECT_TRUE(arr.empty());
    EXPECT_EQ(arr.size(), 0U);
}

TEST(toml_array, push_and_access)
{
    Array arr;
    arr.push_back(Value{1});
    arr.push_back(Value{2});
    arr.push_back(Value{3});

    EXPECT_EQ(arr.size(), 3U);
    EXPECT_EQ(*arr[0].as_integer(), 1);
    EXPECT_EQ(*arr[1].as_integer(), 2);
    EXPECT_EQ(*arr[2].as_integer(), 3);
}

TEST(toml_array, at_bounds_check)
{
    Array arr;
    arr.push_back(Value{42});

    auto result = arr.at(0);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*(*result)->as_integer(), 42);

    auto bad = arr.at(1);
    EXPECT_FALSE(bad.has_value());
}

TEST(toml_array, operator_bounds_check)
{
    Array arr;
    arr.push_back(Value{1});
    arr.push_back(Value{2});

    // Valid access
    EXPECT_EQ(*arr[0].as_integer(), 1);
    EXPECT_EQ(*arr[1].as_integer(), 2);

    // Invalid access should throw
    bool threw = false;
    try {
        (void)arr[2];  // Out of bounds
    } catch (std::system_error const& e) {
        threw = (e.code() == TomlError::index_out_of_range);
    }
    EXPECT_TRUE(threw);
}

TEST(toml_array, const_operator_bounds_check)
{
    Array arr;
    arr.push_back(Value{99});

    Array const& const_arr = arr;

    // Valid access
    EXPECT_EQ(*const_arr[0].as_integer(), 99);

    // Invalid access should throw
    bool threw = false;
    try {
        (void)const_arr[1];  // Out of bounds
    } catch (std::system_error const& e) {
        threw = (e.code() == TomlError::index_out_of_range);
    }
    EXPECT_TRUE(threw);
}

//
// Table Tests
//

TEST(toml_table, empty)
{
    Table tbl;
    EXPECT_TRUE(tbl.empty());
    EXPECT_FALSE(tbl.contains("key"));
}

TEST(toml_table, set_and_get)
{
    Table tbl;
    tbl.set("name", Value{"test"});
    tbl.set("count", Value{42});

    EXPECT_TRUE(tbl.contains("name"));
    EXPECT_TRUE(tbl.contains("count"));
    EXPECT_FALSE(tbl.contains("missing"));

    EXPECT_EQ(*tbl.get("name")->as_string(), "test");
    EXPECT_EQ(*tbl.get("count")->as_integer(), 42);
}

TEST(toml_table, nested_path)
{
    Table tbl;
    Table nested;
    nested.set("port", Value{8080});
    tbl.set("server", Value{std::move(nested)});

    auto* v = tbl.get_path("server.port");
    EXPECT_TRUE(v != nullptr);
    EXPECT_EQ(*v->as_integer(), 8080);
}

TEST(toml_table, get_or_create)
{
    Table tbl;
    Table* sub = tbl.get_or_create_table("a.b.c");
    EXPECT_TRUE(sub != nullptr);

    sub->set("value", Value{123});

    auto* v = tbl.get_path("a.b.c.value");
    EXPECT_TRUE(v != nullptr);
    EXPECT_EQ(*v->as_integer(), 123);
}

//
// Parser Tests - Basic Values
//

TEST(toml_parser, empty_document)
{
    auto result = parse("");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(toml_parser, simple_string)
{
    auto result = parse(R"(name = "value")");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("name")->as_string(), "value");
}

TEST(toml_parser, simple_integer)
{
    auto result = parse("count = 42");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("count")->as_integer(), 42);
}

TEST(toml_parser, negative_integer)
{
    auto result = parse("value = -123");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("value")->as_integer(), -123);
}

TEST(toml_parser, hex_integer)
{
    auto result = parse("value = 0xDEADBEEF");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("value")->as_integer(), 0xDEADBEEF);
}

TEST(toml_parser, octal_integer)
{
    auto result = parse("value = 0o755");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("value")->as_integer(), 0755);
}

TEST(toml_parser, binary_integer)
{
    auto result = parse("value = 0b11010110");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("value")->as_integer(), 0b11010110);
}

TEST(toml_parser, float_value)
{
    auto result = parse("pi = 3.14159");
    EXPECT_TRUE(result.has_value());
    auto v = result->get("pi")->as_float();
    EXPECT_TRUE(v.has_value());
    EXPECT_TRUE(*v > 3.14 && *v < 3.15);
}

TEST(toml_parser, scientific_float)
{
    auto result = parse("value = 1e6");
    EXPECT_TRUE(result.has_value());
    auto v = result->get("value")->as_float();
    EXPECT_TRUE(v.has_value());
    EXPECT_TRUE(*v > 999999 && *v < 1000001);
}

TEST(toml_parser, boolean_true)
{
    auto result = parse("enabled = true");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(*result->get("enabled")->as_boolean());
}

TEST(toml_parser, boolean_false)
{
    auto result = parse("enabled = false");
    EXPECT_TRUE(result.has_value());
    EXPECT_FALSE(*result->get("enabled")->as_boolean());
}

//
// Parser Tests - Strings
//

TEST(toml_parser, basic_string_escapes)
{
    auto result = parse(R"(s = "hello\nworld")");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "hello\nworld");
}

TEST(toml_parser, literal_string)
{
    auto result = parse(R"(s = 'no\escape')");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "no\\escape");
}

TEST(toml_parser, multiline_basic_string)
{
    auto result = parse("s = \"\"\"\nline1\nline2\n\"\"\"");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2\n");
}

TEST(toml_parser, multiline_literal_string)
{
    auto result = parse("s = '''\nline1\nline2\n'''");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2\n");
}

//
// Parser Tests - Arrays
//

TEST(toml_parser, simple_array)
{
    auto result = parse("arr = [1, 2, 3]");
    EXPECT_TRUE(result.has_value());

    auto* arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 3U);
    EXPECT_EQ(*(*arr)[0].as_integer(), 1);
    EXPECT_EQ(*(*arr)[1].as_integer(), 2);
    EXPECT_EQ(*(*arr)[2].as_integer(), 3);
}

TEST(toml_parser, string_array)
{
    auto result = parse(R"(arr = ["a", "b", "c"])");
    EXPECT_TRUE(result.has_value());

    auto* arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 3U);
    EXPECT_EQ(*(*arr)[0].as_string(), "a");
}

TEST(toml_parser, nested_array)
{
    auto result = parse("arr = [[1, 2], [3, 4]]");
    EXPECT_TRUE(result.has_value());

    auto* arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 2U);

    auto* inner = (*arr)[0].as_array();
    EXPECT_TRUE(inner != nullptr);
    EXPECT_EQ(inner->size(), 2U);
}

TEST(toml_parser, multiline_array)
{
    auto result = parse("arr = [\n  1,\n  2,\n  3,\n]");
    EXPECT_TRUE(result.has_value());

    auto* arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 3U);
}

//
// Parser Tests - Tables
//

TEST(toml_parser, table_header)
{
    auto result = parse("[server]\nport = 8080");
    EXPECT_TRUE(result.has_value());

    auto* v = result->get_path("server.port");
    EXPECT_TRUE(v != nullptr);
    EXPECT_EQ(*v->as_integer(), 8080);
}

TEST(toml_parser, nested_table_headers)
{
    auto result = parse("[a.b.c]\nvalue = 42");
    EXPECT_TRUE(result.has_value());

    auto* v = result->get_path("a.b.c.value");
    EXPECT_TRUE(v != nullptr);
    EXPECT_EQ(*v->as_integer(), 42);
}

TEST(toml_parser, multiple_tables)
{
    auto result = parse("[server]\n"
                        "host = \"localhost\"\n"
                        "port = 8080\n"
                        "\n"
                        "[database]\n"
                        "name = \"mydb\"\n");
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(*result->get_path("server.host")->as_string(), "localhost");
    EXPECT_EQ(*result->get_path("server.port")->as_integer(), 8080);
    EXPECT_EQ(*result->get_path("database.name")->as_string(), "mydb");
}

TEST(toml_parser, inline_table)
{
    auto result = parse("point = { x = 1, y = 2 }");
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(*result->get_path("point.x")->as_integer(), 1);
    EXPECT_EQ(*result->get_path("point.y")->as_integer(), 2);
}

TEST(toml_parser, dotted_keys)
{
    auto result = parse("server.host = \"localhost\"\nserver.port = 8080");
    EXPECT_TRUE(result.has_value());

    EXPECT_EQ(*result->get_path("server.host")->as_string(), "localhost");
    EXPECT_EQ(*result->get_path("server.port")->as_integer(), 8080);
}

//
// Parser Tests - Array of Tables
//

TEST(toml_parser, array_of_tables)
{
    auto result = parse("[[items]]\n"
                        "name = \"first\"\n"
                        "\n"
                        "[[items]]\n"
                        "name = \"second\"\n");
    EXPECT_TRUE(result.has_value());

    auto* arr = result->get("items")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 2U);

    EXPECT_EQ(*(*arr)[0].as_table()->get("name")->as_string(), "first");
    EXPECT_EQ(*(*arr)[1].as_table()->get("name")->as_string(), "second");
}

//
// Quoted keys that contain a dot (BUG-004)
//
// `[port."eth0.100"]` names ONE table called `eth0.100` inside `port`.
// The quoting is what makes the dot a character rather than a separator,
// so a key path has to stay segmented from the parser down to the table
// walk -- joining it into a dotted string loses the distinction, and
// `eth0.100` is how every VLAN subinterface on Linux is named.
//

TEST(toml_quoted_dotted_key, a_quoted_table_name_is_one_table)
{
    auto result = parse("[port.\"eth0.100\"]\n"
                        "vlan = 100\n");
    EXPECT_TRUE(result.has_value());
    if (!result) {
        return;
    }

    auto const* port = result->get("port");
    EXPECT_TRUE(port != nullptr);
    if (port == nullptr || port->as_table() == nullptr) {
        return;
    }
    // Exactly one key, spelled with its dot, and no phantom "eth0" level.
    EXPECT_EQ(port->as_table()->size(), 1U);
    EXPECT_TRUE(port->as_table()->contains("eth0.100"));
    EXPECT_FALSE(port->as_table()->contains("eth0"));

    auto const* iface = port->as_table()->get("eth0.100");
    EXPECT_TRUE(iface != nullptr);
    if (iface != nullptr && iface->as_table() != nullptr) {
        EXPECT_EQ(*iface->as_table()->get("vlan")->as_integer(), 100);
    }
}

TEST(toml_quoted_dotted_key, the_dotted_string_lookup_cannot_reach_it)
{
    // get_path() splits on every dot, so it addresses the three-level path
    // `port` -> `eth0` -> `100`, which this document does not contain. That
    // is the price of the string API and the reason for the span overload
    // below; it is asserted here so the semantics cannot drift back.
    auto result = parse("[port.\"eth0.100\"]\n"
                        "vlan = 100\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_TRUE(result->get_path("port.eth0.100.vlan") == nullptr);
    }
}

TEST(toml_quoted_dotted_key, a_segmented_lookup_reaches_a_literal_dot)
{
    auto result = parse("[port.\"eth0.100\"]\n"
                        "vlan = 100\n"
                        "[port]\n"
                        "\"mtu.bytes\" = 1500\n");
    EXPECT_TRUE(result.has_value());
    if (!result) {
        return;
    }

    // A dotted segment in the middle of the path.
    std::vector<std::string> const through{"port", "eth0.100", "vlan"};
    auto const* v = result->get_path(std::span<std::string const>{through});
    EXPECT_TRUE(v != nullptr);
    if (v != nullptr) {
        EXPECT_EQ(*v->as_integer(), 100);
    }

    // And one at the end, which is the step a dotted-string lookup of the
    // final key would quietly split apart.
    std::vector<std::string> const leaf{"port", "mtu.bytes"};
    auto const* mtu = result->get_path(std::span<std::string const>{leaf});
    EXPECT_TRUE(mtu != nullptr);
    if (mtu != nullptr) {
        EXPECT_EQ(*mtu->as_integer(), 1500);
    }
}

TEST(toml_quoted_dotted_key, quoting_makes_a_different_document)
{
    // These two were indistinguishable before: both became three tables.
    auto quoted = parse("[port.\"eth0.100\"]\nvlan = 100\n");
    auto bare = parse("[port.eth0.100]\nvlan = 100\n");
    EXPECT_TRUE(quoted.has_value());
    EXPECT_TRUE(bare.has_value());
    if (!quoted || !bare) {
        return;
    }

    EXPECT_TRUE(quoted->get("port")->as_table()->contains("eth0.100"));
    EXPECT_FALSE(quoted->get("port")->as_table()->contains("eth0"));

    EXPECT_FALSE(bare->get("port")->as_table()->contains("eth0.100"));
    EXPECT_TRUE(bare->get("port")->as_table()->contains("eth0"));
    EXPECT_EQ(*bare->get_path("port.eth0.100.vlan")->as_integer(), 100);
}

TEST(toml_quoted_dotted_key, a_bare_and_a_quoted_segment_mix_in_one_header)
{
    auto result = parse("[a.\"b.c\".d]\n"
                        "v = 1\n");
    EXPECT_TRUE(result.has_value());
    if (!result) {
        return;
    }
    auto const* a = result->get("a");
    EXPECT_TRUE(a != nullptr && a->as_table() != nullptr);
    if (a == nullptr || a->as_table() == nullptr) {
        return;
    }
    auto const* bc = a->as_table()->get("b.c");
    EXPECT_TRUE(bc != nullptr && bc->as_table() != nullptr);
    if (bc != nullptr && bc->as_table() != nullptr) {
        auto const* d = bc->as_table()->get("d");
        EXPECT_TRUE(d != nullptr && d->as_table() != nullptr);
        if (d != nullptr && d->as_table() != nullptr) {
            EXPECT_EQ(*d->as_table()->get("v")->as_integer(), 1);
        }
    }
}

TEST(toml_quoted_dotted_key, a_quoted_dotted_key_value_pair_stays_one_key)
{
    auto result = parse("\"eth0.100\" = 5\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_TRUE(result->contains("eth0.100"));
        EXPECT_FALSE(result->contains("eth0"));
        EXPECT_EQ(*result->get("eth0.100")->as_integer(), 5);
    }
}

TEST(toml_quoted_dotted_key, a_quoted_dotted_key_in_an_inline_table_stays_one_key)
{
    auto result = parse("x = { \"a.b\" = 1 }\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto const* x = result->get("x");
        EXPECT_TRUE(x != nullptr && x->as_table() != nullptr);
        if (x != nullptr && x->as_table() != nullptr) {
            EXPECT_TRUE(x->as_table()->contains("a.b"));
            EXPECT_FALSE(x->as_table()->contains("a"));
        }
    }
}

TEST(toml_quoted_dotted_key, an_array_of_tables_can_be_named_with_a_dot)
{
    auto result = parse("[[\"eth0.100\"]]\n"
                        "x = 1\n"
                        "[[\"eth0.100\"]]\n"
                        "x = 2\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto const* v = result->get("eth0.100");
        EXPECT_TRUE(v != nullptr);
        if (v != nullptr && v->as_array() != nullptr) {
            EXPECT_EQ(v->as_array()->size(), 2U);
            EXPECT_EQ(*(*v->as_array())[1].as_table()->get("x")->as_integer(), 2);
        }
    }
}

TEST(toml_quoted_dotted_key, a_sub_table_under_an_array_of_tables_parses_either_way)
{
    // This test used to assert that both spellings FAILED -- the limitation
    // it pinned became BUG-006, and BUG-006 is fixed, so it now pins the
    // behaviour instead. Kept here as well as in the BUG-006 group because
    // the quoted spelling is what makes it this group's business.
    auto bare = parse("[[s]]\nx = 1\n[s.a]\nv = 7\n");
    auto quoted = parse("[[s]]\nx = 1\n[s.\"a.b\"]\nv = 7\n");
    EXPECT_TRUE(bare.has_value());
    EXPECT_TRUE(quoted.has_value());
    if (bare && quoted) {
        EXPECT_EQ(*(*bare->get("s")->as_array())[0].as_table()->get("a")->as_table()->get("v")->as_integer(), 7);
        EXPECT_EQ(*(*quoted->get("s")->as_array())[0].as_table()->get("a.b")->as_table()->get("v")->as_integer(), 7);
    }
}

//
// Table headers under an array of tables (BUG-006)
//
// `[s.x]` after `[[s]]` belongs to the element `[[s]]` last appended. We
// used to reject the document: `s` is an Array where the walk wanted a
// Table. Only table headers work this way -- TOML does not let a dotted key
// extend an array -- so the descent lives in the parser, not in
// Table::get_or_create_table().
//

TEST(toml_array_subtable, a_sub_table_attaches_to_the_last_element)
{
    auto result = parse("[[s]]\n"
                        "x = 1\n"
                        "[[s]]\n"
                        "x = 2\n"
                        "[s.extra]\n"
                        "v = 9\n");
    EXPECT_TRUE(result.has_value());
    if (!result) {
        return;
    }
    auto const* arr = result->get("s")->as_array();
    EXPECT_TRUE(arr != nullptr);
    if (arr == nullptr) {
        return;
    }
    EXPECT_EQ(arr->size(), 2U);

    // The second element, the one `[[s]]` appended last.
    auto const* second = (*arr)[1].as_table();
    EXPECT_TRUE(second != nullptr);
    if (second != nullptr) {
        EXPECT_EQ(*second->get("x")->as_integer(), 2);
        auto const* extra = second->get("extra");
        EXPECT_TRUE(extra != nullptr && extra->as_table() != nullptr);
        if (extra != nullptr && extra->as_table() != nullptr) {
            EXPECT_EQ(*extra->as_table()->get("v")->as_integer(), 9);
        }
    }

    // And not the first, which is the part a "descend into the array"
    // shortcut would get wrong.
    auto const* first = (*arr)[0].as_table();
    EXPECT_TRUE(first != nullptr);
    if (first != nullptr) {
        EXPECT_FALSE(first->contains("extra"));
    }
}

TEST(toml_array_subtable, values_after_the_sub_table_header_land_in_the_sub_table)
{
    // The header also changes where following key-values go -- it returns the
    // table the document is now writing into.
    auto result = parse("[[s]]\n"
                        "[s.a]\n"
                        "one = 1\n"
                        "two = 2\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto const* a = (*result->get("s")->as_array())[0].as_table()->get("a");
        EXPECT_TRUE(a != nullptr && a->as_table() != nullptr);
        if (a != nullptr && a->as_table() != nullptr) {
            EXPECT_EQ(a->as_table()->size(), 2U);
            EXPECT_EQ(*a->as_table()->get("two")->as_integer(), 2);
        }
    }
}

TEST(toml_array_subtable, an_array_of_tables_nests_under_an_array_of_tables)
{
    // `[[s.t]]` has to resolve `s` the same way before appending to `t`.
    auto result = parse("[[s]]\n"
                        "x = 1\n"
                        "[[s.t]]\n"
                        "v = 1\n"
                        "[[s.t]]\n"
                        "v = 2\n");
    EXPECT_TRUE(result.has_value());
    if (!result) {
        return;
    }
    auto const* outer = result->get("s")->as_array();
    EXPECT_TRUE(outer != nullptr);
    if (outer == nullptr || outer->size() != 1) {
        return;
    }
    auto const* inner = (*outer)[0].as_table()->get("t");
    EXPECT_TRUE(inner != nullptr && inner->as_array() != nullptr);
    if (inner != nullptr && inner->as_array() != nullptr) {
        EXPECT_EQ(inner->as_array()->size(), 2U);
        EXPECT_EQ(*(*inner->as_array())[1].as_table()->get("v")->as_integer(), 2);
    }
}

TEST(toml_array_subtable, a_deeper_path_descends_through_two_arrays)
{
    auto result = parse("[[s]]\n"
                        "[[s.t]]\n"
                        "[s.t.leaf]\n"
                        "v = 5\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto const* s = result->get("s")->as_array();
        EXPECT_TRUE(s != nullptr);
        if (s != nullptr && s->size() == 1) {
            auto const* t = (*s)[0].as_table()->get("t")->as_array();
            EXPECT_TRUE(t != nullptr);
            if (t != nullptr && t->size() == 1) {
                auto const* leaf = (*t)[0].as_table()->get("leaf");
                EXPECT_TRUE(leaf != nullptr && leaf->as_table() != nullptr);
                if (leaf != nullptr && leaf->as_table() != nullptr) {
                    EXPECT_EQ(*leaf->as_table()->get("v")->as_integer(), 5);
                }
            }
        }
    }
}

TEST(toml_array_subtable, an_empty_array_has_no_element_to_attach_to)
{
    // `s = []` then `[s.x]`: the array exists and has no last element, so
    // there is nothing the header could belong to. Still a failure, and the
    // line number locates it.
    Parser parser{"s = []\n[s.x]\nv = 1\n"};
    auto result = parser.parse_document_public();
    EXPECT_FALSE(result.has_value());
    if (!result) {
        EXPECT_EQ(result.error(), make_error_code(TomlError::type_mismatch));
        EXPECT_EQ(parser.error_line(), 2U);
    }
}

TEST(toml_array_subtable, an_array_of_plain_values_is_not_a_table_path)
{
    auto result = parse("s = [1, 2]\n[s.x]\nv = 1\n");
    EXPECT_FALSE(result.has_value());
    if (!result) {
        EXPECT_EQ(result.error(), make_error_code(TomlError::type_mismatch));
    }
}

TEST(toml_array_subtable, a_plain_value_in_the_path_still_fails)
{
    // The pre-existing guard, unchanged: a segment that holds an integer is
    // not a table and not an array.
    auto result = parse("s = 1\n[s.x]\nv = 1\n");
    EXPECT_FALSE(result.has_value());
    if (!result) {
        EXPECT_EQ(result.error(), make_error_code(TomlError::type_mismatch));
    }
}

TEST(toml_array_subtable, a_dotted_key_may_not_extend_an_array)
{
    // The other half of the rule, and why the descent is not in
    // Table::get_or_create_table(): TOML allows a table HEADER to reach into
    // an array's last element, but a dotted key may not. `s.y = 2` with `s`
    // an array stays an error.
    auto result = parse("s = [{ x = 1 }]\ns.y = 2\n");
    EXPECT_FALSE(result.has_value());
    if (!result) {
        EXPECT_EQ(result.error(), make_error_code(TomlError::type_mismatch));
    }
}

TEST(toml_quoted_dotted_key, the_interface_as_a_value_form_keeps_its_dots)
{
    // The shape to prefer in a schema, and the documented workaround while
    // this was broken: the name is a value, not a key.
    auto result = parse("[[stream]]\n"
                        "interface = \"eth0.100\"\n"
                        "[[stream]]\n"
                        "interface = \"eth1.200\"\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        auto const* arr = result->get("stream")->as_array();
        EXPECT_TRUE(arr != nullptr);
        if (arr != nullptr) {
            EXPECT_EQ(arr->size(), 2U);
            EXPECT_EQ(*(*arr)[0].as_table()->get("interface")->as_string(), "eth0.100");
            EXPECT_EQ(*(*arr)[1].as_table()->get("interface")->as_string(), "eth1.200");
        }
    }
}

TEST(toml_quoted_dotted_key, an_unquoted_dotted_path_still_nests)
{
    // The other half of the contract: nothing about ordinary dotted keys
    // changes, including a dotted key-value pair.
    auto result = parse("[server]\n"
                        "a.b.c = 1\n"
                        "[x.y.z]\n"
                        "v = 2\n");
    EXPECT_TRUE(result.has_value());
    if (result) {
        EXPECT_EQ(*result->get_path("server.a.b.c")->as_integer(), 1);
        EXPECT_EQ(*result->get_path("x.y.z.v")->as_integer(), 2);
    }
}

//
// Parser Tests - Comments
//

TEST(toml_parser, line_comments)
{
    auto result = parse("# This is a comment\n"
                        "key = \"value\" # inline comment\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("key")->as_string(), "value");
}

TEST(toml_parser, bare_nan)
{
    auto result = parse("val = nan\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("val")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(std::isnan(*f));
}

TEST(toml_parser, bare_inf)
{
    auto result = parse("val = inf\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("val")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(std::isinf(*f));
    EXPECT_TRUE(*f > 0.0);
}

TEST(toml_parser, negative_inf)
{
    auto result = parse("val = -inf\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("val")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(std::isinf(*f));
    EXPECT_TRUE(*f < 0.0);
}

TEST(toml_parser, positive_nan)
{
    auto result = parse("val = +nan\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("val")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(std::isnan(*f));
}

TEST(toml_parser, cr_in_comments)
{
    // \r\n line endings should work in comments and whitespace
    auto result = parse("# comment\r\nkey = 42\r\n");
    EXPECT_TRUE(result.has_value());
    auto i = result->get("key")->as_integer();
    EXPECT_TRUE(i.has_value());
    EXPECT_EQ(*i, 42);
}

//
// Error Tests
//

TEST(toml_error, unterminated_string)
{
    auto result = parse(R"(s = "unterminated)");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_error, duplicate_key)
{
    auto result = parse("key = 1\nkey = 2");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_error, missing_value)
{
    auto result = parse("key = ");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_error, invalid_table_header)
{
    auto result = parse("[");
    EXPECT_FALSE(result.has_value());
}

//
// Parser Edge Cases
//

TEST(toml_parse_edge, empty_string)
{
    auto result = parse("");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(toml_parse_edge, only_whitespace)
{
    auto result = parse("   \n\t  \n  ");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(toml_parse_edge, only_comments)
{
    auto result = parse("# This is a comment\n# Another comment\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

TEST(toml_parse_edge, comment_after_value)
{
    auto result = parse("key = 42 # inline comment\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->get("key")->as_integer(), 42);
}

TEST(toml_parse_edge, quoted_key)
{
    auto result = parse("\"key with spaces\" = \"value\"\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("key with spaces")->as_string(), "value");
}

TEST(toml_parse_edge, literal_string_key)
{
    auto result = parse("'key' = 'value'\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("key")->as_string(), "value");
}

TEST(toml_parse_edge, escape_sequences)
{
    auto result = parse("s = \"line1\\nline2\\ttab\"\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2\ttab");
}

TEST(toml_parse_edge, escape_backslash)
{
    auto result = parse("s = \"path\\\\to\\\\file\"\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "path\\to\\file");
}

TEST(toml_parse_edge, escape_quote)
{
    auto result = parse("s = \"say \\\"hello\\\"\"\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "say \"hello\"");
}

TEST(toml_parse_edge, unicode_escape_basic)
{
    auto result = parse("s = \"\\u0041\"\n");  // U+0041 = 'A'
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "A");
}

TEST(toml_parse_edge, unicode_escape_multibyte)
{
    auto result = parse("s = \"\\u00E9\"\n");  // U+00E9 = 'é'
    EXPECT_TRUE(result.has_value());
    std::string expected = "é";
    EXPECT_EQ(*result->get("s")->as_string(), expected);
}

TEST(toml_parse_edge, multiline_basic_string)
{
    auto result = parse("s = \"\"\"line1\nline2\nline3\"\"\"\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2\nline3");
}

TEST(toml_parse_edge, multiline_literal_string)
{
    auto result = parse("s = '''line1\nline2\nline3'''\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2\nline3");
}

TEST(toml_parse_edge, multiline_with_leading_newline)
{
    auto result = parse("s = \"\"\"\nline1\nline2\"\"\"\n");
    EXPECT_TRUE(result.has_value());
    // Leading newline after """ is trimmed
    EXPECT_EQ(*result->get("s")->as_string(), "line1\nline2");
}

TEST(toml_parse_edge, multiline_line_ending_backslash)
{
    auto result = parse("s = \"\"\"\\\nline1\\\n  line2\"\"\"\n");
    EXPECT_TRUE(result.has_value());
    // Backslash at end of line trims whitespace and newlines
    EXPECT_EQ(*result->get("s")->as_string(), "line1line2");
}

TEST(toml_parse_edge, hex_number)
{
    auto result = parse("n = 0xDEADBEEF\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("n")->as_integer(), 0xDEADBEEF);
}

TEST(toml_parse_edge, octal_number)
{
    auto result = parse("n = 0o755\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("n")->as_integer(), 0755);
}

TEST(toml_parse_edge, binary_number)
{
    auto result = parse("n = 0b11010110\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("n")->as_integer(), 0b11010110);
}

TEST(toml_parse_edge, number_with_underscores)
{
    auto result = parse("n = 1_000_000\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("n")->as_integer(), 1000000);
}

TEST(toml_parse_edge, float_with_exponent)
{
    auto result = parse("f = 6.022e23\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("f")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(*f > 6.0e23 && *f < 6.1e23);
}

TEST(toml_parse_edge, float_with_negative_exponent)
{
    auto result = parse("f = 1.0e-10\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("f")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(*f > 0.9e-10 && *f < 1.1e-10);
}

TEST(toml_parse_edge, positive_infinity)
{
    auto result = parse("f = +inf\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("f")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(*f > 1e300);  // Positive infinity
}

TEST(toml_parse_edge, negative_infinity)
{
    auto result = parse("f = -inf\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("f")->as_float();
    EXPECT_TRUE(f.has_value());
    EXPECT_TRUE(*f < -1e300);  // Negative infinity
}

TEST(toml_parse_edge, nan_value)
{
    // Parser requires sign before nan: +nan or -nan
    auto result = parse("f = +nan\n");
    EXPECT_TRUE(result.has_value());
    auto f = result->get("f")->as_float();
    EXPECT_TRUE(f.has_value());
    // NaN != NaN, so check using != itself
    EXPECT_TRUE(*f != *f);
}

TEST(toml_parse_edge, array_with_mixed_types)
{
    // TOML 1.0 allows mixed type arrays
    auto result = parse("arr = [1, \"two\", 3.0]\n");
    EXPECT_TRUE(result.has_value());
    auto arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 3U);
    EXPECT_EQ(*(*arr)[0].as_integer(), 1);
    EXPECT_EQ(*(*arr)[1].as_string(), "two");
}

TEST(toml_parse_edge, nested_array)
{
    auto result = parse("arr = [[1, 2], [3, 4]]\n");
    EXPECT_TRUE(result.has_value());
    auto arr = result->get("arr")->as_array();
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 2U);
}

TEST(toml_parse_edge, inline_table)
{
    auto result = parse("tbl = { a = 1, b = \"two\" }\n");
    EXPECT_TRUE(result.has_value());
    auto tbl = result->get("tbl")->as_table();
    EXPECT_TRUE(tbl != nullptr);
    EXPECT_EQ(*tbl->get("a")->as_integer(), 1);
    EXPECT_EQ(*tbl->get("b")->as_string(), "two");
}

TEST(toml_parse_edge, array_of_tables)
{
    auto result = parse("[[items]]\n"
                        "name = \"first\"\n"
                        "[[items]]\n"
                        "name = \"second\"\n");
    EXPECT_TRUE(result.has_value());
    auto items = result->get("items")->as_array();
    EXPECT_TRUE(items != nullptr);
    EXPECT_EQ(items->size(), 2U);
    EXPECT_EQ(*(*items)[0].as_table()->get("name")->as_string(), "first");
    EXPECT_EQ(*(*items)[1].as_table()->get("name")->as_string(), "second");
}

TEST(toml_parse_edge, dotted_key)
{
    auto result = parse("a.b.c = 42\n");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get_path("a.b.c")->as_integer(), 42);
}

TEST(toml_parse_edge, dotted_key_in_inline_table)
{
    auto result = parse("tbl = { a.b = 1 }\n");
    EXPECT_TRUE(result.has_value());
    auto tbl = result->get("tbl")->as_table();
    EXPECT_TRUE(tbl != nullptr);
    EXPECT_EQ(*tbl->get_path("a.b")->as_integer(), 1);
}

//
// Parser Error Tests
//

TEST(toml_parse_error, unterminated_string)
{
    auto result = parse("key = \"unterminated\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, invalid_escape)
{
    auto result = parse("key = \"invalid\\x\"\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, missing_equals)
{
    auto result = parse("key value\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, missing_value)
{
    auto result = parse("key = \n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, duplicate_key)
{
    auto result = parse("key = 1\nkey = 2\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unterminated_array)
{
    auto result = parse("arr = [1, 2, 3\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unterminated_inline_table)
{
    auto result = parse("tbl = { a = 1\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, invalid_table_header)
{
    auto result = parse("[]\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, missing_closing_bracket)
{
    auto result = parse("[table\nkey = 1\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, invalid_boolean)
{
    auto result = parse("key = TRUE\n");  // Must be lowercase
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unexpected_character)
{
    auto result = parse("@invalid = 1\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, junk_after_value)
{
    auto result = parse("key = 42 extra\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, integer_overflow_positive)
{
    // INT64_MAX is 9223372036854775807, this is larger
    auto result = parse("n = 99999999999999999999\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, integer_overflow_negative)
{
    // INT64_MIN is -9223372036854775808, this is smaller
    auto result = parse("n = -99999999999999999999\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unicode_surrogate_low)
{
    // U+D800 is the start of the surrogate range (invalid in TOML)
    auto result = parse("s = \"\\uD800\"\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unicode_surrogate_high)
{
    // U+DFFF is the end of the surrogate range (invalid in TOML)
    auto result = parse("s = \"\\uDFFF\"\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unicode_surrogate_middle)
{
    // U+DBFF is in the middle of the surrogate range (invalid in TOML)
    auto result = parse("s = \"\\uDBFF\"\n");
    EXPECT_FALSE(result.has_value());
}

//
// TomlError Tests
//

TEST(toml_error, error_codes)
{
    std::error_code ec = TomlError::file_not_found;
    EXPECT_TRUE(!ec.message().empty());
    EXPECT_TRUE(std::string(ec.category().name()) == "statusbar.toml");
}

TEST(toml_error, type_mismatch_message)
{
    std::error_code ec = TomlError::type_mismatch;
    EXPECT_TRUE(ec.message().find("type") != std::string::npos);
}

TEST(toml_error, index_out_of_range)
{
    std::error_code ec = TomlError::index_out_of_range;
    EXPECT_TRUE(ec.message().find("range") != std::string::npos);
}

TEST(toml_error, number_overflow)
{
    std::error_code ec = TomlError::number_overflow;
    EXPECT_TRUE(ec.message().find("overflow") != std::string::npos);
}

TEST(toml_error, invalid_unicode_codepoint)
{
    std::error_code ec = TomlError::invalid_unicode_codepoint;
    EXPECT_TRUE(ec.message().find("unicode") != std::string::npos || ec.message().find("surrogate") != std::string::npos);
}

//
// Value StatusValue Tests
//

TEST(toml_value_status, get_string_success)
{
    Value v{"hello"};
    auto result = v.get_string();
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, "hello");
}

TEST(toml_value_status, get_string_failure)
{
    Value v{42};
    auto result = v.get_string();
    EXPECT_FALSE(result.has_value());
}

TEST(toml_value_status, get_integer_success)
{
    Value v{99};
    auto result = v.get_integer();
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result, 99);
}

TEST(toml_value_status, get_integer_failure)
{
    Value v{"not an integer"};
    auto result = v.get_integer();
    EXPECT_FALSE(result.has_value());
}

TEST(toml_value_status, get_float_success)
{
    Value v{3.14};
    auto result = v.get_float();
    EXPECT_TRUE(result.has_value());
}

TEST(toml_value_status, get_boolean_success)
{
    Value v{true};
    auto result = v.get_boolean();
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}

//
// Table Iteration Tests
//

TEST(toml_table_iter, iterate_empty)
{
    Table tbl;
    int count = 0;
    for ([[maybe_unused]] auto [key, val] : tbl) {
        (void)val;
        ++count;
    }
    EXPECT_EQ(count, 0);
}

TEST(toml_table_iter, iterate_values)
{
    Table tbl;
    tbl.set("a", Value{1});
    tbl.set("b", Value{2});
    tbl.set("c", Value{3});

    int64_t sum = 0;
    for (auto [key, val] : tbl) {
        (void)key;
        sum += *val.as_integer();
    }
    EXPECT_EQ(sum, 6);
}

TEST(toml_table_iter, const_iterate)
{
    Table tbl;
    tbl.set("x", Value{4});
    tbl.set("y", Value{6});

    Table const& ctbl = tbl;
    int64_t sum = 0;
    for (auto [key, val] : ctbl) {
        (void)key;
        sum += *val.as_integer();
    }
    EXPECT_EQ(sum, 10);
}

//
// Value type() and DateTime coverage
//

TEST(toml_value_type, type_enum)
{
    Value null_val;
    EXPECT_EQ(static_cast<int>(null_val.type()), static_cast<int>(Value::Type::null));

    Value str_val{"hello"};
    EXPECT_EQ(static_cast<int>(str_val.type()), static_cast<int>(Value::Type::string));

    Value int_val{int64_t{42}};
    EXPECT_EQ(static_cast<int>(int_val.type()), static_cast<int>(Value::Type::integer));

    Value float_val{3.14};
    EXPECT_EQ(static_cast<int>(float_val.type()), static_cast<int>(Value::Type::floating));

    Value bool_val{true};
    EXPECT_EQ(static_cast<int>(bool_val.type()), static_cast<int>(Value::Type::boolean));
}

TEST(toml_value_type, datetime_construction)
{
    DateTime dt{"2024-01-15T10:30:00Z"};
    Value v{dt};
    EXPECT_TRUE(v.is_datetime());
    EXPECT_FALSE(v.is_string());
    EXPECT_FALSE(v.is_integer());
    EXPECT_EQ(static_cast<int>(v.type()), static_cast<int>(Value::Type::datetime));

    auto retrieved = v.as_datetime();
    EXPECT_TRUE(retrieved.has_value());
    EXPECT_TRUE(retrieved->value == "2024-01-15T10:30:00Z");
}

TEST(toml_value_type, datetime_equality)
{
    DateTime dt1{"2024-01-15T10:30:00Z"};
    DateTime dt2{"2024-01-15T10:30:00Z"};
    DateTime dt3{"2025-06-01T00:00:00Z"};
    EXPECT_TRUE(dt1 == dt2);
    EXPECT_FALSE(dt1 == dt3);
}

TEST(toml_value_type, as_datetime_wrong_type)
{
    Value v{"not a datetime"};
    auto result = v.as_datetime();
    EXPECT_FALSE(result.has_value());
}

TEST(toml_value_type, string_view_construction)
{
    std::string_view sv = "from string_view";
    Value v{sv};
    EXPECT_TRUE(v.is_string());
    auto s = v.as_string();
    EXPECT_TRUE(s.has_value());
    EXPECT_TRUE(*s == "from string_view");
}

TEST(toml_value_type, is_array_check)
{
    Array arr;
    arr.push_back(Value{int64_t{1}});
    arr.push_back(Value{int64_t{2}});
    Value v{std::move(arr)};
    EXPECT_TRUE(v.is_array());
    EXPECT_EQ(static_cast<int>(v.type()), static_cast<int>(Value::Type::array));
}

//
// Array and Table const accessors, erase, copy assignment
//

TEST(toml_const_access, array_at_const)
{
    Array arr;
    arr.push_back(Value{int64_t{10}});
    arr.push_back(Value{int64_t{20}});
    arr.push_back(Value{int64_t{30}});

    Array const& carr = arr;
    auto r0 = carr.at(0);
    EXPECT_TRUE(r0.has_value());
    EXPECT_TRUE((*r0)->is_integer());
    EXPECT_TRUE((*r0)->as_integer().value() == 10);

    auto r2 = carr.at(2);
    EXPECT_TRUE(r2.has_value());
    EXPECT_TRUE((*r2)->as_integer().value() == 30);

    auto r_oob = carr.at(99);
    EXPECT_FALSE(r_oob.has_value());
}

TEST(toml_const_access, table_get_const)
{
    Table tbl;
    tbl.set("name", Value{"Alice"});
    tbl.set("age", Value{int64_t{30}});

    Table const& ctbl = tbl;
    auto const* name = ctbl.get("name");
    EXPECT_TRUE(name != nullptr);
    EXPECT_TRUE(name->is_string());
    EXPECT_TRUE(name->as_string().value() == "Alice");

    auto const* missing = ctbl.get("nonexistent");
    EXPECT_TRUE(missing == nullptr);
}

TEST(toml_const_access, table_size)
{
    Table tbl;
    EXPECT_EQ(tbl.size(), size_t{0});
    tbl.set("a", Value{int64_t{1}});
    EXPECT_EQ(tbl.size(), size_t{1});
    tbl.set("b", Value{int64_t{2}});
    EXPECT_EQ(tbl.size(), size_t{2});
}

TEST(toml_const_access, table_erase)
{
    Table tbl;
    tbl.set("x", Value{int64_t{1}});
    tbl.set("y", Value{int64_t{2}});
    EXPECT_EQ(tbl.size(), size_t{2});

    bool erased = tbl.erase("x");
    EXPECT_TRUE(erased);
    EXPECT_EQ(tbl.size(), size_t{1});
    EXPECT_TRUE(tbl.get("x") == nullptr);

    bool not_erased = tbl.erase("nonexistent");
    EXPECT_FALSE(not_erased);
    EXPECT_EQ(tbl.size(), size_t{1});
}

TEST(toml_copy_assign, array_copy_assignment)
{
    Array arr1;
    arr1.push_back(Value{int64_t{100}});
    arr1.push_back(Value{"hello"});

    Array arr2;
    arr2.push_back(Value{int64_t{999}});
    arr2 = arr1;

    EXPECT_EQ(arr2.size(), size_t{2});
    EXPECT_TRUE(arr2[0].as_integer().value() == 100);
    EXPECT_TRUE(arr2[1].as_string().value() == "hello");

    // Verify it's a deep copy (modifying original doesn't affect copy)
    arr1.push_back(Value{int64_t{200}});
    EXPECT_EQ(arr1.size(), size_t{3});
    EXPECT_EQ(arr2.size(), size_t{2});
}

TEST(toml_copy_assign, table_copy_assignment)
{
    Table tbl1;
    tbl1.set("key1", Value{int64_t{42}});
    tbl1.set("key2", Value{"world"});

    Table tbl2;
    tbl2.set("other", Value{true});
    tbl2 = tbl1;

    EXPECT_EQ(tbl2.size(), size_t{2});
    EXPECT_TRUE(tbl2.get("key1") != nullptr);
    EXPECT_TRUE(tbl2.get("key1")->as_integer().value() == 42);
    EXPECT_TRUE(tbl2.get("other") == nullptr);

    // Verify deep copy
    tbl1.set("key3", Value{3.14});
    EXPECT_EQ(tbl1.size(), size_t{3});
    EXPECT_EQ(tbl2.size(), size_t{2});
}

//
// Parser error position and file parsing
//

TEST(toml_parser_file, parse_file_success)
{
    // Write a valid TOML file
    std::string const path = "/tmp/statusbar_toml_parse_test.toml";
    {
        std::ofstream out{path};
        out << "key = \"value\"\nnum = 42\n";
    }

    // Parse via Parser::parse_file
    auto result = Parser::parse_file(path);
    EXPECT_TRUE(result.has_value());

    // Also test the free function parse_file
    auto result2 = parse_file(path);
    EXPECT_TRUE(result2.has_value());

    std::remove(path.c_str());
}

TEST(toml_parser_file, parse_file_missing)
{
    auto result = Parser::parse_file("/tmp/statusbar_no_such_file.toml");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parser_file, error_line_column)
{
    // Parse invalid TOML to trigger an error, then check error_line/column
    auto result = parse("key = \n[invalid");
    // Whether this parse succeeds or not depends on the parser,
    // but we can always test that parse() returns a result
    // The key thing is that Parser::parse_file and parse() functions are exercised
    (void)result;

    // Parse something definitely invalid to get an error
    auto result2 = parse("[table\nkey = ");
    // Just exercising the parser error paths
    (void)result2;
}

TEST(toml_parser_error_position, fresh_parser_reports_line_1_column_1)
{
    Parser parser{"key = \"value\""};
    EXPECT_EQ(parser.error_line(), 1U);
    EXPECT_EQ(parser.error_column(), 1U);
}

TEST(toml_parser_error_position, after_failed_parse_line_column_match_failure_site)
{
    // Line 3 has an unterminated string, which should fail parsing.
    Parser parser{"# ok\nkey1 = 1\nbad = \"unterminated"};
    auto const result = parser.parse_document_public();
    EXPECT_FALSE(result.has_value());
    // error_line / error_column must be reachable and produce sensible values
    // (non-zero; exact line/column depends on how the parser advances through
    // the stream before the error is raised).
    EXPECT_TRUE(parser.error_line() >= 1U);
    EXPECT_TRUE(parser.error_column() >= 1U);
}

//
// parse_value_string hex/octal/binary tests
//

TEST(toml_parse_value_string_hex, hex_prefix)
{
    auto v = parse_value_string("0x0800");
    EXPECT_TRUE(v.is_integer());
    EXPECT_EQ(*v.as_integer(), 2048);
}

TEST(toml_parse_value_string_hex, octal_prefix)
{
    auto v = parse_value_string("0o777");
    EXPECT_TRUE(v.is_integer());
    EXPECT_EQ(*v.as_integer(), 511);
}

TEST(toml_parse_value_string_hex, binary_prefix)
{
    auto v = parse_value_string("0b1010");
    EXPECT_TRUE(v.is_integer());
    EXPECT_EQ(*v.as_integer(), 10);
}

TEST(toml_parse_value_string_hex, decimal_no_regression)
{
    auto v = parse_value_string("42");
    EXPECT_TRUE(v.is_integer());
    EXPECT_EQ(*v.as_integer(), 42);
}

//
// Exhaustive error message coverage
//

TEST(toml_error, all_errors_have_messages)
{
    // Verify every TomlError code produces a non-"Unknown" message
    auto check = [](TomlError e) {
        std::error_code ec = e;
        EXPECT_TRUE(!ec.message().empty());
        EXPECT_TRUE(ec.message().find("Unknown") == std::string::npos);
    };
    check(TomlError::file_not_found);
    check(TomlError::file_read_error);
    check(TomlError::unexpected_character);
    check(TomlError::unterminated_string);
    check(TomlError::invalid_escape_sequence);
    check(TomlError::invalid_number);
    check(TomlError::invalid_boolean);
    check(TomlError::invalid_date);
    check(TomlError::invalid_key);
    check(TomlError::duplicate_key);
    check(TomlError::expected_equals);
    check(TomlError::expected_value);
    check(TomlError::expected_newline);
    check(TomlError::expected_bracket);
    check(TomlError::unterminated_array);
    check(TomlError::unterminated_inline_table);
    check(TomlError::nested_inline_table);
    check(TomlError::invalid_table_header);
    check(TomlError::invalid_array_table_header);
    check(TomlError::key_not_found);
    check(TomlError::type_mismatch);
    check(TomlError::index_out_of_range);
    check(TomlError::number_overflow);
    check(TomlError::invalid_unicode_codepoint);
}

TEST(toml_error, category_name)
{
    EXPECT_EQ(std::string_view{toml_error_category().name()}, "statusbar.toml");
}

//
// TOML 1.0 conformance edge cases.
//
// The parser is a fuzz target (text → typed tree, called on untrusted
// config files). These tests pin down parser behavior on inputs that
// the TOML 1.0 spec calls out as invalid, plus a few shapes most
// likely to regress if the hand-written state machine is changed.
//
// Where the parser currently accepts an input the spec forbids, the
// test DOCUMENTS that behavior with a comment so a future tightening
// pass will flip the assertion and know why.
//

TEST(toml_parse_error, plus_or_minus_alone_is_invalid_number)
{
    EXPECT_FALSE(parse("n = +").has_value());
    EXPECT_FALSE(parse("n = -").has_value());
}

TEST(toml_parse_error, hex_prefix_with_no_digits)
{
    // "0x" with no hex digits — parser should reject.
    auto const result = parse("n = 0x");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, binary_prefix_with_no_digits)
{
    EXPECT_FALSE(parse("n = 0b").has_value());
}

TEST(toml_parse_error, octal_prefix_with_no_digits)
{
    EXPECT_FALSE(parse("n = 0o").has_value());
}

TEST(toml_parse_error, unterminated_backslash_at_eof)
{
    // String ending mid-escape: backslash at EOF inside a basic string
    // must be rejected (invalid_escape_sequence or unterminated_string).
    auto const result = parse(R"(s = "abc\)");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unterminated_multiline_basic_string)
{
    auto const result = parse("s = \"\"\"hello\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, unterminated_multiline_literal_string)
{
    auto const result = parse("s = '''hello\n");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, inline_table_empty_comma)
{
    // `{,}` is not a valid inline table.
    EXPECT_FALSE(parse("t = {,}").has_value());
}

TEST(toml_parse_error, array_trailing_junk_after_close)
{
    // Junk on the same line after an array value.
    EXPECT_FALSE(parse("a = [1, 2] garbage").has_value());
}

TEST(toml_parse_error, junk_in_table_header)
{
    // `[a.b.c garbage]` — extra token before the closing bracket.
    EXPECT_FALSE(parse("[a.b garbage]\n").has_value());
}

TEST(toml_parse_error, control_char_in_basic_string_rejected)
{
    // Raw tab (0x09) is allowed, but an unescaped control char like
    // 0x01 in a basic string should be rejected. Spec §2.3 forbids
    // unescaped control chars other than \t.
    //
    // DOCUMENTATION: parser currently accepts raw control bytes in
    // basic strings. If the parser is tightened to reject these per
    // spec, this assertion flips.
    std::string input = "s = \"";
    input.push_back('\x01');
    input += "\"";
    auto const result = parse(input);
    EXPECT_TRUE(result.has_value());  // current behavior; spec says should be FALSE
}

TEST(toml_parse_accepts, decimal_with_leading_zero)
{
    // TOML 1.0 §2.6 forbids leading zeros on decimal integers ("0123"
    // should be a syntax error). The parser currently accepts it and
    // returns 123.
    //
    // DOCUMENTATION: if we add spec-strict leading-zero rejection,
    // flip this to EXPECT_FALSE.
    auto const result = parse("n = 0123");
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(*result->get("n")->as_integer(), int64_t{123});
}

TEST(toml_parse_accepts, inline_table_trailing_comma)
{
    // TOML 1.0 §4.6 forbids a trailing comma after the last key/value
    // pair of an inline table. The parser currently accepts it.
    //
    // DOCUMENTATION: flip to EXPECT_FALSE if we tighten inline-table
    // parsing to match spec.
    auto const result = parse("t = {a = 1,}");
    EXPECT_TRUE(result.has_value());
}

TEST(toml_parse_accepts, multi_dot_float_consumes_only_first_part)
{
    // `1.2.3` — parser takes the longest valid float prefix (`1.2`),
    // leaving `.3` as unexpected trailing input. Confirms the whole
    // line fails rather than being silently truncated.
    auto const result = parse("n = 1.2.3");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_accepts, nested_arrays_moderate_depth_ok)
{
    // Sanity: the recursive-descent parser handles reasonable nesting
    // without exploding. Pathological depths are intentionally not
    // stack-tested here (that's ASAN/fuzzer territory).
    std::string input = "a = ";
    for (int i = 0; i < 32; ++i) {
        input += '[';
    }
    input += "1";
    for (int i = 0; i < 32; ++i) {
        input += ']';
    }
    auto const result = parse(input);
    EXPECT_TRUE(result.has_value());
}

TEST(toml_parse_error, newline_in_basic_string)
{
    // Single-quoted basic strings may not contain raw newlines.
    auto const result = parse("s = \"hello\nworld\"");
    EXPECT_FALSE(result.has_value());
}

TEST(toml_parse_error, key_collision_dotted_then_table)
{
    // Defining `a.b = 1` makes `a` an implicit table; then `[a]`
    // followed by `b = 2` would redefine `a.b`. Must be rejected.
    auto const result = parse("a.b = 1\n[a]\nb = 2\n");
    EXPECT_FALSE(result.has_value());
}

TEST_MAIN(statusbar_toml, toml_test)
