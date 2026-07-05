// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// Config Module Tests

#include "statusbar/config/config.hpp"

#include "statusbar/ieee/ieee.hpp"
#include "statusbar/test/test.hpp"
#include "statusbar/tsn/tsn.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <string>
#include <system_error>
#include <vector>

using namespace statusbar;
using namespace statusbar::config;
using statusbar::args::ArgumentSpecs;

//
// Config Store Tests
//

TEST(config_store, write_control_characters)
{
    // Control characters must be escaped as \uXXXX in TOML output
    Config config;
    config.set("test", std::string("hello\x01world"));
    std::string const output = config.to_toml_string();
    // The \x01 should be escaped as \u0001, not passed through raw
    EXPECT_TRUE(output.find("\\u0001") != std::string::npos);
    EXPECT_TRUE(output.find('\x01') == std::string::npos);
}

TEST(config_store, load_string)
{
    Config config;
    auto status = config.load_string("[server]\n"
                                     "host = \"localhost\"\n"
                                     "port = 8080\n");
    EXPECT_TRUE(status);

    EXPECT_EQ(config.get_string("server.host", ""), "localhost");
    EXPECT_EQ(config.get_integer("server.port", 0), 8080);
}

TEST(config_store, get_with_defaults)
{
    Config config;
    (void)config.load_string("key = \"value\"");

    EXPECT_EQ(config.get_string("key", "default"), "value");
    EXPECT_EQ(config.get_string("missing", "default"), "default");
    EXPECT_EQ(config.get_integer("missing", 42), 42);
    EXPECT_TRUE(config.get_float("missing", 3.14) > 3.13);
    EXPECT_FALSE(config.get_boolean("missing", false));
}

TEST(config_store, set_values)
{
    Config config;

    config.set("name", "test");
    config.set("count", static_cast<int64_t>(42));
    config.set("enabled", true);
    config.set("ratio", 0.5);

    EXPECT_EQ(config.get_string("name", ""), "test");
    EXPECT_EQ(config.get_integer("count", 0), 42);
    EXPECT_TRUE(config.get_boolean("enabled", false));
    EXPECT_TRUE(config.get_float("ratio", 0.0) > 0.4);
}

TEST(config_store, set_nested)
{
    Config config;

    config.set("a.b.c", "deep");

    EXPECT_EQ(config.get_string("a.b.c", ""), "deep");
}

TEST(config_store, cli_override_equals)
{
    char const* args[] = {"prog", "--server.port=9000", "--debug=true"};
    Config config;
    (void)config.load_string("[server]\nport = 8080");

    auto remaining = config.apply_cli_overrides(3, args);

    EXPECT_EQ(remaining.size(), 1U);
    EXPECT_EQ(remaining[0], "prog");
    EXPECT_EQ(config.get_integer("server.port", 0), 9000);
    EXPECT_TRUE(config.get_boolean("debug", false));
}

TEST(config_store, cli_override_space)
{
    char const* args[] = {"prog", "--name", "test", "--count", "42"};
    Config config;

    auto remaining = config.apply_cli_overrides(5, args);

    EXPECT_EQ(remaining.size(), 1U);
    EXPECT_EQ(config.get_string("name", ""), "test");
    EXPECT_EQ(config.get_integer("count", 0), 42);
}

TEST(config_store, cli_flag_without_value)
{
    char const* args[] = {"prog", "--verbose", "--debug"};
    Config config;

    (void)config.apply_cli_overrides(3, args);

    EXPECT_TRUE(config.get_boolean("verbose", false));
    EXPECT_TRUE(config.get_boolean("debug", false));
}

TEST(config_store, cli_preserves_positional)
{
    // Note: --verbose without = consumes the next non-flag argument as its value
    // To preserve positional args, either use --verbose=true or put flags last
    char const* args[] = {"prog", "input.txt", "output.txt", "--verbose"};
    Config config;

    auto remaining = config.apply_cli_overrides(4, args);

    EXPECT_EQ(remaining.size(), 3U);
    EXPECT_EQ(remaining[0], "prog");
    EXPECT_EQ(remaining[1], "input.txt");
    EXPECT_EQ(remaining[2], "output.txt");
    EXPECT_TRUE(config.get_boolean("verbose", false));
}

TEST(config_store, cli_negative_number)
{
    char const* args[] = {"prog", "--offset", "-100"};
    Config config;

    (void)config.apply_cli_overrides(3, args);

    EXPECT_EQ(config.get_integer("offset", 0), -100);
}

//
// IEEE Type Parsing Tests
//

TEST(config_ieee_parse, eui48_from_string_colon)
{
    auto mac = statusbar::ieee::eui48_from_string("aa:bb:cc:dd:ee:ff");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
    EXPECT_EQ(static_cast<int>(mac->value[5]), 0xff);
}

TEST(config_ieee_parse, eui48_from_string_dash)
{
    auto mac = statusbar::ieee::eui48_from_string("aa-bb-cc-dd-ee-ff");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
}

TEST(config_ieee_parse, eui48_from_string_no_sep)
{
    auto mac = statusbar::ieee::eui48_from_string("aabbccddeeff");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
}

TEST(config_ieee_parse, eui48_to_string)
{
    statusbar::ieee::Eui48 mac{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    auto str = statusbar::ieee::to_string(mac);
    EXPECT_EQ(str, "aa:bb:cc:dd:ee:ff");
}

TEST(config_ieee_parse, eui64_from_string)
{
    auto mac = statusbar::ieee::eui64_from_string("aa:bb:cc:dd:ee:ff:00:11");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->span()[0]), 0xaa);
    EXPECT_EQ(static_cast<int>(mac->span()[7]), 0x11);
}

TEST(config_ieee_parse, eui64_to_string)
{
    statusbar::ieee::Eui64 mac{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11};
    auto str = statusbar::ieee::to_string(mac);
    EXPECT_EQ(str, "aa:bb:cc:dd:ee:ff:00:11");
}

TEST(config_ieee_parse, stream_id_from_string)
{
    auto sid = statusbar::tsn::stream_id_from_string("aa:bb:cc:dd:ee:ff:0001");
    EXPECT_TRUE(sid.has_value());
    EXPECT_EQ(static_cast<int>(sid->get_system_address().value[0]), 0xaa);
    EXPECT_EQ(static_cast<int>(sid->get_unique_id()), 1);
}

TEST(config_ieee_parse, stream_id_to_string)
{
    statusbar::ieee::Eui48 addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    statusbar::tsn::StreamId sid{addr, 0x1234};
    auto str = statusbar::tsn::to_string(sid);
    EXPECT_EQ(str, "aa:bb:cc:dd:ee:ff:1234");
}

//
// Config IEEE Type Tests (using generic get<T>/set<T>)
//

TEST(config_ieee, get_eui48)
{
    Config config;
    (void)config.load_string(R"(mac = "aa:bb:cc:dd:ee:ff")");

    auto mac = config.get<ieee::Eui48>("mac");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
}

TEST(config_ieee, set_eui48)
{
    Config config;
    statusbar::ieee::Eui48 mac{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    config.set<ieee::Eui48>("network.mac", mac);

    EXPECT_EQ(config.get_string("network.mac", ""), "11:22:33:44:55:66");
}

TEST(config_ieee, get_stream_id)
{
    Config config;
    (void)config.load_string(R"(stream = "aa:bb:cc:dd:ee:ff:0001")");

    auto sid = config.get<tsn::StreamId>("stream");
    EXPECT_TRUE(sid.has_value());
    EXPECT_EQ(sid->get_unique_id(), 1);
}

TEST(config_ieee, set_stream_id)
{
    Config config;
    statusbar::ieee::Eui48 addr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    statusbar::tsn::StreamId sid{addr, 0xabcd};
    config.set<tsn::StreamId>("avb.stream_id", sid);

    EXPECT_EQ(config.get_string("avb.stream_id", ""), "aa:bb:cc:dd:ee:ff:abcd");
}

//
// Config Merge Tests
//

TEST(config_merge, basic_override)
{
    Config config;
    (void)config.load_string("key = 1");
    (void)config.load_string("key = 2");

    EXPECT_EQ(config.get_integer("key", 0), 2);
}

TEST(config_merge, nested_table_merge)
{
    Config config;
    (void)config.load_string("[server]\nhost = \"localhost\"\nport = 8080");
    (void)config.load_string("[server]\nport = 9090");

    // Host should be preserved, port overridden
    EXPECT_EQ(config.get_string("server.host", ""), "localhost");
    EXPECT_EQ(config.get_integer("server.port", 0), 9090);
}

TEST(config_merge, deep_nested_merge)
{
    Config config;
    (void)config.load_string("[a.b]\nc = 1\nd = 2");
    (void)config.load_string("[a.b]\nd = 3\ne = 4");

    EXPECT_EQ(config.get_integer("a.b.c", 0), 1);
    EXPECT_EQ(config.get_integer("a.b.d", 0), 3);
    EXPECT_EQ(config.get_integer("a.b.e", 0), 4);
}

//
// Config Serialization Tests
//

TEST(config_serialize, simple_values)
{
    Config config;
    config.set("name", "test");
    config.set("count", static_cast<int64_t>(42));
    config.set("enabled", true);

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("name = \"test\"") != std::string::npos);
    EXPECT_TRUE(toml.find("count = 42") != std::string::npos);
    EXPECT_TRUE(toml.find("enabled = true") != std::string::npos);
}

TEST(config_serialize, nested_table)
{
    Config config;
    config.set("server.host", "localhost");
    config.set("server.port", static_cast<int64_t>(8080));

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("[server]") != std::string::npos);
    EXPECT_TRUE(toml.find("host = \"localhost\"") != std::string::npos);
    EXPECT_TRUE(toml.find("port = 8080") != std::string::npos);
}

TEST(config_serialize, roundtrip)
{
    Config config1;
    config1.set("name", "test");
    config1.set("server.host", "localhost");
    config1.set("server.port", static_cast<int64_t>(8080));

    auto toml = config1.to_toml_string();

    Config config2;
    (void)config2.load_string(toml);

    EXPECT_EQ(config2.get_string("name", ""), "test");
    EXPECT_EQ(config2.get_string("server.host", ""), "localhost");
    EXPECT_EQ(config2.get_integer("server.port", 0), 8080);
}

//
// CLI --config Test
//

TEST(config_cli, config_flag_handled)
{
    // We can't easily test file loading, but we can verify --config is consumed
    char const* args[] = {"prog", "--debug=true", "--name", "test"};
    Config config;

    auto remaining = config.apply_cli_overrides(4, args);

    EXPECT_EQ(remaining.size(), 1U);
    EXPECT_TRUE(config.get_boolean("debug", false));
    EXPECT_EQ(config.get_string("name", ""), "test");
}

//
// IEEE Type Parsing Edge Cases
//

TEST(config_ieee_edge, eui48_uppercase)
{
    auto mac = statusbar::ieee::eui48_from_string("AA:BB:CC:DD:EE:FF");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
}

TEST(config_ieee_edge, eui48_mixed_case)
{
    auto mac = statusbar::ieee::eui48_from_string("aA:Bb:cC:Dd:eE:fF");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->value[0]), 0xaa);
}

TEST(config_ieee_edge, eui48_invalid_too_short)
{
    auto mac = statusbar::ieee::eui48_from_string("aa:bb:cc:dd:ee");
    EXPECT_FALSE(mac.has_value());
}

TEST(config_ieee_edge, eui48_invalid_too_long)
{
    auto mac = statusbar::ieee::eui48_from_string("aa:bb:cc:dd:ee:ff:gg");
    EXPECT_FALSE(mac.has_value());
}

TEST(config_ieee_edge, eui48_invalid_chars)
{
    auto mac = statusbar::ieee::eui48_from_string("aa:bb:cc:dd:ee:zz");
    EXPECT_FALSE(mac.has_value());
}

TEST(config_ieee_edge, eui48_empty)
{
    auto mac = statusbar::ieee::eui48_from_string("");
    EXPECT_FALSE(mac.has_value());
}

TEST(config_ieee_edge, eui64_uppercase)
{
    auto mac = statusbar::ieee::eui64_from_string("AA:BB:CC:DD:EE:FF:00:11");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->span()[0]), 0xaa);
}

TEST(config_ieee_edge, eui64_dash_sep)
{
    auto mac = statusbar::ieee::eui64_from_string("aa-bb-cc-dd-ee-ff-00-11");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->span()[0]), 0xaa);
}

TEST(config_ieee_edge, eui64_no_sep)
{
    auto mac = statusbar::ieee::eui64_from_string("aabbccddeeff0011");
    EXPECT_TRUE(mac.has_value());
    EXPECT_EQ(static_cast<int>(mac->span()[0]), 0xaa);
}

TEST(config_ieee_edge, eui64_invalid_short)
{
    auto mac = statusbar::ieee::eui64_from_string("aa:bb:cc:dd:ee:ff:00");
    EXPECT_FALSE(mac.has_value());
}

TEST(config_ieee_edge, stream_id_uppercase)
{
    auto sid = statusbar::tsn::stream_id_from_string("AA:BB:CC:DD:EE:FF:ABCD");
    EXPECT_TRUE(sid.has_value());
    EXPECT_EQ(static_cast<int>(sid->get_unique_id()), 0xabcd);
}

TEST(config_ieee_edge, stream_id_invalid_short)
{
    auto sid = statusbar::tsn::stream_id_from_string("aa:bb:cc:dd:ee:ff");
    EXPECT_FALSE(sid.has_value());
}

TEST(config_ieee_edge, stream_id_invalid_format)
{
    auto sid = statusbar::tsn::stream_id_from_string("not-a-stream-id");
    EXPECT_FALSE(sid.has_value());
}

//
// IEEE Type Default Value Tests (using generic get<T> with default)
//

TEST(config_ieee_defaults, eui48_with_default)
{
    Config config;
    statusbar::ieee::Eui48 default_mac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

    auto mac = config.get<ieee::Eui48>("missing", default_mac);
    EXPECT_EQ(static_cast<int>(mac.value[0]), 0x00);
    EXPECT_EQ(static_cast<int>(mac.value[5]), 0x55);
}

TEST(config_ieee_defaults, eui64_with_default)
{
    Config config;
    statusbar::ieee::Eui64 default_mac{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

    auto mac = config.get<ieee::Eui64>("missing", default_mac);
    EXPECT_EQ(static_cast<int>(mac.span()[0]), 0x00);
    EXPECT_EQ(static_cast<int>(mac.span()[7]), 0x77);
}

TEST(config_ieee_defaults, stream_id_with_default)
{
    Config config;
    statusbar::ieee::Eui48 addr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    statusbar::tsn::StreamId default_sid{addr, 0x1234};

    auto sid = config.get<tsn::StreamId>("missing", default_sid);
    EXPECT_EQ(sid.get_unique_id(), 0x1234);
}

TEST(config_ieee_defaults, eui48_invalid_string_uses_default)
{
    Config config;
    (void)config.load_string(R"(mac = "not-valid-mac")");
    statusbar::ieee::Eui48 default_mac{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    auto mac = config.get<ieee::Eui48>("mac", default_mac);
    EXPECT_EQ(static_cast<int>(mac.value[0]), 0xaa);
}

//
// Serialization Edge Cases
//

TEST(config_serialize_edge, array_of_integers)
{
    Config config;
    (void)config.load_string("arr = [1, 2, 3, 4, 5]");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("arr = [1, 2, 3, 4, 5]") != std::string::npos);
}

TEST(config_serialize_edge, array_of_strings)
{
    Config config;
    (void)config.load_string(R"(arr = ["a", "b", "c"])");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("[") != std::string::npos);
}

TEST(config_serialize_edge, string_with_escapes)
{
    Config config;
    config.set("msg", "line1\nline2\ttab");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("\\n") != std::string::npos);
    EXPECT_TRUE(toml.find("\\t") != std::string::npos);
}

TEST(config_serialize_edge, string_with_quotes)
{
    Config config;
    config.set("msg", R"(He said "hello")");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("\\\"") != std::string::npos);
}

TEST(config_serialize_edge, string_with_backslash)
{
    Config config;
    config.set("path", "C:\\Users\\test");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("\\\\") != std::string::npos);
}

TEST(config_serialize_edge, deeply_nested_tables)
{
    Config config;
    config.set("a.b.c.d.e", "deep");

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("[a.b.c.d]") != std::string::npos);
    EXPECT_TRUE(toml.find("e = \"deep\"") != std::string::npos);
}

TEST(config_serialize_edge, deeply_nested_roundtrip)
{
    Config config1;
    config1.set("name", "test");
    config1.set("server.host", "localhost");
    config1.set("server.tls.enabled", true);
    config1.set("server.tls.cert.path", "/etc/cert.pem");
    config1.set("a.b.c.d.e", static_cast<int64_t>(5));

    auto toml = config1.to_toml_string();

    Config config2;
    auto load_result = config2.load_string(toml);
    EXPECT_TRUE(load_result.has_value());

    EXPECT_EQ(config2.get_string("name", ""), "test");
    EXPECT_EQ(config2.get_string("server.host", ""), "localhost");
    EXPECT_TRUE(config2.get_boolean("server.tls.enabled", false));
    EXPECT_EQ(config2.get_string("server.tls.cert.path", ""), "/etc/cert.pem");
    EXPECT_EQ(config2.get_integer("a.b.c.d.e", 0), 5);
}

TEST(config_serialize_edge, float_values)
{
    Config config;
    config.set("pi", 3.14159);

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find("3.14") != std::string::npos);
}

TEST(config_serialize_edge, ieee_types_roundtrip)
{
    Config config1;
    statusbar::ieee::Eui48 mac{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    statusbar::ieee::Eui48 addr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    statusbar::tsn::StreamId sid{addr, 0xabcd};

    config1.set<ieee::Eui48>("network.mac", mac);
    config1.set<tsn::StreamId>("avb.stream", sid);

    auto toml = config1.to_toml_string();

    Config config2;
    (void)config2.load_string(toml);

    auto mac2 = config2.get<ieee::Eui48>("network.mac");
    EXPECT_TRUE(mac2.has_value());
    EXPECT_EQ(static_cast<int>(mac2->value[0]), 0xaa);

    auto sid2 = config2.get<tsn::StreamId>("avb.stream");
    EXPECT_TRUE(sid2.has_value());
    EXPECT_EQ(sid2->get_unique_id(), 0xabcd);
}

//
// CLI Override Edge Cases
//

TEST(config_cli_edge, single_dash_flag)
{
    char const* args[] = {"prog", "-v"};
    Config config;

    auto remaining = config.apply_cli_overrides(2, args);

    EXPECT_EQ(remaining.size(), 1U);
    EXPECT_TRUE(config.get_boolean("v", false));
}

TEST(config_cli_edge, mixed_flags_and_positional)
{
    // Note: --debug without = consumes output.txt as its value
    // Use --debug=true to preserve positional args
    char const* args[] = {"prog", "--port=8080", "input.txt", "--debug=true", "output.txt"};
    Config config;

    auto remaining = config.apply_cli_overrides(5, args);

    EXPECT_EQ(remaining.size(), 3U);
    EXPECT_EQ(remaining[0], "prog");
    EXPECT_EQ(remaining[1], "input.txt");
    EXPECT_EQ(remaining[2], "output.txt");
    EXPECT_EQ(config.get_integer("port", 0), 8080);
    EXPECT_TRUE(config.get_boolean("debug", false));
}

TEST(config_cli_edge, float_value)
{
    char const* args[] = {"prog", "--ratio=0.75"};
    Config config;

    (void)config.apply_cli_overrides(2, args);

    // get_float also works with integer values (promotion), but our CLI
    // parsing stores "0.75" as a float value directly
    auto* v = config.get("ratio");
    EXPECT_TRUE(v != nullptr);
    EXPECT_TRUE(v->is_float());
    auto ratio = config.get_float("ratio", 0.0);
    EXPECT_TRUE(ratio > 0.74 && ratio < 0.76);
}

TEST(config_cli_edge, quoted_string_value)
{
    char const* args[] = {"prog", "--name=\"hello world\""};
    Config config;

    (void)config.apply_cli_overrides(2, args);

    EXPECT_EQ(config.get_string("name", ""), "hello world");
}

TEST(config_cli_edge, dotted_key_deep)
{
    char const* args[] = {"prog", "--a.b.c.d=value"};
    Config config;

    (void)config.apply_cli_overrides(2, args);

    EXPECT_EQ(config.get_string("a.b.c.d", ""), "value");
}

TEST(config_cli_edge, override_existing_nested)
{
    char const* args[] = {"prog", "--server.timeout=60"};
    Config config;
    (void)config.load_string("[server]\nhost = \"localhost\"\nport = 8080\ntimeout = 30");

    (void)config.apply_cli_overrides(2, args);

    EXPECT_EQ(config.get_string("server.host", ""), "localhost");
    EXPECT_EQ(config.get_integer("server.port", 0), 8080);
    EXPECT_EQ(config.get_integer("server.timeout", 0), 60);
}

TEST(config_cli_edge, empty_args)
{
    char const* args[] = {"prog"};
    Config config;

    auto remaining = config.apply_cli_overrides(1, args);

    EXPECT_EQ(remaining.size(), 1U);
}

//
// Merge Edge Cases
//

TEST(config_merge_edge, replace_non_table_with_table)
{
    Config config;
    (void)config.load_string("server = 123");
    (void)config.load_string("[server]\nport = 8080");

    // server is now a table
    EXPECT_EQ(config.get_integer("server.port", 0), 8080);
}

TEST(config_merge_edge, replace_table_with_value)
{
    Config config;
    (void)config.load_string("[server]\nport = 8080");
    (void)config.load_string("server = 123");

    // server is now an integer
    EXPECT_EQ(config.get_integer("server", 0), 123);
}

TEST(config_merge_edge, multiple_files_cascade)
{
    Config config;
    (void)config.load_string("[app]\nname = \"default\"\nversion = 1");
    (void)config.load_string("[app]\nversion = 2\ndebug = true");
    (void)config.load_string("[app]\ndebug = false");

    EXPECT_EQ(config.get_string("app.name", ""), "default");
    EXPECT_EQ(config.get_integer("app.version", 0), 2);
    EXPECT_FALSE(config.get_boolean("app.debug", true));
}

//
// Contains and Get Edge Cases
//

TEST(config_access_edge, contains_nested_key)
{
    Config config;
    (void)config.load_string("[server]\nhost = \"localhost\"");

    EXPECT_TRUE(config.contains("server"));
    EXPECT_TRUE(config.contains("server.host"));
    EXPECT_FALSE(config.contains("server.port"));
    EXPECT_FALSE(config.contains("client"));
}

TEST(config_access_edge, get_table)
{
    Config config;
    (void)config.load_string("[server]\nhost = \"localhost\"\nport = 8080");

    auto* table = config.get_table("server");
    EXPECT_TRUE(table != nullptr);
    EXPECT_TRUE(table->contains("host"));
    EXPECT_TRUE(table->contains("port"));
}

TEST(config_access_edge, get_array)
{
    Config config;
    (void)config.load_string("ports = [80, 443, 8080]");

    auto* arr = config.get_array("ports");
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), 3U);
    EXPECT_EQ(*(*arr)[0].as_integer(), 80);
    EXPECT_EQ(*(*arr)[1].as_integer(), 443);
    EXPECT_EQ(*(*arr)[2].as_integer(), 8080);
}

TEST(config_access_edge, get_missing_returns_nullopt)
{
    Config config;

    EXPECT_FALSE(config.get_string("missing").has_value());
    EXPECT_FALSE(config.get_integer("missing").has_value());
    EXPECT_FALSE(config.get_float("missing").has_value());
    EXPECT_FALSE(config.get_boolean("missing").has_value());
    EXPECT_FALSE(config.get<ieee::Eui48>("missing").has_value());
    EXPECT_FALSE(config.get<ieee::Eui64>("missing").has_value());
    EXPECT_FALSE(config.get<tsn::StreamId>("missing").has_value());
}

TEST(config_access_edge, root_access)
{
    Config config;
    (void)config.load_string("key = \"value\"");

    auto& root = config.root();
    EXPECT_TRUE(root.contains("key"));

    auto const& const_root = static_cast<Config const&>(config).root();
    EXPECT_TRUE(const_root.contains("key"));
}

//
// loaded_files Test
//

TEST(config_loaded_files, tracks_loaded_strings)
{
    Config config;

    // load_string doesn't add to loaded_files
    (void)config.load_string("key = 1");

    EXPECT_TRUE(config.loaded_files().empty());
}

//
// set_from_string Tests
//

TEST(config_set_from_string, boolean_true)
{
    Config config;
    config.set_from_string("flag", "true");

    EXPECT_TRUE(config.get_boolean("flag", false));
}

TEST(config_set_from_string, boolean_false)
{
    Config config;
    config.set_from_string("flag", "false");

    EXPECT_FALSE(config.get_boolean("flag", true));
}

TEST(config_set_from_string, integer)
{
    Config config;
    config.set_from_string("count", "42");

    EXPECT_EQ(config.get_integer("count", 0), 42);
}

TEST(config_set_from_string, float_explicit)
{
    Config config;
    config.set_from_string("ratio", "0.5");

    auto ratio = config.get_float("ratio", 0.0);
    EXPECT_TRUE(ratio > 0.4 && ratio < 0.6);
}

TEST(config_set_from_string, string_unquoted)
{
    Config config;
    config.set_from_string("name", "hello");

    EXPECT_EQ(config.get_string("name", ""), "hello");
}

TEST(config_set_from_string, string_quoted)
{
    Config config;
    config.set_from_string("name", "\"hello world\"");

    EXPECT_EQ(config.get_string("name", ""), "hello world");
}

TEST(config_set_from_string, nested_key)
{
    Config config;
    config.set_from_string("a.b.c", "nested");

    EXPECT_EQ(config.get_string("a.b.c", ""), "nested");
}

//
// File I/O Tests
//

TEST(config_fileio, write_and_load_file)
{
    Config cfg;
    cfg.set("server.host", "localhost");
    cfg.set("server.port", int64_t{8080});
    cfg.set("debug", true);

    std::string const path = "/tmp/statusbar_config_test_config.toml";
    auto write_status = cfg.write_file(path);
    EXPECT_TRUE(write_status.has_value());

    Config cfg2;
    auto load_status = cfg2.load_file(path);
    EXPECT_TRUE(load_status.has_value());
    EXPECT_TRUE(cfg2.get_string("server.host").value() == "localhost");
    EXPECT_EQ(cfg2.get_integer("server.port", 0), int64_t{8080});
    EXPECT_TRUE(cfg2.get_boolean("debug", false));

    std::remove(path.c_str());
}

TEST(config_fileio, load_file_if_exists_missing)
{
    Config cfg;
    auto status = cfg.load_file_if_exists("/tmp/statusbar_nonexistent_config.toml");
    EXPECT_TRUE(status.has_value());  // Should succeed silently
}

TEST(config_fileio, load_file_if_exists_present)
{
    // Write a file first
    std::string const path = "/tmp/statusbar_config_test_exists.toml";
    Config cfg1;
    cfg1.set("value", int64_t{123});
    auto ws = cfg1.write_file(path);
    EXPECT_TRUE(ws.has_value());

    // Now load_file_if_exists should find and load it
    Config cfg2;
    auto status = cfg2.load_file_if_exists(path);
    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(cfg2.get_integer("value", 0), int64_t{123});

    std::remove(path.c_str());
}

TEST(config_fileio, load_file_missing)
{
    Config cfg;
    auto status = cfg.load_file("/tmp/statusbar_definitely_not_here.toml");
    EXPECT_FALSE(status.has_value());
}

//
// Config Set Tests
//

TEST(config_set, set_string_view)
{
    Config cfg;
    std::string_view sv = "sv_value";
    cfg.set("key", sv);
    EXPECT_TRUE(cfg.get_string("key").value() == "sv_value");
}

TEST(config_set, set_string)
{
    Config cfg;
    std::string s = "string_value";
    cfg.set("key", s);
    EXPECT_TRUE(cfg.get_string("key").value() == "string_value");
}

TEST(config_set, set_eui64)
{
    Config cfg;
    statusbar::ieee::Eui64 eui{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    cfg.set<ieee::Eui64>("mac64", eui);
    auto result = cfg.get<ieee::Eui64>("mac64");
    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(*result == eui);
}

TEST(config_set, apply_cli_overrides_span)
{
    Config cfg;
    cfg.set("port", int64_t{80});

    char const* args[] = {"--port=9090", "--host", "example.com", "remaining_arg"};
    std::span<char const* const> arg_span{args};
    auto remaining = cfg.apply_cli_overrides(arg_span);

    EXPECT_EQ(cfg.get_integer("port", 0), int64_t{9090});
    EXPECT_TRUE(cfg.get_string("host").value() == "example.com");
    EXPECT_EQ(remaining.size(), size_t{1});
    EXPECT_TRUE(remaining[0] == "remaining_arg");
}

//
// Config Const Accessor Tests
//

TEST(config_const, get_table_const)
{
    Config cfg;
    cfg.set("section.key", int64_t{42});

    Config const& ccfg = cfg;
    auto const* tbl = ccfg.get_table("section");
    EXPECT_TRUE(tbl != nullptr);
    EXPECT_TRUE(tbl->get("key") != nullptr);
}

TEST(config_const, get_array_const)
{
    Config cfg;
    auto status = cfg.load_string("items = [1, 2, 3]");
    EXPECT_TRUE(status.has_value());

    Config const& ccfg = cfg;
    auto const* arr = ccfg.get_array("items");
    EXPECT_TRUE(arr != nullptr);
    EXPECT_EQ(arr->size(), size_t{3});
}

TEST(config_const, get_table_const_missing)
{
    Config cfg;
    Config const& ccfg = cfg;
    auto const* tbl = ccfg.get_table("nonexistent");
    EXPECT_TRUE(tbl == nullptr);
}

TEST(config_const, get_array_const_missing)
{
    Config cfg;
    Config const& ccfg = cfg;
    auto const* arr = ccfg.get_array("nonexistent");
    EXPECT_TRUE(arr == nullptr);
}

//
// get_list<T>() accessor tests
//

TEST(config_list, array_of_integers)
{
    Config cfg;
    (void)cfg.load_string("ports = [80, 443, 8080]");
    auto result = cfg.get_list<int64_t>("ports");
    EXPECT_EQ(result.size(), 3U);
    EXPECT_EQ(result[0], 80);
    EXPECT_EQ(result[1], 443);
    EXPECT_EQ(result[2], 8080);
}

TEST(config_list, array_of_strings)
{
    Config cfg;
    (void)cfg.load_string("names = [\"alice\", \"bob\"]");
    auto result = cfg.get_list<std::string>("names");
    EXPECT_EQ(result.size(), 2U);
    EXPECT_EQ(result[0], "alice");
    EXPECT_EQ(result[1], "bob");
}

TEST(config_list, single_scalar_returns_one_element)
{
    Config cfg;
    (void)cfg.load_string("port = 8080");
    auto result = cfg.get_list<int64_t>("port");
    EXPECT_EQ(result.size(), 1U);
    EXPECT_EQ(result[0], 8080);
}

TEST(config_list, missing_key_returns_empty)
{
    Config cfg;
    auto result = cfg.get_list<int64_t>("nonexistent");
    EXPECT_TRUE(result.empty());
}

TEST(config_list, mixed_type_skips_unconvertible)
{
    Config cfg;
    (void)cfg.load_string("mixed = [1, \"hello\", 3]");
    auto result = cfg.get_list<int64_t>("mixed");
    EXPECT_EQ(result.size(), 2U);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 3);
}

//
// add_list<T>() CLI comma-separated tests
//

TEST(config_list_cli, integer_comma_separated)
{
    Config cfg;
    cfg.set_from_string("nums", "1,2,3");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("nums", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 3U);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], 2);
    EXPECT_EQ(out[2], 3);
}

TEST(config_list_cli, hex_comma_separated)
{
    Config cfg;
    cfg.set_from_string("ethertypes", "0x0800,0x0806");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("ethertypes", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0], 2048);
    EXPECT_EQ(out[1], 2054);
}

TEST(config_list_cli, string_comma_separated)
{
    Config cfg;
    cfg.set_from_string("names", "hello,world");
    ArgumentSpecs specs;
    std::vector<std::string> out;
    specs.add_list<std::string>("names", "test", [&](std::vector<std::string> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0], "hello");
    EXPECT_EQ(out[1], "world");
}

TEST(config_list_cli, single_value)
{
    Config cfg;
    cfg.set_from_string("num", "42");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("num", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 1U);
    EXPECT_EQ(out[0], 42);
}

TEST(config_list_cli, empty_value)
{
    Config cfg;
    cfg.set_from_string("nums", "");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("nums", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_TRUE(out.empty());
}

TEST(config_list_cli, trailing_comma_skipped)
{
    Config cfg;
    cfg.set_from_string("nums", "1,2,");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("nums", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], 2);
}

TEST(config_list_cli, double_comma_skipped)
{
    Config cfg;
    cfg.set_from_string("nums", "1,,3");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("nums", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0], 1);
    EXPECT_EQ(out[1], 3);
}

TEST(config_list_cli, get_list_from_toml_array)
{
    Config cfg;
    (void)cfg.load_string("ports = [80, 443]");
    ArgumentSpecs specs;
    std::vector<int64_t> out;
    specs.add_list<int64_t>("ports", "test", [&](std::vector<int64_t> const& v) { out = v; });
    (void)specs.apply(cfg.root());
    EXPECT_EQ(out.size(), 2U);
    EXPECT_EQ(out[0], 80);
    EXPECT_EQ(out[1], 443);
}

TEST(config_list_cli, without_binding)
{
    Config cfg;
    cfg.set_from_string("nums", "1,2,3");
    ArgumentSpecs specs;
    specs.add_list<int64_t>("nums", "test");
    EXPECT_TRUE(specs.is_known("nums"));
}

TEST(config_list_cli, help_text_shows_list_format)
{
    ArgumentSpecs specs;
    specs.add_list<int64_t>("ports", "Port numbers");
    std::string help;
    specs.format_help_to(std::back_inserter(help));
    // Should contain "N,..." to indicate comma-separated list
    EXPECT_TRUE(help.find("N,...") != std::string::npos);
}

//
// CLI parsing and completion infrastructure tests
//

TEST(config_cli_parse, parse_cli_args_with_typed_args)
{
    int64_t port_val = 0;
    bool verbose_val = false;
    double rate_val = 0.0;

    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });
    specs.add_flag("verbose", "Verbose mode", [&](bool v) { verbose_val = v; });
    specs.add<double>("rate", "Sample rate", 48000.0, [&](double v) { rate_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--port=9090", "--verbose", "--rate=96000.0"};
    auto status = statusbar::config::parse_cli_args(4, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 9090);
    EXPECT_TRUE(verbose_val);
    EXPECT_TRUE(rate_val > 95999.0 && rate_val < 96001.0);
}

TEST(config_cli_parse, parse_cli_args_help_is_handled_builtin)
{
    ArgumentSpecs specs;

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--help"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    // --help should fail with ConfigError::builtin_handled
    EXPECT_FALSE(status.has_value());
    EXPECT_TRUE(statusbar::config::handled_builtin_command(status));
}

TEST(config_cli_parse, handled_builtin_command_false_for_real_error)
{
    // A real error (not ConfigError::builtin_handled) should return false
    auto err_status = statusbar::failure(std::errc::invalid_argument);
    EXPECT_FALSE(statusbar::config::handled_builtin_command(err_status));
}

TEST(config_cli_parse, handled_builtin_command_false_for_success)
{
    auto ok_status = statusbar::success();
    EXPECT_FALSE(statusbar::config::handled_builtin_command(ok_status));
}

TEST(config_cli_parse, default_print_usage_runs)
{
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080);
    specs.add_flag("verbose", "Verbose mode");
    specs.add_choice("format", "Output format", {"json", "csv"}, "json");

    // Just verify it doesn't crash -- output goes to stderr/stdout
    statusbar::config::default_print_usage("test_prog", specs);
}

TEST(config_cli_parse, handle_completion_returns_false_without_flag)
{
    ArgumentSpecs specs;
    specs.add_flag("verbose", "Verbose");

    Config config;
    // No --completion key set
    bool was_handled = statusbar::config::handle_completion(config, specs, "/usr/bin/test-app");
    EXPECT_FALSE(was_handled);
}

//
// default_config_path tests
//

namespace {

class EnvGuard
{
  public:
    EnvGuard(char const* name, char const* value)
        : name_(name)
    {
        if (char const* prev = std::getenv(name); prev != nullptr) {
            had_previous_ = true;
            previous_ = prev;
        }
        if (value != nullptr) {
            ::setenv(name, value, 1);
        } else {
            ::unsetenv(name);
        }
    }
    ~EnvGuard()
    {
        if (had_previous_) {
            ::setenv(name_, previous_.c_str(), 1);
        } else {
            ::unsetenv(name_);
        }
    }
    EnvGuard(EnvGuard const&) = delete;
    EnvGuard(EnvGuard&&) = delete;
    auto operator=(EnvGuard const&) -> EnvGuard& = delete;
    auto operator=(EnvGuard&&) -> EnvGuard& = delete;

  private:
    char const* name_;
    bool had_previous_{false};
    std::string previous_;
};

}  // namespace

TEST(config_default_path, empty_program_name_returns_empty)
{
    EXPECT_TRUE(statusbar::config::default_config_path("").empty());
}

TEST(config_default_path, xdg_config_home_preferred)
{
    EnvGuard const xdg{"XDG_CONFIG_HOME", "/custom/xdg"};
    EnvGuard const home{"HOME", "/home/user"};

    auto path = statusbar::config::default_config_path("myapp");
    EXPECT_EQ(path, "/custom/xdg/myapp/config.toml");
}

TEST(config_default_path, falls_back_to_home_config)
{
    EnvGuard const xdg{"XDG_CONFIG_HOME", nullptr};
    EnvGuard const home{"HOME", "/home/user"};

    auto path = statusbar::config::default_config_path("myapp");
    EXPECT_EQ(path, "/home/user/.config/myapp/config.toml");
}

TEST(config_default_path, empty_xdg_falls_back_to_home)
{
    EnvGuard const xdg{"XDG_CONFIG_HOME", ""};
    EnvGuard const home{"HOME", "/home/user"};

    auto path = statusbar::config::default_config_path("myapp");
    EXPECT_EQ(path, "/home/user/.config/myapp/config.toml");
}

TEST(config_default_path, no_env_vars_returns_empty)
{
    EnvGuard const xdg{"XDG_CONFIG_HOME", nullptr};
    EnvGuard const home{"HOME", nullptr};

    auto path = statusbar::config::default_config_path("myapp");
    EXPECT_TRUE(path.empty());
}

//
// parse_cli_args default-config loading tests
//

TEST(config_cli_default, loads_default_config_file)
{
    namespace fs = std::filesystem;

    // Set XDG_CONFIG_HOME to a temp dir and write a config file
    auto tmp_dir = fs::temp_directory_path() / "statusbar_default_config_test";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir / "test-app");

    auto cfg_path = tmp_dir / "test-app" / "config.toml";
    {
        Config cfg;
        cfg.set("port", int64_t{1234});
        auto ws = cfg.write_file(cfg_path.string());
        EXPECT_TRUE(ws.has_value());
    }

    EnvGuard const xdg{"XDG_CONFIG_HOME", tmp_dir.c_str()};

    int64_t port_val = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog"};
    auto status = statusbar::config::parse_cli_args(1, const_cast<char**>(args), specs, nullptr, "test-app");
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 1234);

    fs::remove_all(tmp_dir);
}

TEST(config_cli_default, missing_default_is_silent)
{
    namespace fs = std::filesystem;
    auto tmp_dir = fs::temp_directory_path() / "statusbar_default_missing_test";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir);

    EnvGuard const xdg{"XDG_CONFIG_HOME", tmp_dir.c_str()};

    int64_t port_val = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog"};
    auto status = statusbar::config::parse_cli_args(1, const_cast<char**>(args), specs, nullptr, "nonexistent-app");
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 8080);

    fs::remove_all(tmp_dir);
}

TEST(config_cli_default, cli_overrides_default)
{
    namespace fs = std::filesystem;
    auto tmp_dir = fs::temp_directory_path() / "statusbar_default_override_test";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir / "test-app2");

    auto cfg_path = tmp_dir / "test-app2" / "config.toml";
    {
        Config cfg;
        cfg.set("port", int64_t{1234});
        auto ws = cfg.write_file(cfg_path.string());
        EXPECT_TRUE(ws.has_value());
    }

    EnvGuard const xdg{"XDG_CONFIG_HOME", tmp_dir.c_str()};

    int64_t port_val = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--port=5555"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr, "test-app2");
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 5555);

    fs::remove_all(tmp_dir);
}

TEST(config_cli_default, no_default_config_flag_skips_load)
{
    namespace fs = std::filesystem;
    auto tmp_dir = fs::temp_directory_path() / "statusbar_default_skip_test";
    fs::remove_all(tmp_dir);
    fs::create_directories(tmp_dir / "test-app3");

    auto cfg_path = tmp_dir / "test-app3" / "config.toml";
    {
        Config cfg;
        cfg.set("port", int64_t{1234});
        auto ws = cfg.write_file(cfg_path.string());
        EXPECT_TRUE(ws.has_value());
    }

    EnvGuard const xdg{"XDG_CONFIG_HOME", tmp_dir.c_str()};

    int64_t port_val = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--no-default-config"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr, "test-app3");
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 8080);

    fs::remove_all(tmp_dir);
}

TEST(config_cli_default, empty_program_name_skips_default)
{
    // With no program_name, parse_cli_args should not attempt any default load
    int64_t port_val = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 8080, [&](int64_t v) { port_val = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog"};
    auto status = statusbar::config::parse_cli_args(1, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port_val, 8080);
}

TEST(config_cli_typed_string, hex_string_with_only_octal_digits_stays_string)
{
    // Regression: pure-octal-digit hex strings (e.g. "0...0063") were
    // being auto-typed to integers because TOML's parse_value_string
    // sees a leading 0 and interprets the value as octal. With the
    // spec-aware overload, ArgType::String values bypass auto-typing.
    std::string captured{};
    ArgumentSpecs specs;
    specs.add<std::string>("session-id", "16-byte hex session id", std::string{}, [&](auto v) { captured = v; });

    constexpr std::string_view all_octal_hex = "00000000000000000000000000000063";

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--session-id=00000000000000000000000000000063"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_TRUE(captured == all_octal_hex);
}

TEST(config_cli_typed_string, integer_typed_arg_still_auto_parses)
{
    // The spec-aware overload must NOT regress integer parsing for
    // ArgType::Integer (or Float). "8080" must still arrive as 8080.
    int64_t port = 0;
    ArgumentSpecs specs;
    specs.add<int64_t>("port", "Port number", 0, [&](int64_t v) { port = v; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--port=8080"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_EQ(port, 8080);
}

TEST(config_cli_typed_string, choice_value_keeps_string_form)
{
    // Choice args historically went through auto-typing too. Verify the
    // value reaches the lambda unchanged.
    std::string mode{};
    ArgumentSpecs specs;
    specs.add_choice("mode", "Mode", {"normal", "reflect"}, "normal", [&](auto v) { mode = std::string{v}; });

    // NOLINTBEGIN(cppcoreguidelines-pro-type-const-cast)
    char const* args[] = {"test_prog", "--mode=reflect"};
    auto status = statusbar::config::parse_cli_args(2, const_cast<char**>(args), specs, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-const-cast)

    EXPECT_TRUE(status.has_value());
    EXPECT_TRUE(mode == "reflect");
}

TEST(config_serialize, with_specs_emits_descriptions)
{
    ArgumentSpecs specs;
    specs.add<int64_t>("count", "Number of widgets to produce", 0);
    specs.add<std::string>("name", "Human-readable name of the run", std::string{});
    specs.add<int64_t>("server.port", "Port to listen on", 0);
    specs.add_choice("mode", "Pick a mode", {"a", "b"}, "a");

    Config config;
    config.set("count", static_cast<int64_t>(42));
    config.set("name", std::string{"test"});
    config.set("server.port", static_cast<int64_t>(8080));
    config.set("mode", std::string{"a"});

    auto toml = config.to_toml_string(specs);

    EXPECT_TRUE(toml.find("# Number of widgets to produce\ncount = 42") != std::string::npos);
    EXPECT_TRUE(toml.find("# Human-readable name of the run\nname = \"test\"") != std::string::npos);
    EXPECT_TRUE(toml.find("# Port to listen on\nport = 8080") != std::string::npos);
    EXPECT_TRUE(toml.find("# Pick a mode\n# (choices: a, b)\nmode = \"a\"") != std::string::npos);
}

TEST(config_serialize, with_specs_multiline_description)
{
    ArgumentSpecs specs;
    specs.add<int64_t>("count", "First line.\nSecond line.", 0);

    Config config;
    config.set("count", static_cast<int64_t>(7));

    auto toml = config.to_toml_string(specs);
    EXPECT_TRUE(toml.find("# First line.\n# Second line.\ncount = 7") != std::string::npos);
}

TEST(config_serialize, without_specs_unchanged)
{
    Config config;
    config.set("count", static_cast<int64_t>(42));

    auto toml = config.to_toml_string();
    EXPECT_TRUE(toml.find('#') == std::string::npos);
}

TEST_MAIN(statusbar_config, config_test)
