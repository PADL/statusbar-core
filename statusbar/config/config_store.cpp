// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/config/config_store.hpp"

#include "statusbar/status/status.hpp"
#include "statusbar/toml/toml_error.hpp"
#include "statusbar/toml/toml_parser.hpp"
#include "statusbar/toml/toml_value.hpp"

#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace statusbar::config {

auto Config::load_file(std::string_view path) -> Status
{
    auto result = toml::parse_file(path);
    if (!result) {
        return forward_failure(result);
    }
    merge_table(root_, *result);
    loaded_files_.emplace_back(path);
    return success();
}

auto Config::load_file_if_exists(std::string_view path) -> Status
{
    if (!std::filesystem::exists(path)) {
        return success();
    }
    return load_file(path);
}

auto Config::load_string(std::string_view toml) -> Status
{
    auto result = toml::parse(toml);
    if (!result) {
        return forward_failure(result);
    }
    merge_table(root_, *result);
    return success();
}

auto Config::apply_cli_overrides(int argc, char const* const* argv) -> std::vector<std::string>
{
    std::vector<std::string> remaining;

    for (int i = 0; i < argc; ++i) {
        std::string_view arg{argv[i]};

        // Check for -- or - prefix
        if (arg.starts_with("--")) {
            arg = arg.substr(2);
        } else if (arg.starts_with("-") && arg.size() > 1 && std::isdigit(static_cast<unsigned char>(arg[1])) == 0) {
            arg = arg.substr(1);
        } else {
            remaining.emplace_back(arg);
            continue;
        }

        // Find = sign
        size_t const eq = arg.find('=');
        std::string key;
        std::string value_str;

        if (eq != std::string_view::npos) {
            key = std::string{arg.substr(0, eq)};
            value_str = std::string{arg.substr(eq + 1)};
        } else {
            key = std::string{arg};
            // Check if next arg is the value
            if (i + 1 < argc) {
                std::string_view const next{argv[i + 1]};
                if (!next.starts_with("-") || (next.size() > 1 && std::isdigit(static_cast<unsigned char>(next[1])) != 0)) {
                    value_str = std::string{next};
                    ++i;
                } else {
                    // Boolean flag with no value - set to true
                    value_str = "true";
                }
            } else {
                // Boolean flag at end - set to true
                value_str = "true";
            }
        }

        // Handle special --config argument to load additional files
        if (key == "config") {
            (void)load_file(value_str);
            continue;
        }

        // Parse the value and set it
        set_from_string(key, value_str);
    }

    return remaining;
}

auto Config::apply_cli_overrides(std::span<char const* const> args) -> std::vector<std::string>
{
    return apply_cli_overrides(static_cast<int>(args.size()), args.data());
}

namespace {

[[nodiscard]] auto find_spec_type(args::ArgumentSpecs const& specs, std::string_view key) -> std::optional<args::ArgType>
{
    for (auto const& s : specs.specs()) {
        if (s.name == key) {
            return s.type;
        }
    }
    return std::nullopt;
}

}  // namespace

auto Config::apply_cli_overrides(int argc, char const* const* argv, args::ArgumentSpecs const& specs) -> std::vector<std::string>
{
    std::vector<std::string> remaining;

    for (int i = 0; i < argc; ++i) {
        std::string_view arg{argv[i]};

        if (arg.starts_with("--")) {
            arg = arg.substr(2);
        } else if (arg.starts_with("-") && arg.size() > 1 && std::isdigit(static_cast<unsigned char>(arg[1])) == 0) {
            arg = arg.substr(1);
        } else {
            remaining.emplace_back(arg);
            continue;
        }

        size_t const eq = arg.find('=');
        std::string key;
        std::string value_str;

        if (eq != std::string_view::npos) {
            key = std::string{arg.substr(0, eq)};
            value_str = std::string{arg.substr(eq + 1)};
        } else {
            key = std::string{arg};
            if (i + 1 < argc) {
                std::string_view const next{argv[i + 1]};
                if (!next.starts_with("-") || (next.size() > 1 && std::isdigit(static_cast<unsigned char>(next[1])) != 0)) {
                    value_str = std::string{next};
                    ++i;
                } else {
                    value_str = "true";
                }
            } else {
                value_str = "true";
            }
        }

        if (key == "config") {
            (void)load_file(value_str);
            continue;
        }

        auto const type = find_spec_type(specs, key);
        if (type.has_value() && args::is_string_shaped(*type)) {
            set_string(key, value_str);
        } else {
            set_from_string(key, value_str);
        }
    }

    return remaining;
}

namespace {

void set_value_at(toml::Table& root, std::string_view key, toml::Value value)
{
    size_t const dot = key.rfind('.');
    if (dot != std::string_view::npos) {
        toml::Table* parent = root.get_or_create_table(key.substr(0, dot));
        if (parent != nullptr) {
            parent->set(std::string{key.substr(dot + 1)}, std::move(value));
        }
        return;
    }
    root.set(std::string{key}, std::move(value));
}

}  // namespace

void Config::set_from_string(std::string_view key, std::string_view value_str)
{
    set_value_at(root_, key, parse_value_string(value_str));
}

void Config::set_string(std::string_view key, std::string_view value_str)
{
    set_value_at(root_, key, toml::Value{std::string{value_str}});
}

auto Config::get_value_as_string(std::string_view key) const -> std::optional<std::string>
{
    if (auto const* v = get(key); v != nullptr) {
        // If it's already a string, return it
        if (auto str = v->as_string(); str.has_value()) {
            return std::string{*str};
        }
        // If it's an integer, convert to string
        if (auto int_val = v->as_integer(); int_val.has_value()) {
            return std::to_string(*int_val);
        }
        // If it's a float, convert to string
        if (auto float_val = v->as_float(); float_val.has_value()) {
            return std::to_string(*float_val);
        }
        // If it's a boolean, return "true" or "false"
        if (auto bool_val = v->as_boolean(); bool_val.has_value()) {
            return *bool_val ? "true" : "false";
        }
    }
    return std::nullopt;
}

auto Config::get_value_as_string(std::string_view key, std::string_view default_value) const -> std::string
{
    return get_value_as_string(key).value_or(std::string{default_value});
}

auto Config::write_file(std::string_view path) const -> Status
{
    std::ofstream file{std::string{path}};
    if (!file.is_open()) {
        return failure(toml::TomlError::file_not_found);
    }

    write_table(file, root_, "");
    return success();
}

auto Config::write_file(std::string_view path, args::ArgumentSpecs const& specs) const -> Status
{
    std::ofstream file{std::string{path}};
    if (!file.is_open()) {
        return failure(toml::TomlError::file_not_found);
    }

    write_table(file, root_, "", &specs);
    return success();
}

auto Config::to_toml_string() const -> std::string
{
    std::ostringstream ss;
    write_table(ss, root_, "");
    return ss.str();
}

auto Config::to_toml_string(args::ArgumentSpecs const& specs) const -> std::string
{
    std::ostringstream ss;
    write_table(ss, root_, "", &specs);
    return ss.str();
}

void Config::set_value(std::string_view key, toml::Value value)
{
    size_t const dot = key.rfind('.');
    if (dot != std::string_view::npos) {
        toml::Table* parent = root_.get_or_create_table(key.substr(0, dot));
        if (parent != nullptr) {
            parent->set(std::string{key.substr(dot + 1)}, std::move(value));
        }
    } else {
        root_.set(std::string{key}, std::move(value));
    }
}

void Config::merge_table(toml::Table& dest, toml::Table const& source)
{
    for (auto const& [key, value] : source) {
        if (value.is_table()) {
            // Recursively merge tables
            auto* dest_val = dest.get(key);
            if (dest_val != nullptr && dest_val->is_table()) {
                merge_table(*dest_val->as_table(), *value.as_table());
            } else {
                // Replace with new table
                dest.set(key, value);
            }
        } else {
            // Replace value
            dest.set(key, value);
        }
    }
}

void Config::write_value(std::ostream& out, toml::Value const& value)
{
    if (auto const str = value.as_string(); str.has_value()) {
        // Escape string properly
        out << '"';
        for (char const c : *str) {
            switch (c) {
                case '"':
                    out << "\\\"";
                    break;
                case '\\':
                    out << "\\\\";
                    break;
                case '\n':
                    out << "\\n";
                    break;
                case '\r':
                    out << "\\r";
                    break;
                case '\t':
                    out << "\\t";
                    break;
                case '\b':
                    out << "\\b";
                    break;
                case '\f':
                    out << "\\f";
                    break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) {
                        // TOML spec requires control characters to be escaped as \uXXXX
                        out << "\\u" << std::format("{:04x}", static_cast<unsigned int>(static_cast<unsigned char>(c)));
                    } else {
                        out << c;
                    }
                    break;
            }
        }
        out << '"';
    } else if (auto const i = value.as_integer(); i.has_value()) {
        out << *i;
    } else if (auto const f = value.as_float(); f.has_value()) {
        out << *f;
    } else if (auto const b = value.as_boolean(); b.has_value()) {
        out << (*b ? "true" : "false");
    } else if (auto const* arr = value.as_array(); arr != nullptr) {
        out << '[';
        for (size_t i = 0; i < arr->size(); ++i) {
            if (i > 0) {
                out << ", ";
            }
            write_value(out, (*arr)[i]);
        }
        out << ']';
    } else if (auto const* tbl = value.as_table(); tbl != nullptr) {
        // Inline table
        out << '{';
        bool first = true;
        for (auto const& [key, val] : *tbl) {
            if (!first) {
                out << ", ";
            }
            first = false;
            out << key << " = ";
            write_value(out, val);
        }
        out << '}';
    }
}

namespace {

[[nodiscard]] auto find_spec_by_name(args::ArgumentSpecs const& specs, std::string_view full_key) -> args::ArgumentSpec const*
{
    for (auto const& s : specs.specs()) {
        if (s.name == full_key) {
            return &s;
        }
    }
    return nullptr;
}

void emit_description_comment(std::ostream& out, std::string_view full_key, args::ArgumentSpecs const* specs)
{
    if (specs == nullptr) {
        return;
    }
    auto const* spec = find_spec_by_name(*specs, full_key);
    if (spec == nullptr || spec->description.empty()) {
        return;
    }
    out << '\n';
    std::string_view const desc{spec->description};
    size_t start = 0;
    while (start <= desc.size()) {
        size_t const end = desc.find('\n', start);
        size_t const stop = (end == std::string_view::npos) ? desc.size() : end;
        out << "# " << desc.substr(start, stop - start) << '\n';
        if (end == std::string_view::npos) {
            break;
        }
        start = end + 1;
    }
    if (spec->type == args::ArgType::Choice && !spec->choices.empty()) {
        out << "# (choices:";
        for (size_t i = 0; i < spec->choices.size(); ++i) {
            out << (i == 0 ? " " : ", ") << spec->choices[i];
        }
        out << ")\n";
    }
}

}  // namespace

void Config::write_table(std::ostream& out, toml::Table const& table, std::string_view prefix, args::ArgumentSpecs const* specs)
{
    // The root table (empty prefix) has no header; every nested table emits
    // its own `[dotted.key]` header before its values, so arbitrarily deep
    // tables serialize completely.
    if (!prefix.empty()) {
        out << '\n';
        out << '[' << prefix << ']' << '\n';
    }

    // First write this table's non-table values
    for (auto const& [key, value] : table) {
        if (!value.is_table()) {
            std::string const full_key = prefix.empty() ? key : std::string{prefix} + "." + key;
            emit_description_comment(out, full_key, specs);
            out << key << " = ";
            write_value(out, value);
            out << '\n';
        }
    }

    // Then recurse into nested tables
    for (auto const& [key, value] : table) {
        if (value.is_table()) {
            std::string const full_key = prefix.empty() ? key : std::string{prefix} + "." + key;
            write_table(out, *value.as_table(), full_key, specs);
        }
    }
}

}  // namespace statusbar::config
