// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/toml/toml_value.hpp"

#include "statusbar/status/throw_or_abort.hpp"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

namespace statusbar::toml {

//
// Array implementation
//

Array::Array(Array const& other)
{
    for (auto const& v : other.values_) {
        values_.push_back(std::make_unique<Value>(*v));
    }
}

auto Array::operator=(Array const& other) -> Array&
{
    if (this != &other) {
        values_.clear();
        for (auto const& v : other.values_) {
            values_.push_back(std::make_unique<Value>(*v));
        }
    }
    return *this;
}

auto Array::push_back(Value value) -> void
{
    values_.push_back(std::make_unique<Value>(std::move(value)));
}

auto Array::operator[](size_t index) -> Value&
{
    if (index >= values_.size()) {
        throw_or_abort(TomlError::index_out_of_range);
    }
    return *values_[index];
}

auto Array::operator[](size_t index) const -> Value const&
{
    if (index >= values_.size()) {
        throw_or_abort(TomlError::index_out_of_range);
    }
    return *values_[index];
}

auto Array::at(size_t index) -> StatusValue<Value*>
{
    if (index >= values_.size()) {
        return failure(TomlError::index_out_of_range);
    }
    return success(values_[index].get());
}

auto Array::at(size_t index) const -> StatusValue<Value const*>
{
    if (index >= values_.size()) {
        return failure(TomlError::index_out_of_range);
    }
    return success(values_[index].get());
}

//
// Table implementation
//

Table::Table(Table const& other)
{
    for (auto const& [key, value] : other.values_) {
        values_.emplace(key, std::make_unique<Value>(*value));
    }
}

auto Table::operator=(Table const& other) -> Table&
{
    if (this != &other) {
        values_.clear();
        for (auto const& [key, value] : other.values_) {
            values_.emplace(key, std::make_unique<Value>(*value));
        }
    }
    return *this;
}

auto Table::set(std::string key, Value value) -> void
{
    values_.insert_or_assign(std::move(key), std::make_unique<Value>(std::move(value)));
}

auto Table::contains(std::string_view key) const -> bool
{
    return values_.contains(key);
}

auto Table::get(std::string_view key) -> Value*
{
    auto it = values_.find(key);
    return it != values_.end() ? it->second.get() : nullptr;
}

auto Table::get(std::string_view key) const -> Value const*
{
    auto it = values_.find(key);
    return it != values_.end() ? it->second.get() : nullptr;
}

auto Table::get_path(std::string_view path) -> Value*
{
    size_t const dot = path.find('.');
    if (dot == std::string_view::npos) {
        return get(path);
    }

    std::string_view const first = path.substr(0, dot);
    std::string_view const rest = path.substr(dot + 1);

    Value* v = get(first);
    if (v == nullptr) {
        return nullptr;
    }

    Table* t = v->as_table();
    if (t == nullptr) {
        return nullptr;
    }

    return t->get_path(rest);
}

auto Table::get_path(std::string_view path) const -> Value const*
{
    return const_cast<Table*>(this)->get_path(path);
}

auto Table::get_path(std::span<std::string const> segments) -> Value*
{
    if (segments.empty()) {
        return nullptr;
    }
    Table* current = this;
    for (auto const& segment : segments.first(segments.size() - 1)) {
        Value* v = current->get(segment);
        if (v == nullptr) {
            return nullptr;
        }
        current = v->as_table();
        if (current == nullptr) {
            return nullptr;
        }
    }
    return current->get(segments.back());
}

auto Table::get_path(std::span<std::string const> segments) const -> Value const*
{
    return const_cast<Table*>(this)->get_path(segments);
}

auto Table::get_or_create_table(std::string_view path) -> Table*
{
    // Iterative walk over dotted segments. The previous implementation
    // recursed once per segment, which would blow the stack on a key path
    // like `a.a.a.a.…` (attacker-controlled TOML config files). Iteration
    // is bounded by path length.
    Table* current = this;
    while (true) {
        size_t const dot = path.find('.');
        std::string_view const first = (dot == std::string_view::npos) ? path : path.substr(0, dot);

        Value* v = current->get(first);
        if (v == nullptr) {
            current->set(std::string{first}, Table{});
            v = current->get(first);
        }

        Table* t = v->as_table();
        if (t == nullptr) {
            return nullptr;  // Key exists but is not a table
        }

        if (dot == std::string_view::npos) {
            return t;
        }
        current = t;
        path = path.substr(dot + 1);
    }
}

auto Table::get_or_create_table(std::span<std::string const> segments) -> Table*
{
    // The segmented form of the walk above. The parser uses this one, so a
    // segment keeps whatever characters it was quoted with -- a dot in a
    // segment is part of the key, not another level.
    Table* current = this;
    for (auto const& segment : segments) {
        Value* v = current->get(segment);
        if (v == nullptr) {
            current->set(segment, Table{});
            v = current->get(segment);
        }
        Table* t = v->as_table();
        if (t == nullptr) {
            return nullptr;  // Key exists but is not a table
        }
        current = t;
    }
    return current;
}

//
// Free function: parse_value_string
//

auto parse_value_string(std::string_view s) -> Value
{
    // Try boolean
    if (s == "true") {
        return Value{true};
    }
    if (s == "false") {
        return Value{false};
    }

    // Try integer (auto-detect base: decimal, 0x hex, 0o octal, 0b binary)
    // strtoll with base 0 handles 0x, 0 (octal), and decimal automatically.
    // We also handle 0o and 0b prefixes manually since strtoll doesn't support them.
    if (!s.empty() && (std::isdigit(static_cast<unsigned char>(s[0])) != 0 || s[0] == '-' || s[0] == '+')) {
        std::string const str{s};
        char* end = nullptr;  // NOLINT(misc-const-correctness) - modified by strtoll
        int base = 0;
        char const* start = str.c_str();

        // Handle 0o (octal) and 0b (binary) prefixes that strtoll doesn't support
        if (str.size() > 2 && str[0] == '0') {
            if (str[1] == 'o' || str[1] == 'O') {
                base = 8;
                start = str.c_str() + 2;
            } else if (str[1] == 'b' || str[1] == 'B') {
                base = 2;
                start = str.c_str() + 2;
            }
        }

        errno = 0;
        int64_t const int_val = std::strtoll(start, &end, base);
        if (errno == 0 && end == str.c_str() + str.size() && end != start) {
            return Value{int_val};
        }
    }

    // Try float
    if (s.contains('.') || s.contains('e') || s.contains('E')) {
        std::string const str{s};
        char* end = nullptr;
        double const float_val = std::strtod(str.c_str(), &end);
        if (end == str.c_str() + str.size()) {
            return Value{float_val};
        }
    }

    // Default to string (remove quotes if present)
    if ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        return Value{std::string{s.substr(1, s.size() - 2)}};
    }

    return Value{std::string{s}};
}

}  // namespace statusbar::toml
