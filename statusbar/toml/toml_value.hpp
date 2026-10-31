#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TOML Value types
/// Represents TOML values: string, integer, float, boolean, datetime, array, table

#include "statusbar/status/status.hpp"
#include "statusbar/toml/toml_error.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace statusbar::toml {

/// TOML datetime (simplified - stores as string for now)
struct DateTime
{
    std::string value;  // ISO 8601 format string

    auto operator==(DateTime const&) const -> bool = default;
};

// Forward declare Value for use in containers
class Value;

/// TOML Array - ordered collection of values
/// Uses unique_ptr<Value> to break circular dependency
class Array
{
  public:
    Array() = default;
    ~Array() = default;

    // Copy constructor (deep copy)
    Array(Array const& other);
    auto operator=(Array const& other) -> Array&;

    // Move constructor
    Array(Array&&) noexcept = default;
    auto operator=(Array&&) noexcept -> Array& = default;

    auto push_back(Value value) -> void;

    [[nodiscard]] auto size() const noexcept -> size_t { return values_.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return values_.empty(); }

    [[nodiscard]] auto operator[](size_t index) -> Value&;
    [[nodiscard]] auto operator[](size_t index) const -> Value const&;

    [[nodiscard]] auto at(size_t index) -> StatusValue<Value*>;
    [[nodiscard]] auto at(size_t index) const -> StatusValue<Value const*>;

  private:
    std::vector<std::unique_ptr<Value>> values_;
};

/// TOML Table - key-value mapping
/// Uses unique_ptr<Value> to break circular dependency
class Table
{
  public:
    Table() = default;
    ~Table() = default;

    // Copy constructor (deep copy)
    Table(Table const& other);
    auto operator=(Table const& other) -> Table&;

    // Move constructor
    Table(Table&&) noexcept = default;
    auto operator=(Table&&) noexcept -> Table& = default;

    /// Insert or update a value
    /// @param key The key to insert or update
    /// @param value The value to set
    auto set(std::string key, Value value) -> void;

    /// Check if key exists
    /// @param key The key to look up
    [[nodiscard]] auto contains(std::string_view key) const -> bool;

    /// Get value by key (returns nullptr if not found)
    /// @param key The key to look up
    [[nodiscard]] auto get(std::string_view key) -> Value*;
    /// @param key The key to look up
    [[nodiscard]] auto get(std::string_view key) const -> Value const*;

    /// Get value by dotted key path (e.g., "server.host").
    /// Every dot is a separator, so this cannot address a key that
    /// contains one — `[port."eth0.100"]` names a single key `eth0.100`,
    /// and only the span overload below can reach it.
    /// @param path Dotted key path to look up
    [[nodiscard]] auto get_path(std::string_view path) -> Value*;
    /// @param path Dotted key path to look up
    [[nodiscard]] auto get_path(std::string_view path) const -> Value const*;

    /// Get value by an already-split key path, one segment per level.
    /// A segment is a key in full, dots and all, which is what the parser
    /// produces for a quoted key.
    /// @param segments One key per level; an empty span finds nothing
    [[nodiscard]] auto get_path(std::span<std::string const> segments) -> Value*;
    /// @param segments One key per level
    [[nodiscard]] auto get_path(std::span<std::string const> segments) const -> Value const*;

    /// Get or create nested table for key path
    /// @param path Dotted key path to navigate or create
    [[nodiscard]] auto get_or_create_table(std::string_view path) -> Table*;

    /// Get or create a nested table from an already-split key path.
    /// @param segments One key per level; an empty span is this table
    /// @return The table, or nullptr if a segment exists and is not a table
    [[nodiscard]] auto get_or_create_table(std::span<std::string const> segments) -> Table*;

    [[nodiscard]] auto size() const noexcept -> size_t { return values_.size(); }
    [[nodiscard]] auto empty() const noexcept -> bool { return values_.empty(); }

    /// Erase a key from the table
    /// @param key The key to erase
    /// @return true if the key was found and erased, false if key didn't exist
    auto erase(std::string_view key) -> bool { return values_.erase(std::string{key}) > 0; }

    /// Iteration support
    class Iterator
    {
      public:
        using MapIt = std::map<std::string, std::unique_ptr<Value>, std::less<>>::iterator;

        Iterator(MapIt it)
            : it_{it}
        {}

        auto operator++() -> Iterator&
        {
            ++it_;
            return *this;
        }

        auto operator*() -> std::pair<std::string const&, Value&> { return {it_->first, *it_->second}; }

        auto operator!=(Iterator const& other) const -> bool { return it_ != other.it_; }

      private:
        MapIt it_;
    };

    class ConstIterator
    {
      public:
        using MapIt = std::map<std::string, std::unique_ptr<Value>, std::less<>>::const_iterator;

        ConstIterator(MapIt it)
            : it_{it}
        {}

        auto operator++() -> ConstIterator&
        {
            ++it_;
            return *this;
        }

        auto operator*() const -> std::pair<std::string const&, Value const&> { return {it_->first, *it_->second}; }

        auto operator!=(ConstIterator const& other) const -> bool { return it_ != other.it_; }

      private:
        MapIt it_;
    };

    [[nodiscard]] auto begin() noexcept -> Iterator { return Iterator{values_.begin()}; }
    [[nodiscard]] auto end() noexcept -> Iterator { return Iterator{values_.end()}; }
    [[nodiscard]] auto begin() const noexcept -> ConstIterator { return ConstIterator{values_.begin()}; }
    [[nodiscard]] auto end() const noexcept -> ConstIterator { return ConstIterator{values_.end()}; }

  private:
    std::map<std::string, std::unique_ptr<Value>, std::less<>> values_;
};

/// TOML Value - variant holding any TOML type
class Value
{
  public:
    /// Value types
    enum class Type
    {
        null,
        string,
        integer,
        floating,
        boolean,
        datetime,
        array,
        table
    };

    /// Default constructor - creates null value
    Value() = default;

    /// Construct from various types
    /// @param s String view to construct a string Value from
    Value(std::string_view s)
        : data_{std::string{s}}
    {}
    /// @param s String to construct a string Value from
    Value(std::string s)
        : data_{std::move(s)}
    {}
    Value(char const* s)
        : data_{std::string{s}}
    {}
    Value(int64_t i)
        : data_{i}
    {}
    Value(int i)
        : data_{static_cast<int64_t>(i)}
    {}
    Value(double d)
        : data_{d}
    {}
    Value(bool b)
        : data_{b}
    {}
    Value(DateTime dt)
        : data_{std::move(dt)}
    {}
    Value(Array arr)
        : data_{std::move(arr)}
    {}
    Value(Table tbl)
        : data_{std::move(tbl)}
    {}

    /// Get the type of this value
    [[nodiscard]] auto type() const noexcept -> Type { return static_cast<Type>(data_.index()); }

    /// Type checking
    [[nodiscard]] auto is_null() const noexcept -> bool { return std::holds_alternative<std::monostate>(data_); }
    [[nodiscard]] auto is_string() const noexcept -> bool { return std::holds_alternative<std::string>(data_); }
    [[nodiscard]] auto is_integer() const noexcept -> bool { return std::holds_alternative<int64_t>(data_); }
    [[nodiscard]] auto is_float() const noexcept -> bool { return std::holds_alternative<double>(data_); }
    [[nodiscard]] auto is_boolean() const noexcept -> bool { return std::holds_alternative<bool>(data_); }
    [[nodiscard]] auto is_datetime() const noexcept -> bool { return std::holds_alternative<DateTime>(data_); }
    [[nodiscard]] auto is_array() const noexcept -> bool { return std::holds_alternative<Array>(data_); }
    [[nodiscard]] auto is_table() const noexcept -> bool { return std::holds_alternative<Table>(data_); }

    /// Get value as specific type (returns nullopt if wrong type)
    [[nodiscard]] auto as_string() const -> std::optional<std::string_view>
    {
        if (auto const* p = std::get_if<std::string>(&data_)) {
            return *p;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto as_integer() const -> std::optional<int64_t>
    {
        if (auto const* p = std::get_if<int64_t>(&data_)) {
            return *p;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto as_float() const -> std::optional<double>
    {
        if (auto const* p = std::get_if<double>(&data_)) {
            return *p;
        }
        // Also allow integer to float conversion
        if (auto const* p = std::get_if<int64_t>(&data_)) {
            return static_cast<double>(*p);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto as_boolean() const -> std::optional<bool>
    {
        if (auto const* p = std::get_if<bool>(&data_)) {
            return *p;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto as_datetime() const -> std::optional<DateTime>
    {
        if (auto const* p = std::get_if<DateTime>(&data_)) {
            return *p;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto as_array() -> Array* { return std::get_if<Array>(&data_); }

    [[nodiscard]] auto as_array() const -> Array const* { return std::get_if<Array>(&data_); }

    [[nodiscard]] auto as_table() -> Table* { return std::get_if<Table>(&data_); }

    [[nodiscard]] auto as_table() const -> Table const* { return std::get_if<Table>(&data_); }

    /// Get with StatusValue (for chained error handling)
    [[nodiscard]] auto get_string() const -> StatusValue<std::string_view>
    {
        if (auto v = as_string(); v.has_value()) {
            return success(*v);
        }
        return failure(TomlError::type_mismatch);
    }

    [[nodiscard]] auto get_integer() const -> StatusValue<int64_t>
    {
        if (auto v = as_integer(); v.has_value()) {
            return success(*v);
        }
        return failure(TomlError::type_mismatch);
    }

    [[nodiscard]] auto get_float() const -> StatusValue<double>
    {
        if (auto v = as_float(); v.has_value()) {
            return success(*v);
        }
        return failure(TomlError::type_mismatch);
    }

    [[nodiscard]] auto get_boolean() const -> StatusValue<bool>
    {
        if (auto v = as_boolean(); v.has_value()) {
            return success(*v);
        }
        return failure(TomlError::type_mismatch);
    }

    /// Convenience: get with default value
    /// @param default_value Value returned if this is not a string
    [[nodiscard]] auto string_or(std::string_view default_value) const -> std::string_view
    {
        return as_string().value_or(default_value);
    }

    [[nodiscard]] auto integer_or(int64_t default_value) const -> int64_t { return as_integer().value_or(default_value); }

    [[nodiscard]] auto float_or(double default_value) const -> double { return as_float().value_or(default_value); }

    [[nodiscard]] auto boolean_or(bool default_value) const -> bool { return as_boolean().value_or(default_value); }

  private:
    std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table> data_;
};

// Verify Type enum values match variant alternative indices at compile time
static_assert(
    std::is_same_v<
        std::variant_alternative_t<
            static_cast<size_t>(Value::Type::null),
            decltype(std::declval<Value>().type(), std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>{})>,
        std::monostate>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::string),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              std::string>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::integer),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              int64_t>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::floating),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              double>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::boolean),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              bool>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::datetime),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              DateTime>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::array),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              Array>);
static_assert(std::is_same_v<
              std::variant_alternative_t<
                  static_cast<size_t>(Value::Type::table),
                  std::variant<std::monostate, std::string, int64_t, double, bool, DateTime, Array, Table>>,
              Table>);

/// Parse a string into a typed Value
/// Handles: booleans, integers (decimal, 0x hex, 0o octal, 0b binary), floats, quoted/unquoted strings
/// @param s String representation to parse
[[nodiscard]] auto parse_value_string(std::string_view s) -> Value;

/// Get a typed vector from a table by key
/// If key holds an Array: iterates elements, converts each to T, skips failures.
/// If key holds a scalar of type T: returns a one-element vector.
/// If key doesn't exist: returns empty vector.
/// @param root Table to look up in
/// @param key Dotted key path
template <typename T>
[[nodiscard]] auto get_list(Table const& root, std::string_view key) -> std::vector<T>
{
    auto const* v = root.get_path(key);
    if (v == nullptr) {
        return {};
    }

    // If it's an array, iterate and convert each element
    if (auto const* arr = v->as_array(); arr != nullptr) {
        std::vector<T> result;
        result.reserve(arr->size());
        for (size_t i = 0; i < arr->size(); ++i) {
            auto const& elem = (*arr)[i];
            // IMPORTANT: bool must come before is_integral_v because
            // std::is_integral_v<bool> is true, and as_integer() returns
            // nullopt for booleans
            if constexpr (std::is_same_v<T, std::string>) {
                if (auto s = elem.as_string(); s.has_value()) {
                    result.emplace_back(*s);
                }
            } else if constexpr (std::is_same_v<T, bool>) {
                if (auto b = elem.as_boolean(); b.has_value()) {
                    result.push_back(*b);
                }
            } else if constexpr (std::is_integral_v<T>) {
                if (auto n = elem.as_integer(); n.has_value()) {
                    result.push_back(static_cast<T>(*n));
                }
            } else if constexpr (std::is_floating_point_v<T>) {
                if (auto f = elem.as_float(); f.has_value()) {
                    result.push_back(static_cast<T>(*f));
                }
            }
        }
        return result;
    }

    // Single scalar — try to return as one-element vector
    // IMPORTANT: bool before is_integral_v (same reason as above)
    if constexpr (std::is_same_v<T, std::string>) {
        if (auto s = v->as_string(); s.has_value()) {
            return {std::string{*s}};
        }
    } else if constexpr (std::is_same_v<T, bool>) {
        if (auto b = v->as_boolean(); b.has_value()) {
            return {*b};
        }
    } else if constexpr (std::is_integral_v<T>) {
        if (auto n = v->as_integer(); n.has_value()) {
            return {static_cast<T>(*n)};
        }
    } else if constexpr (std::is_floating_point_v<T>) {
        if (auto f = v->as_float(); f.has_value()) {
            return {static_cast<T>(*f)};
        }
    }

    return {};
}

}  // namespace statusbar::toml
