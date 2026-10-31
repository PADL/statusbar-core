#pragma once

// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

/// TOML Parser
/// Parses TOML text into a Table structure

#include "statusbar/status/status.hpp"
#include "statusbar/toml/toml_error.hpp"
#include "statusbar/toml/toml_value.hpp"

#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace statusbar::toml {

/// TOML Parser
/// Parses TOML v1.0 format (subset - most common features)
class Parser
{
  public:
    /// Parse TOML from a string
    /// @param input TOML text to parse
    [[nodiscard]] static auto parse(std::string_view input) -> StatusValue<Table>
    {
        Parser parser{input};
        return parser.parse_document();
    }

    /// Parse TOML from a file
    /// @param path Filesystem path to the TOML file
    [[nodiscard]] static auto parse_file(std::string_view path) -> StatusValue<Table>;

    /// Get the line number of the last error
    [[nodiscard]] auto error_line() const noexcept -> size_t { return line_; }

    /// Get the column number of the last error
    [[nodiscard]] auto error_column() const noexcept -> size_t { return column_; }

    /// Direct construction — useful when a caller wants to retrieve
    /// line/column diagnostics after a parse failure. The static
    /// parse() / parse_file() factories remain the recommended path
    /// for one-shot parsing.
    explicit Parser(std::string_view input)
        : input_{input}
    {}

    /// Parse the document held by this Parser. After a failure,
    /// error_line() / error_column() report the position.
    [[nodiscard]] auto parse_document_public() -> StatusValue<Table> { return parse_document(); }

  private:
    /// Parse a table header ([key] or [[key]]) and return the target table
    [[nodiscard]] auto parse_table_header(Table& root) -> StatusValue<Table*>;

    /// Insert a key-value pair into the current table, handling dotted keys
    [[nodiscard]] auto insert_key_value(Table* current_table) -> Status;

    [[nodiscard]] auto parse_document() -> StatusValue<Table>;

    [[nodiscard]] auto get_or_create_array_of_tables(Table& root, std::span<std::string const> path) -> Array*;

    /// The table a `[header]` names, created if need be. The segments before
    /// the last go through resolve_table_path(), so `[s.x]` after `[[s]]`
    /// attaches to the last `[[s]]`; the last segment itself must be a
    /// table, so `[s]` after `[[s]]` - which names the array - is refused,
    /// as TOML requires and as this parser did before that descent existed.
    [[nodiscard]] static auto open_table(Table& root, std::span<std::string const> path) -> StatusValue<Table*>;

    /// Walk (creating as needed) the table a `[header]` path names.
    /// Where a segment is already an array of tables, this descends into
    /// its LAST element, which is what `[s.x]` after `[[s]]` means.
    /// Only table headers work this way: a dotted key may not extend an
    /// array, so insert_key_value() keeps using Table::get_or_create_table.
    /// @return The table, or nullptr if a segment is a non-table value or
    ///         an empty array (nothing for the header to attach to)
    [[nodiscard]] static auto resolve_table_path(Table& root, std::span<std::string const> path) -> Table*;

    [[nodiscard]] auto parse_key_value() -> StatusValue<std::pair<std::vector<std::string>, Value>>;

    /// Parse a key path into one string per segment. Segments, not a joined
    /// dotted string: a quoted segment may contain a dot of its own, and
    /// joining would make `["a.b"]` and `[a.b]` the same key path.
    [[nodiscard]] auto parse_key_path() -> StatusValue<std::vector<std::string>>;

    [[nodiscard]] auto parse_key() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_bare_key() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_value() -> StatusValue<Value>;

    /// Parse a single escape sequence (after the backslash) and append to result
    [[nodiscard]] auto parse_escape_sequence(char escaped, std::string& result) -> Status;

    [[nodiscard]] auto parse_basic_string() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_multiline_basic_string() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_literal_string() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_multiline_literal_string() -> StatusValue<std::string>;

    [[nodiscard]] auto parse_unicode_escape(int digits) -> StatusValue<std::string>;

    [[nodiscard]] auto parse_boolean() -> StatusValue<bool>;

    [[nodiscard]] auto parse_number() -> StatusValue<Value>;

    // parse_number implementation helpers. Split to keep each step
    // individually testable and to cap cyclomatic complexity.
    enum class NumberBase
    {
        Decimal,
        Hex,
        Octal,
        Binary,
    };

    [[nodiscard]] auto collect_number_prefix(std::string& num_str) -> NumberBase;

    void collect_number_digits(std::string& num_str, NumberBase base, bool& has_dot, bool& has_exp);

    [[nodiscard]] auto parse_inf_or_nan(std::string const& num_str) -> StatusValue<Value>;

    [[nodiscard]] static auto parse_float_literal(std::string const& num_str) -> StatusValue<Value>;

    [[nodiscard]] static auto parse_int_literal(std::string const& num_str, NumberBase base) -> StatusValue<Value>;

    [[nodiscard]] auto parse_array() -> StatusValue<Array>;

    [[nodiscard]] auto parse_inline_table() -> StatusValue<Table>;

    // Helper functions
    [[nodiscard]] auto at_end() const noexcept -> bool { return pos_ >= input_.size(); }

    [[nodiscard]] auto peek(size_t offset = 0) const noexcept -> char
    {
        size_t const idx = pos_ + offset;
        return (idx < input_.size()) ? input_[idx] : '\0';
    }

    auto advance() -> char;

    auto match(std::string_view expected) -> bool;

    void skip_whitespace()
    {
        while (!at_end() && (peek() == ' ' || peek() == '\t')) {
            advance();
        }
    }

    void skip_whitespace_and_newlines();

    void skip_whitespace_and_comments();

    [[nodiscard]] static auto is_bare_key_char(char c) noexcept -> bool
    {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '-';
    }

    /// Check if a character can start a key (alphabetic, underscore, or quoted string opener)
    [[nodiscard]] static auto is_key_start_char(char c) noexcept -> bool
    {
        return std::isalpha(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '"' || c == '\'';
    }

    /// Maximum array / inline-table nesting depth. The recursive descent in
    /// parse_array / parse_inline_table / parse_value bounces back through
    /// parse_value each level, so unbounded nesting on attacker-controlled
    /// input would blow the stack. 64 is far beyond any sensible config file.
    static constexpr size_t max_nesting_depth = 64;

    std::string_view input_;
    size_t pos_{0};
    size_t line_{1};
    size_t column_{1};
    size_t nesting_depth_{0};
};

/// Parse TOML from a string
/// @param input TOML text to parse
[[nodiscard]] inline auto parse(std::string_view input) -> StatusValue<Table>
{
    return Parser::parse(input);
}

/// Parse TOML from a file
/// @param path Filesystem path to the TOML file
[[nodiscard]] inline auto parse_file(std::string_view path) -> StatusValue<Table>
{
    return Parser::parse_file(path);
}

}  // namespace statusbar::toml
