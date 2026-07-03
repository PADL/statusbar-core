// Copyright 2026 Jeff Koftinoff <jeff.koftinoff@statusbar.com>
// SPDX-License-Identifier: MIT

#include "statusbar/toml/toml_parser.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace statusbar::toml {

auto Parser::parse_file(std::string_view path) -> StatusValue<Table>
{
    std::ifstream file{std::string{path}};  // NOLINT(misc-const-correctness) — stream is read from
    if (!file.is_open()) {
        return failure(TomlError::file_not_found);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    if (file.fail() && !file.eof()) {
        return failure(TomlError::file_read_error);
    }

    return parse(buffer.str());
}

auto Parser::parse_table_header(Table& root) -> StatusValue<Table*>
{
    advance();  // skip '['
    bool is_array_table = false;

    if (peek() == '[') {
        advance();
        is_array_table = true;
    }

    skip_whitespace();

    auto key_result = parse_key_path();
    if (!key_result) {
        return forward_failure(key_result);
    }

    skip_whitespace();

    if (peek() != ']') {
        return failure(TomlError::expected_bracket);
    }
    advance();

    if (is_array_table) {
        if (peek() != ']') {
            return failure(TomlError::expected_bracket);
        }
        advance();
    }

    skip_whitespace();
    if (!at_end() && peek() != '\n' && peek() != '\r' && peek() != '#') {
        return failure(TomlError::expected_newline);
    }

    if (is_array_table) {
        auto* arr = get_or_create_array_of_tables(root, *key_result);
        if (arr == nullptr) {
            return failure(TomlError::type_mismatch);
        }
        arr->push_back(Table{});
        return success(arr->operator[](arr->size() - 1).as_table());
    }

    Table* tbl = root.get_or_create_table(*key_result);
    if (tbl == nullptr) {
        return failure(TomlError::type_mismatch);
    }
    return success(tbl);
}

auto Parser::insert_key_value(Table* current_table) -> Status
{
    auto kv_result = parse_key_value();
    if (!kv_result) {
        return failure(kv_result.error());
    }

    auto& [key, value] = *kv_result;

    size_t const dot = key.rfind('.');
    if (dot != std::string::npos) {
        std::string const parent_path = key.substr(0, dot);
        std::string final_key = key.substr(dot + 1);
        Table* parent = current_table->get_or_create_table(parent_path);
        if (parent == nullptr) {
            return failure(TomlError::type_mismatch);
        }
        if (parent->contains(final_key)) {
            return failure(TomlError::duplicate_key);
        }
        parent->set(std::move(final_key), std::move(value));
    } else {
        if (current_table->contains(key)) {
            return failure(TomlError::duplicate_key);
        }
        current_table->set(std::move(key), std::move(value));
    }

    return success();
}

auto Parser::parse_document() -> StatusValue<Table>
{
    Table root;
    Table* current_table = &root;

    while (!at_end()) {
        skip_whitespace_and_comments();
        if (at_end()) {
            break;
        }

        char const c = peek();

        if (c == '[') {
            auto result = parse_table_header(root);
            if (!result) {
                return forward_failure(result);
            }
            current_table = *result;
        } else if (c == '\n' || c == '\r') {
            advance();
        } else if (is_key_start_char(c)) {
            auto result = insert_key_value(current_table);
            if (!result) {
                return forward_failure(result);
            }
        } else {
            return failure(TomlError::unexpected_character);
        }
    }

    return success(std::move(root));
}

auto Parser::get_or_create_array_of_tables(Table& root, std::string_view path) -> Array*
{
    size_t const dot = path.rfind('.');
    Table* parent = &root;

    if (dot != std::string::npos) {
        parent = root.get_or_create_table(path.substr(0, dot));
        if (parent == nullptr) {
            return nullptr;
        }
        path = path.substr(dot + 1);
    }

    Value* v = parent->get(path);
    if (v == nullptr) {
        parent->set(std::string{path}, Array{});
        v = parent->get(path);
    }

    return v->as_array();
}

auto Parser::parse_key_value() -> StatusValue<std::pair<std::string, Value>>
{
    auto key_result = parse_key_path();
    if (!key_result) {
        return failure(key_result.error());
    }

    skip_whitespace();

    if (peek() != '=') {
        return failure(TomlError::expected_equals);
    }
    advance();

    skip_whitespace();

    auto value_result = parse_value();
    if (!value_result) {
        return failure(value_result.error());
    }

    skip_whitespace();
    if (!at_end() && peek() != '\n' && peek() != '\r' && peek() != '#') {
        return failure(TomlError::expected_newline);
    }

    return success(std::make_pair(std::move(*key_result), std::move(*value_result)));
}

auto Parser::parse_key_path() -> StatusValue<std::string>
{
    std::string result;

    while (true) {
        auto key_result = parse_key();
        if (!key_result) {
            return forward_failure(key_result);
        }

        if (!result.empty()) {
            result += '.';
        }
        result += *key_result;

        skip_whitespace();
        if (peek() != '.') {
            break;
        }
        advance();
        skip_whitespace();
    }

    return success(std::move(result));
}

auto Parser::parse_key() -> StatusValue<std::string>
{
    char const c = peek();

    if (c == '"') {
        return parse_basic_string();
    }
    if (c == '\'') {
        return parse_literal_string();
    }
    if (is_bare_key_char(c)) {
        return parse_bare_key();
    }
    return failure(TomlError::invalid_key);
}

auto Parser::parse_bare_key() -> StatusValue<std::string>
{
    std::string result;
    while (!at_end() && is_bare_key_char(peek())) {
        result += advance();
    }
    if (result.empty()) {
        return failure(TomlError::invalid_key);
    }
    return success(std::move(result));
}

auto Parser::parse_value() -> StatusValue<Value>
{
    skip_whitespace();

    if (at_end()) {
        return failure(TomlError::expected_value);
    }

    char const c = peek();

    if (c == '"') {
        if (peek(1) == '"' && peek(2) == '"') {
            return parse_multiline_basic_string().transform([](std::string s) -> Value { return Value{std::move(s)}; });
        }
        return parse_basic_string().transform([](std::string s) -> Value { return Value{std::move(s)}; });
    }
    if (c == '\'') {
        if (peek(1) == '\'' && peek(2) == '\'') {
            return parse_multiline_literal_string().transform([](std::string s) -> Value { return Value{std::move(s)}; });
        }
        return parse_literal_string().transform([](std::string s) -> Value { return Value{std::move(s)}; });
    }
    if (c == 't' || c == 'f') {
        return parse_boolean().transform([](bool b) -> Value { return Value{b}; });
    }
    if (c == '[') {
        return parse_array().transform([](Array a) -> Value { return Value{std::move(a)}; });
    }
    if (c == '{') {
        return parse_inline_table().transform([](Table t) -> Value { return Value{std::move(t)}; });
    }
    auto const is_number_start = [](char ch) {
        return ch == '-' || ch == '+' || ch == 'n' || ch == 'i' || std::isdigit(static_cast<unsigned char>(ch)) != 0;
    };
    if (is_number_start(c)) {
        return parse_number();
    }
    return failure(TomlError::expected_value);
}

auto Parser::parse_escape_sequence(char escaped, std::string& result) -> Status
{
    switch (escaped) {
        case 'b':
            result += '\b';
            break;
        case 't':
            result += '\t';
            break;
        case 'n':
            result += '\n';
            break;
        case 'f':
            result += '\f';
            break;
        case 'r':
            result += '\r';
            break;
        case '"':
            result += '"';
            break;
        case '\\':
            result += '\\';
            break;
        case 'u':
        case 'U': {
            int const digits = (escaped == 'u') ? 4 : 8;
            auto unicode_result = parse_unicode_escape(digits);
            if (!unicode_result) {
                return failure(unicode_result.error());
            }
            result += *unicode_result;
            break;
        }
        default:
            return failure(TomlError::invalid_escape_sequence);
    }
    return success();
}

auto Parser::parse_basic_string() -> StatusValue<std::string>
{
    if (peek() != '"') {
        return failure(TomlError::unterminated_string);
    }
    advance();

    std::string result;
    while (!at_end()) {
        char const c = peek();
        if (c == '"') {
            advance();
            return success(std::move(result));
        }
        if (c == '\\') {
            advance();
            if (at_end()) {
                return failure(TomlError::invalid_escape_sequence);
            }
            char const escaped = advance();
            auto esc_result = parse_escape_sequence(escaped, result);
            if (!esc_result) {
                return forward_failure(esc_result);
            }
        } else if (c == '\n') {
            return failure(TomlError::unterminated_string);
        } else {
            result += advance();
        }
    }

    return failure(TomlError::unterminated_string);
}

auto Parser::parse_multiline_basic_string() -> StatusValue<std::string>
{
    // Skip opening """
    advance();
    advance();
    advance();

    // Skip immediate newline if present
    if (peek() == '\n') {
        advance();
    } else if (peek() == '\r' && peek(1) == '\n') {
        advance();
        advance();
    }

    std::string result;
    while (!at_end()) {
        if (peek() == '"' && peek(1) == '"' && peek(2) == '"') {
            advance();
            advance();
            advance();
            return success(std::move(result));
        }
        if (peek() == '\\') {
            advance();
            if (at_end()) {
                return failure(TomlError::invalid_escape_sequence);
            }
            auto const is_line_ending_whitespace = [](char ch) { return ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t'; };
            char const escaped = peek();
            if (is_line_ending_whitespace(escaped)) {
                // Line-ending backslash - skip whitespace and newlines
                skip_whitespace();
                while (peek() == '\n' || peek() == '\r') {
                    advance();
                    skip_whitespace();
                }
            } else {
                advance();
                auto esc_result = parse_escape_sequence(escaped, result);
                if (!esc_result) {
                    return forward_failure(esc_result);
                }
            }
        } else {
            result += advance();
        }
    }

    return failure(TomlError::unterminated_string);
}

auto Parser::parse_literal_string() -> StatusValue<std::string>
{
    if (peek() != '\'') {
        return failure(TomlError::unterminated_string);
    }
    advance();

    std::string result;
    while (!at_end()) {
        char const c = peek();
        if (c == '\'') {
            advance();
            return success(std::move(result));
        }
        if (c == '\n') {
            return failure(TomlError::unterminated_string);
        }
        result += advance();
    }

    return failure(TomlError::unterminated_string);
}

auto Parser::parse_multiline_literal_string() -> StatusValue<std::string>
{
    // Skip opening '''
    advance();
    advance();
    advance();

    // Skip immediate newline if present
    if (peek() == '\n') {
        advance();
    } else if (peek() == '\r' && peek(1) == '\n') {
        advance();
        advance();
    }

    std::string result;
    while (!at_end()) {
        if (peek() == '\'' && peek(1) == '\'' && peek(2) == '\'') {
            advance();
            advance();
            advance();
            return success(std::move(result));
        }
        result += advance();
    }

    return failure(TomlError::unterminated_string);
}

auto Parser::parse_unicode_escape(int digits) -> StatusValue<std::string>
{
    uint32_t codepoint = 0;
    for (int i = 0; i < digits; ++i) {
        if (at_end()) {
            return failure(TomlError::invalid_escape_sequence);
        }
        char const c = advance();
        codepoint *= 16;
        if (c >= '0' && c <= '9') {
            codepoint += static_cast<uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            codepoint += static_cast<uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            codepoint += static_cast<uint32_t>(c - 'A' + 10);
        } else {
            return failure(TomlError::invalid_escape_sequence);
        }
    }

    // Reject Unicode surrogate codepoints (U+D800-U+DFFF) per TOML spec
    if (codepoint >= 0xD800 && codepoint <= 0xDFFF) {
        return failure(TomlError::invalid_unicode_codepoint);
    }

    // Convert codepoint to UTF-8
    std::string result;
    if (codepoint < 0x80) {
        result += static_cast<char>(codepoint);
    } else if (codepoint < 0x800) {
        result += static_cast<char>(0xC0 | (codepoint >> 6));
        result += static_cast<char>(0x80 | (codepoint & 0x3F));
    } else if (codepoint < 0x10000) {
        result += static_cast<char>(0xE0 | (codepoint >> 12));
        result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
        result += static_cast<char>(0x80 | (codepoint & 0x3F));
    } else if (codepoint < 0x110000) {
        result += static_cast<char>(0xF0 | (codepoint >> 18));
        result += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
        result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
        result += static_cast<char>(0x80 | (codepoint & 0x3F));
    } else {
        return failure(TomlError::invalid_escape_sequence);
    }

    return success(std::move(result));
}

auto Parser::parse_boolean() -> StatusValue<bool>
{
    if (match("true")) {
        return success(true);
    }
    if (match("false")) {
        return success(false);
    }
    return failure(TomlError::invalid_boolean);
}

auto Parser::collect_number_prefix(std::string& num_str) -> NumberBase
{
    if (peek() == '+' || peek() == '-') {
        num_str += advance();
    }
    if (peek() != '0') {
        return NumberBase::Decimal;
    }
    num_str += advance();
    char const next = peek();
    if (next == 'x' || next == 'X') {
        num_str += advance();
        return NumberBase::Hex;
    }
    if (next == 'o' || next == 'O') {
        num_str += advance();
        return NumberBase::Octal;
    }
    if (next == 'b' || next == 'B') {
        num_str += advance();
        return NumberBase::Binary;
    }
    return NumberBase::Decimal;
}

void Parser::collect_number_digits(std::string& num_str, NumberBase base, bool& has_dot, bool& has_exp)
{
    auto is_digit_for_base = [base](char c) -> bool {
        auto const uc = static_cast<unsigned char>(c);
        switch (base) {
            case NumberBase::Hex:
                return std::isxdigit(uc) != 0;
            case NumberBase::Octal:
                return c >= '0' && c <= '7';
            case NumberBase::Binary:
                return c == '0' || c == '1';
            case NumberBase::Decimal:
                return std::isdigit(uc) != 0;
        }
        return false;
    };

    while (!at_end()) {
        char const c = peek();
        if (c == '_') {
            advance();  // Skip underscores in numbers
            continue;
        }
        if (is_digit_for_base(c)) {
            num_str += advance();
            continue;
        }
        if (base != NumberBase::Decimal) {
            break;  // Typed literal saw a non-matching character.
        }
        if (c == '.' && !has_dot && !has_exp) {
            has_dot = true;
            num_str += advance();
        } else if ((c == 'e' || c == 'E') && !has_exp) {
            has_exp = true;
            num_str += advance();
            if (peek() == '+' || peek() == '-') {
                num_str += advance();
            }
        } else {
            break;
        }
    }
}

auto Parser::parse_inf_or_nan(std::string const& num_str) -> StatusValue<Value>
{
    std::string word;
    while (!at_end() && std::isalpha(static_cast<unsigned char>(peek())) != 0) {
        word += advance();
    }
    if (word == "inf") {
        double const sign = (num_str == "-") ? -1.0 : 1.0;
        return success(Value{sign * std::numeric_limits<double>::infinity()});
    }
    if (word == "nan") {
        return success(Value{std::numeric_limits<double>::quiet_NaN()});
    }
    return failure(TomlError::invalid_number);
}

auto Parser::parse_float_literal(std::string const& num_str) -> StatusValue<Value>
{
    char* end = nullptr;  // NOLINT(misc-const-correctness) - modified by strtod
    double const value = std::strtod(num_str.c_str(), &end);
    if (end != num_str.c_str() + num_str.size()) {
        return failure(TomlError::invalid_number);
    }
    return success(Value{value});
}

auto Parser::parse_int_literal(std::string const& num_str, NumberBase base) -> StatusValue<Value>
{
    char const* const start = num_str.c_str();
    char const* const end_ptr = num_str.c_str() + num_str.size();

    // Decimal: from_chars handles the sign directly.
    if (base == NumberBase::Decimal) {
        int64_t value = 0;
        auto [ptr, ec] = std::from_chars(start, end_ptr, value, 10);
        if (ec == std::errc::result_out_of_range) {
            return failure(TomlError::number_overflow);
        }
        if (ec != std::errc{} || ptr != end_ptr) {
            return failure(TomlError::invalid_number);
        }
        return success(Value{value});
    }

    // Non-decimal: handle sign manually and skip the 2-char base prefix.
    char const* digit_start = start;
    if (*digit_start == '-' || *digit_start == '+') {
        ++digit_start;
    }
    digit_start += 2;  // skip 0x / 0o / 0b
    int numeric_base = 10;
    switch (base) {
        case NumberBase::Hex:
            numeric_base = 16;
            break;
        case NumberBase::Octal:
            numeric_base = 8;
            break;
        case NumberBase::Binary:
            numeric_base = 2;
            break;
        case NumberBase::Decimal:
            break;  // unreachable; handled above
    }

    bool const negative = (*start == '-');
    uint64_t uvalue = 0;
    auto [ptr, ec] = std::from_chars(digit_start, end_ptr, uvalue, numeric_base);
    if (ec == std::errc::result_out_of_range) {
        return failure(TomlError::number_overflow);
    }
    if (ec != std::errc{} || ptr != end_ptr) {
        return failure(TomlError::invalid_number);
    }
    if (negative) {
        if (uvalue > static_cast<uint64_t>(INT64_MAX) + 1U) {
            return failure(TomlError::number_overflow);
        }
        return success(Value{-static_cast<int64_t>(uvalue)});
    }
    if (uvalue > static_cast<uint64_t>(INT64_MAX)) {
        return failure(TomlError::number_overflow);
    }
    return success(Value{static_cast<int64_t>(uvalue)});
}

auto Parser::parse_number() -> StatusValue<Value>
{
    std::string num_str;
    auto const base = collect_number_prefix(num_str);

    bool has_dot = false;
    bool has_exp = false;
    collect_number_digits(num_str, base, has_dot, has_exp);

    if (num_str.empty() || num_str == "+" || num_str == "-") {
        return parse_inf_or_nan(num_str);
    }
    if (has_dot || has_exp) {
        return parse_float_literal(num_str);
    }
    return parse_int_literal(num_str, base);
}

auto Parser::parse_array() -> StatusValue<Array>
{
    if (peek() != '[') {
        return failure(TomlError::unterminated_array);
    }
    advance();

    // Guard against stack exhaustion on hostile deeply-nested input like
    // `[[[[...]]]]`. parse_array -> parse_value -> parse_array recursion
    // would otherwise blow the stack on attacker-controlled config files.
    if (nesting_depth_ >= max_nesting_depth) {
        return failure(TomlError::nesting_too_deep);
    }
    ++nesting_depth_;

    Array result;
    skip_whitespace_and_newlines();

    while (!at_end() && peek() != ']') {
        auto value_result = parse_value();
        if (!value_result) {
            --nesting_depth_;
            return forward_failure(value_result);
        }
        result.push_back(std::move(*value_result));

        skip_whitespace_and_newlines();

        if (peek() == ',') {
            advance();
            skip_whitespace_and_newlines();
        }
    }

    --nesting_depth_;

    if (peek() != ']') {
        return failure(TomlError::unterminated_array);
    }
    advance();

    return success(std::move(result));
}

auto Parser::parse_inline_table() -> StatusValue<Table>
{
    if (peek() != '{') {
        return failure(TomlError::unterminated_inline_table);
    }
    advance();

    // Same stack-exhaustion guard as parse_array: parse_inline_table ->
    // parse_value -> parse_inline_table recursion bounded to max_nesting_depth.
    if (nesting_depth_ >= max_nesting_depth) {
        return failure(TomlError::nesting_too_deep);
    }
    ++nesting_depth_;

    Table result;
    skip_whitespace();

    while (!at_end() && peek() != '}') {
        auto key_result = parse_key_path();
        if (!key_result) {
            --nesting_depth_;
            return forward_failure(key_result);
        }

        skip_whitespace();

        if (peek() != '=') {
            --nesting_depth_;
            return failure(TomlError::expected_equals);
        }
        advance();

        skip_whitespace();

        auto value_result = parse_value();
        if (!value_result) {
            --nesting_depth_;
            return forward_failure(value_result);
        }

        // Handle dotted keys in inline tables
        size_t const dot = key_result->rfind('.');
        if (dot != std::string::npos) {
            std::string const parent_path = key_result->substr(0, dot);
            std::string final_key = key_result->substr(dot + 1);
            Table* parent = result.get_or_create_table(parent_path);
            if (parent == nullptr) {
                --nesting_depth_;
                return failure(TomlError::type_mismatch);
            }
            parent->set(std::move(final_key), std::move(*value_result));
        } else {
            result.set(std::move(*key_result), std::move(*value_result));
        }

        skip_whitespace();

        if (peek() == ',') {
            advance();
            skip_whitespace();
        }
    }

    --nesting_depth_;

    if (peek() != '}') {
        return failure(TomlError::unterminated_inline_table);
    }
    advance();

    return success(std::move(result));
}

auto Parser::advance() -> char
{
    // input_ is a string_view: operator[] at pos_ >= size() is UB (unlike std::string,
    // it does not return '\0'). Fail safe past end, matching peek().
    if (pos_ >= input_.size()) {
        return '\0';
    }
    char const c = input_[pos_++];
    if (c == '\n') {
        ++line_;
        column_ = 1;
    } else {
        ++column_;
    }
    return c;
}

auto Parser::match(std::string_view expected) -> bool
{
    if (input_.substr(pos_, expected.size()) == expected) {
        for (size_t i = 0; i < expected.size(); ++i) {
            advance();
        }
        return true;
    }
    return false;
}

void Parser::skip_whitespace_and_newlines()
{
    auto const is_whitespace_or_newline = [](char ch) { return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'; };
    while (!at_end()) {
        char const c = peek();
        if (is_whitespace_or_newline(c)) {
            advance();
        } else if (c == '#') {
            // Skip comment
            while (!at_end() && peek() != '\n') {
                advance();
            }
        } else {
            break;
        }
    }
}

void Parser::skip_whitespace_and_comments()
{
    auto const is_horizontal_whitespace_or_cr = [](char ch) { return ch == ' ' || ch == '\t' || ch == '\r'; };
    while (!at_end()) {
        char const c = peek();
        if (is_horizontal_whitespace_or_cr(c)) {
            advance();
        } else if (c == '#') {
            // Comments run to end of line; \r before \n is part of the comment
            while (!at_end() && peek() != '\n') {
                advance();
            }
        } else {
            break;
        }
    }
}

}  // namespace statusbar::toml
