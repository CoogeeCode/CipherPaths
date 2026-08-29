// Copyright 2026 Coogee Code Pty. Ltd. Australia
// https://www.coogeecode.com.au/
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// CipherPaths - https://cipherpaths.com/ - for more information.

// CipherPaths Core - Minimal JSON implementation.
#include "cipherpaths/Json.h"

#include "cipherpaths/Errors.h"

#include <cmath>
#include <cstdio>
#include <sstream>

namespace cipherpaths {

namespace {
const JsonValue kNullValue{};
} // namespace

// Return (creating if needed) the member for `key`, promoting this value to an object.
JsonValue& JsonValue::operator[](const std::string& key) {
    if (type_ != Type::Object) { type_ = Type::Object; }
    return obj_[key];
}

// Read-only member lookup; returns a shared null value when `key` is absent.
const JsonValue& JsonValue::at(const std::string& key) const {
    auto it = obj_.find(key);
    if (it == obj_.end()) return kNullValue;
    return it->second;
}

// True if this value is an object that has a member named `key`.
bool JsonValue::contains(const std::string& key) const {
    return type_ == Type::Object && obj_.find(key) != obj_.end();
}

// Return the string member `key`, or `def` if it is missing or not a string.
std::string JsonValue::getString(const std::string& key, const std::string& def) const {
    auto it = obj_.find(key);
    if (it == obj_.end() || it->second.type_ != Type::String) return def;
    return it->second.str_;
}

// ---- Serialisation -------------------------------------------------------

// Append `s` to `out` as a quoted, JSON-escaped string (UTF-8 passed through).
static void escapeString(std::string& out, const std::string& s) {
    out.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c); // UTF-8 passthrough
                }
        }
    }
    out.push_back('"');
}

// Recursively serialise this value into `out` at the given indent level.
void JsonValue::dumpTo(std::string& out, bool pretty, int indent) const {
    auto pad = [&](int n) { if (pretty) out.append(static_cast<size_t>(n) * 2, ' '); };
    auto nl = [&] { if (pretty) out.push_back('\n'); };

    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Number: {
            if (std::floor(num_) == num_ && std::abs(num_) < 1e15) {
                out += std::to_string(static_cast<long long>(num_));
            } else {
                std::ostringstream ss; ss << num_; out += ss.str();
            }
            break;
        }
        case Type::String: escapeString(out, str_); break;
        case Type::Array: {
            out.push_back('[');
            nl();
            for (size_t i = 0; i < arr_.size(); ++i) {
                pad(indent + 1);
                arr_[i].dumpTo(out, pretty, indent + 1);
                if (i + 1 < arr_.size()) out.push_back(',');
                nl();
            }
            pad(indent);
            out.push_back(']');
            break;
        }
        case Type::Object: {
            out.push_back('{');
            nl();
            size_t i = 0;
            for (const auto& [k, v] : obj_) {
                pad(indent + 1);
                escapeString(out, k);
                out += pretty ? ": " : ":";
                v.dumpTo(out, pretty, indent + 1);
                if (++i < obj_.size()) out.push_back(',');
                nl();
            }
            pad(indent);
            out.push_back('}');
            break;
        }
    }
}

// Serialise this value to a compact (or, when `pretty`, indented) JSON string.
std::string JsonValue::dump(bool pretty) const {
    std::string out;
    dumpTo(out, pretty, 0);
    return out;
}

// ---- Parsing -------------------------------------------------------------

namespace {

// Recursive-descent parser over a JSON string.
class Parser {
public:
    explicit Parser(const std::string& text) : s_(text) {}

    // Parse the whole input as a single JSON value; rejects trailing junk.
    JsonValue parse() {
        skipWs();
        JsonValue v = parseValue();
        skipWs();
        if (pos_ != s_.size()) fail("trailing characters");
        return v;
    }

private:
    // Throw an InvalidJson error with the given message.
    [[noreturn]] void fail(const char* msg) {
        throw CipherPathsError(ErrorCode::InvalidJson, msg);
    }

    // Look at / consume the current character ('\0' at end of input).
    char peek() { return pos_ < s_.size() ? s_[pos_] : '\0'; }
    char get()  { return pos_ < s_.size() ? s_[pos_++] : '\0'; }

    // Advance past any run of JSON whitespace.
    void skipWs() {
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos_;
            else break;
        }
    }

    // Dispatch on the next non-whitespace character to the right parser.
    JsonValue parseValue() {
        skipWs();
        char c = peek();
        switch (c) {
            case '{': return parseObject();
            case '[': return parseArray();
            case '"': return JsonValue(parseString());
            case 't': case 'f': return parseBool();
            case 'n': return parseNull();
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
                fail("unexpected character");
        }
    }

    // Parse a '{ ... }' object of string keys to values.
    JsonValue parseObject() {
        JsonValue obj = JsonValue::makeObject();
        get(); // '{'
        skipWs();
        if (peek() == '}') { get(); return obj; }
        while (true) {
            skipWs();
            if (peek() != '"') fail("expected object key");
            std::string key = parseString();
            skipWs();
            if (get() != ':') fail("expected ':'");
            obj[key] = parseValue();
            skipWs();
            char c = get();
            if (c == ',') continue;
            if (c == '}') break;
            fail("expected ',' or '}'");
        }
        return obj;
    }

    // Parse a '[ ... ]' array of values.
    JsonValue parseArray() {
        JsonValue arr = JsonValue::makeArray();
        get(); // '['
        skipWs();
        if (peek() == ']') { get(); return arr; }
        while (true) {
            arr.push_back(parseValue());
            skipWs();
            char c = get();
            if (c == ',') continue;
            if (c == ']') break;
            fail("expected ',' or ']'");
        }
        return arr;
    }

    // Parse a double-quoted string, decoding the standard JSON escapes.
    std::string parseString() {
        get(); // opening quote
        std::string out;
        while (true) {
            if (pos_ >= s_.size()) fail("unterminated string");
            char c = s_[pos_++];
            if (c == '"') break;
            if (c == '\\') {
                char e = get();
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'u': {
                        if (pos_ + 4 > s_.size()) fail("bad \\u escape");
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = s_[pos_++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= (h - '0');
                            else if (h >= 'a' && h <= 'f') code |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= (h - 'A' + 10);
                            else fail("bad hex digit");
                        }
                        // Encode the BMP code point as UTF-8 (surrogate pairs are
                        // uncommon for our data and left as-is).
                        if (code < 0x80) {
                            out.push_back(static_cast<char>(code));
                        } else if (code < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                        }
                        break;
                    }
                    default: fail("bad escape");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    // Parse an integer or floating-point number into a Number value.
    JsonValue parseNumber() {
        size_t start = pos_;
        if (peek() == '-') get();
        while (std::isdigit(static_cast<unsigned char>(peek()))) get();
        if (peek() == '.') { get(); while (std::isdigit(static_cast<unsigned char>(peek()))) get(); }
        if (peek() == 'e' || peek() == 'E') {
            get();
            if (peek() == '+' || peek() == '-') get();
            while (std::isdigit(static_cast<unsigned char>(peek()))) get();
        }
        return JsonValue(std::stod(s_.substr(start, pos_ - start)));
    }

    // Parse the literal `true` or `false`.
    JsonValue parseBool() {
        if (s_.compare(pos_, 4, "true") == 0) { pos_ += 4; return JsonValue(true); }
        if (s_.compare(pos_, 5, "false") == 0) { pos_ += 5; return JsonValue(false); }
        fail("invalid literal");
    }

    // Parse the literal `null`.
    JsonValue parseNull() {
        if (s_.compare(pos_, 4, "null") == 0) { pos_ += 4; return JsonValue(nullptr); }
        fail("invalid literal");
    }

    const std::string& s_;
    size_t pos_ = 0;
};

} // namespace

// Parse JSON text into a JsonValue; throws CipherPathsError(InvalidJson) on error.
JsonValue JsonValue::parse(const std::string& text) {
    Parser p(text);
    return p.parse();
}

} // namespace cipherpaths
