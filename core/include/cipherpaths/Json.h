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

// CipherPaths Core - Minimal JSON value.
// A small, dependency-free JSON implementation sufficient for the vault header
// and the simple ##password##.json structure. Supports objects, arrays,
// strings, numbers, booleans and null, with UTF-8 passthrough.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace cipherpaths {

class JsonValue {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    JsonValue() : type_(Type::Null) {}
    JsonValue(std::nullptr_t) : type_(Type::Null) {}
    JsonValue(bool b) : type_(Type::Bool), bool_(b) {}
    JsonValue(double n) : type_(Type::Number), num_(n) {}
    JsonValue(int n) : type_(Type::Number), num_(n) {}
    JsonValue(const char* s) : type_(Type::String), str_(s) {}
    JsonValue(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static JsonValue makeObject() { JsonValue v; v.type_ = Type::Object; return v; }
    static JsonValue makeArray()  { JsonValue v; v.type_ = Type::Array;  return v; }

    Type type() const { return type_; }
    bool isObject() const { return type_ == Type::Object; }
    bool isArray()  const { return type_ == Type::Array; }
    bool isString() const { return type_ == Type::String; }
    bool isNull()   const { return type_ == Type::Null; }

    // Accessors with safe defaults.
    const std::string& asString() const { return str_; }
    double asNumber() const { return num_; }
    bool asBool() const { return bool_; }

    /// Object access. operator[] inserts on write; use `contains` to test.
    JsonValue& operator[](const std::string& key);
    const JsonValue& at(const std::string& key) const;
    bool contains(const std::string& key) const;
    std::string getString(const std::string& key, const std::string& def = {}) const;

    /// Array access.
    void push_back(JsonValue v) { arr_.push_back(std::move(v)); }
    const std::vector<JsonValue>& items() const { return arr_; }
    const std::map<std::string, JsonValue>& members() const { return obj_; }

    /// Serialise to a compact (or pretty) JSON string.
    std::string dump(bool pretty = false) const;

    /// Parse JSON text. Throws CipherPathsError(InvalidJson) on malformed input.
    static JsonValue parse(const std::string& text);

private:
    void dumpTo(std::string& out, bool pretty, int indent) const;

    Type type_;
    bool bool_ = false;
    double num_ = 0.0;
    std::string str_;
    std::vector<JsonValue> arr_;
    std::map<std::string, JsonValue> obj_;
};

} // namespace cipherpaths
