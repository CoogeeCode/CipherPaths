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

// CipherPaths Core - Password entry service implementation.
#include "cipherpaths/PasswordEntry.h"

#include "cipherpaths/Errors.h"
#include "cipherpaths/Json.h"

namespace cipherpaths {

namespace {

// Write the web-login fields onto the credential JSON object.
void serializeWebCredential(JsonValue& cred, const WebCredential& web) {
    cred["url"] = web.url;
    cred["username"] = web.username;
    cred["password"] = web.password;
    cred["twoFactorType"] = web.twoFactorType;
}

// Write the credit-card fields onto the credential JSON object.
void serializeCreditCardCredential(JsonValue& cred, const CreditCardCredential& card) {
    cred["cardholderName"] = card.cardholderName;
    cred["cardNumber"] = card.cardNumber;
    cred["expiryDate"] = card.expiryDate;
    cred["cvv"] = card.cvv;
    cred["issuer"] = card.issuer;
}

// Write the contact-detail fields onto the credential JSON object.
void serializeContactCredential(JsonValue& cred, const ContactCredential& contact) {
    cred["fullName"] = contact.fullName;
    cred["email"] = contact.email;
    cred["phoneNumber"] = contact.phoneNumber;
    cred["address"] = contact.address;
    cred["city"] = contact.city;
    cred["state"] = contact.state;
    cred["postalCode"] = contact.postalCode;
    cred["country"] = contact.country;
    cred["dateOfBirth"] = contact.dateOfBirth;
}

// Read the web-login fields from the credential JSON object.
WebCredential deserializeWebCredential(const JsonValue& cred) {
    WebCredential web;
    web.url = cred.getString("url");
    web.username = cred.getString("username");
    web.password = cred.getString("password");
    web.twoFactorType = cred.getString("twoFactorType");
    return web;
}

// Read the credit-card fields from the credential JSON object.
CreditCardCredential deserializeCreditCardCredential(const JsonValue& cred) {
    CreditCardCredential card;
    card.cardholderName = cred.getString("cardholderName");
    card.cardNumber = cred.getString("cardNumber");
    card.expiryDate = cred.getString("expiryDate");
    card.cvv = cred.getString("cvv");
    card.issuer = cred.getString("issuer");
    return card;
}

// Read the contact-detail fields from the credential JSON object.
ContactCredential deserializeContactCredential(const JsonValue& cred) {
    ContactCredential contact;
    contact.fullName = cred.getString("fullName");
    contact.email = cred.getString("email");
    contact.phoneNumber = cred.getString("phoneNumber");
    contact.address = cred.getString("address");
    contact.city = cred.getString("city");
    contact.state = cred.getString("state");
    contact.postalCode = cred.getString("postalCode");
    contact.country = cred.getString("country");
    contact.dateOfBirth = cred.getString("dateOfBirth");
    return contact;
}

} // namespace

// Serialise a password entry (folder name + typed credential) to pretty JSON.
std::string PasswordEntryService::toJson(const PasswordEntry& entry) {
    JsonValue root = JsonValue::makeObject();
    root["folderName"] = entry.folderName;
    JsonValue cred = JsonValue::makeObject();
    cred["type"] = entry.credential.type;
    cred["dateCreated"] = entry.credential.dateCreated;
    cred["lastUpdated"] = entry.credential.lastUpdated;
    cred["passwordUpdated"] = entry.credential.passwordUpdated;
    
    JsonValue tagsArray = JsonValue::makeArray();
    for (const auto& tag : entry.credential.tags) {
        tagsArray.push_back(JsonValue(tag));
    }
    cred["tags"] = tagsArray;
    
    if (entry.credential.type == "web") {
        serializeWebCredential(cred, std::get<WebCredential>(entry.credential.data));
    } else if (entry.credential.type == "creditcard") {
        serializeCreditCardCredential(cred, std::get<CreditCardCredential>(entry.credential.data));
    } else if (entry.credential.type == "contact") {
        serializeContactCredential(cred, std::get<ContactCredential>(entry.credential.data));
    }
    
    root["credential"] = cred;
    return root.dump(true);
}

// Parse a password entry from JSON; throws InvalidJson on malformed or unknown data.
PasswordEntry PasswordEntryService::fromJson(const std::string& json) {
    JsonValue root;
    try {
        root = JsonValue::parse(json);
    } catch (const CipherPathsError&) {
        throw CipherPathsError(ErrorCode::InvalidJson, "credentials.json");
    }
    if (!root.isObject()) throw CipherPathsError(ErrorCode::InvalidJson, "credentials.json");

    PasswordEntry entry;
    entry.folderName = root.getString("folderName");
    const JsonValue& c = root.at("credential");
    entry.credential.type = c.getString("type", "web");
    entry.credential.dateCreated = c.getString("dateCreated");
    entry.credential.lastUpdated = c.getString("lastUpdated");
    entry.credential.passwordUpdated = c.getString("passwordUpdated");
    
    if (c.contains("tags")) {
        const JsonValue& tagsArray = c.at("tags");
        if (tagsArray.isArray()) {
            for (const auto& tag : tagsArray.items()) {
                entry.credential.tags.push_back(tag.asString());
            }
        }
    }
    
    if (entry.credential.type == "web") {
        entry.credential.data = deserializeWebCredential(c);
    } else if (entry.credential.type == "creditcard") {
        entry.credential.data = deserializeCreditCardCredential(c);
    } else if (entry.credential.type == "contact") {
        entry.credential.data = deserializeContactCredential(c);
    } else {
        throw CipherPathsError(ErrorCode::InvalidJson, "unknown credential type");
    }
    
    return entry;
}

// Decrypt and parse the credential file for a top-level folder, or nullopt if absent.
std::optional<PasswordEntry> PasswordEntryService::load(
    const std::filesystem::path& topLevelFolder) const {
    auto child = efs_.findChild(topLevelFolder, kFileName);
    if (!child) return std::nullopt;
    SecureBuffer plain = efs_.readFile(child->diskPath);
    const std::string json(reinterpret_cast<const char*>(plain.data()), plain.size());
    return fromJson(json);
}

// Serialise `entry` and write it as the folder's encrypted credential file.
void PasswordEntryService::save(const std::filesystem::path& topLevelFolder,
                                const PasswordEntry& entry) {
    const std::string json = toJson(entry);
    efs_.writeNewFile(topLevelFolder, kFileName,
                      reinterpret_cast<const uint8_t*>(json.data()), json.size(),
                      /*overwrite=*/true);
}

// Return a fixed-width mask for display, or an empty string for an empty password.
std::string PasswordEntryService::mask(const std::string& password) {
    return password.empty() ? std::string{} : std::string(8, '*');
}

// Return the web-login payload, or nullptr if the credential is not of that type.
WebCredential* PasswordEntryService::getWebCredential(Credential& cred) {
    if (cred.type != "web") return nullptr;
    return std::get_if<WebCredential>(&cred.data);
}

// Const overload of getWebCredential.
const WebCredential* PasswordEntryService::getWebCredential(const Credential& cred) {
    if (cred.type != "web") return nullptr;
    return std::get_if<WebCredential>(&cred.data);
}

// Return the credit-card payload, or nullptr if the credential is not of that type.
CreditCardCredential* PasswordEntryService::getCreditCardCredential(Credential& cred) {
    if (cred.type != "creditcard") return nullptr;
    return std::get_if<CreditCardCredential>(&cred.data);
}

// Const overload of getCreditCardCredential.
const CreditCardCredential* PasswordEntryService::getCreditCardCredential(const Credential& cred) {
    if (cred.type != "creditcard") return nullptr;
    return std::get_if<CreditCardCredential>(&cred.data);
}

// Return the contact-detail payload, or nullptr if the credential is not of that type.
ContactCredential* PasswordEntryService::getContactCredential(Credential& cred) {
    if (cred.type != "contact") return nullptr;
    return std::get_if<ContactCredential>(&cred.data);
}

// Const overload of getContactCredential.
const ContactCredential* PasswordEntryService::getContactCredential(const Credential& cred) {
    if (cred.type != "contact") return nullptr;
    return std::get_if<ContactCredential>(&cred.data);
}

} // namespace cipherpaths
