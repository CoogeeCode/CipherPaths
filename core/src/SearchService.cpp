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

// CipherPaths Core - Search service implementation.
#include "cipherpaths/SearchService.h"

#include "cipherpaths/Errors.h"
#include "cipherpaths/NotesService.h"

#include <algorithm>
#include <cctype>

namespace cipherpaths {

namespace {

// Return an ASCII-lowercased copy of `s`.
std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char> (std::tolower(c)); });
    return s;
}

// Case-insensitive substring test; an empty needle matches everything.
bool containsLower(const std::string& haystack, const std::string& needleLower) {
    if (needleLower.empty()) return true;   // empty query matches everything
    return toLower(haystack).find(needleLower) != std::string::npos;
}

// True for the reserved credential / notes file names handled separately.
bool isSpecialFile(const std::string& name) {
    return name == PasswordEntryService::kFileName || name == NotesService::kFileName;
}

} // namespace

// Recursively scan `dir`, appending every name / credential / notes / content
// match to `out`. `advanced` also scans notes and text file contents.
void SearchService::walk(const std::filesystem::path& dir,
                         std::vector<std::string>& path,
                         const std::string& needleLower, bool advanced,
                         std::vector<SearchHit>& out) const {
    const bool topLevel = (path.size() == 1); // one component below the root
    for (const auto& e : efs_.list(dir)) {
        std::vector<std::string> childPath = path;
        childPath.push_back(e.name);

        if (e.isDirectory) {
            if (containsLower(e.name, needleLower)) {
                out.push_back({SearchHit::Kind::FolderName, e.name, childPath,
                               e.diskPath, e.name, /*isDirectory=*/true});
            }
            walk(e.diskPath, childPath, needleLower, advanced, out);
        } else {
            if (isSpecialFile(e.name)) continue; // handled separately below
            if (containsLower(e.name, needleLower)) {
                out.push_back({SearchHit::Kind::FileName, e.name, childPath,
                               e.diskPath, e.name, /*isDirectory=*/false});
            }
            if (advanced) {
                const std::string lower = toLower(e.name);
                const bool textLike = lower.size() > 4 &&
                    (lower.rfind(".txt") == lower.size() - 4 ||
                     lower.rfind(".md") == lower.size() - 3 ||
                     lower.rfind(".json") == lower.size() - 5 ||
                     lower.rfind(".log") == lower.size() - 4);
                if (textLike) {
                    try {
                        SecureBuffer plain = efs_.readFile(e.diskPath);
                        std::string content(reinterpret_cast<const char*>(plain.data()),
                                            plain.size());
                        if (containsLower(content, needleLower)) {
                            out.push_back({SearchHit::Kind::FileContent, e.name,
                                           childPath, e.diskPath, "(matched contents)",
                                           /*isDirectory=*/false});
                        }
                    } catch (const CipherPathsError&) { /* skip unreadable */ }
                }
            }
        }
    }

    // Credential fields only count at the top level.
    if (topLevel) {
        PasswordEntryService pwd(efs_);
        try {
            if (auto entry = pwd.load(dir)) {
                if (const WebCredential* web =
                        PasswordEntryService::getWebCredential(entry->credential)) {
                    if (containsLower(web->url, needleLower)) {
                        out.push_back({SearchHit::Kind::CredentialUrl, path.back(), path,
                                       dir, web->url, /*isDirectory=*/true});
                    }
                    if (containsLower(web->username, needleLower)) {
                        out.push_back({SearchHit::Kind::CredentialUsername, path.back(), path,
                                       dir, web->username, /*isDirectory=*/true});
                    }
                }
            }
        } catch (const CipherPathsError&) { /* ignore invalid json during search */ }

        if (advanced) {
            NotesService notes(efs_);
            try {
                if (auto text = notes.load(dir)) {
                    if (containsLower(*text, needleLower)) {
                        out.push_back({SearchHit::Kind::NotesText, path.back(), path,
                                       dir, "(matched notes)", /*isDirectory=*/true});
                    }
                }
            } catch (const CipherPathsError&) {}
        }
    }
}

// Basic search over names, credential URLs and usernames.
std::vector<SearchHit> SearchService::search(const std::string& query) const {
    std::vector<SearchHit> out;
    const std::string needle = toLower(query);
    for (const auto& folder : efs_.listTopLevelFolders()) {
        std::vector<std::string> path{folder.name};
        if (containsLower(folder.name, needle)) {
            out.push_back({SearchHit::Kind::FolderName, folder.name, path,
                           folder.diskPath, folder.name, /*isDirectory=*/true});
        }
        walk(folder.diskPath, path, needle, /*advanced=*/false, out);
    }
    return out;
}

// Advanced search: everything search() covers, plus notes and text file contents.
std::vector<SearchHit> SearchService::searchAdvanced(const std::string& query) const {
    std::vector<SearchHit> out;
    const std::string needle = toLower(query);
    for (const auto& folder : efs_.listTopLevelFolders()) {
        std::vector<std::string> path{folder.name};
        if (containsLower(folder.name, needle)) {
            out.push_back({SearchHit::Kind::FolderName, folder.name, path,
                           folder.diskPath, folder.name, /*isDirectory=*/true});
        }
        walk(folder.diskPath, path, needle, /*advanced=*/true, out);
    }
    return out;
}

} // namespace cipherpaths
