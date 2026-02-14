#pragma once

#include "common/json.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace common::profile_store {

struct Entry {
  std::string name;
  std::string rel_dir;
  bool encrypted = false;
};

struct Index {
  int format = 1;
  std::string current;
  std::vector<Entry> profiles;
};

inline std::filesystem::path resolve_root() {
  if (const char* env = std::getenv("P2P_CHAT_CONFIG_DIR"); env && *env) {
    return std::filesystem::path(env);
  }
  if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
    return std::filesystem::path(xdg) / "p2p-chat";
  }
  if (const char* home = std::getenv("HOME"); home && *home) {
    return std::filesystem::path(home) / ".config" / "p2p-chat";
  }
  return std::filesystem::path(".") / "p2p-chat";
}

inline std::filesystem::path index_path(const std::filesystem::path& root) {
  return root / "profiles.json";
}

inline std::string slugify(std::string_view in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    const unsigned char uc = static_cast<unsigned char>(c);
    if (std::isalnum(uc)) {
      out.push_back(static_cast<char>(std::tolower(uc)));
    } else if (c == '_' || c == '-') {
      out.push_back(c);
    } else if (std::isspace(uc)) {
      out.push_back('-');
    }
  }
  while (!out.empty() && out.front() == '-') out.erase(out.begin());
  while (!out.empty() && out.back() == '-') out.pop_back();
  if (out.empty()) out = "profile";
  return out;
}

inline bool copy_recursively(const std::filesystem::path& from,
                             const std::filesystem::path& to,
                             std::string* error_out = nullptr) {
  std::error_code ec;
  if (std::filesystem::is_directory(from, ec)) {
    std::filesystem::create_directories(to, ec);
    if (ec) {
      if (error_out) *error_out = "failed to create directory: " + to.string();
      return false;
    }
    for (const auto& entry : std::filesystem::directory_iterator(from, ec)) {
      if (ec) {
        if (error_out) *error_out = "failed to iterate directory: " + from.string();
        return false;
      }
      const auto dst = to / entry.path().filename();
      if (!copy_recursively(entry.path(), dst, error_out)) return false;
    }
    return true;
  }

  std::filesystem::create_directories(to.parent_path(), ec);
  if (ec) {
    if (error_out) *error_out = "failed to create parent directory: " + to.parent_path().string();
    return false;
  }
  std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
  if (ec) {
    if (error_out) *error_out = "failed to copy file: " + from.string();
    return false;
  }
  return true;
}

inline bool move_best_effort(const std::filesystem::path& from,
                             const std::filesystem::path& to,
                             std::string* error_out = nullptr) {
  if (!std::filesystem::exists(from)) return true;
  std::error_code ec;
  std::filesystem::create_directories(to.parent_path(), ec);
  ec.clear();
  std::filesystem::rename(from, to, ec);
  if (!ec) return true;
  if (!copy_recursively(from, to, error_out)) return false;
  std::filesystem::remove_all(from, ec);
  return true;
}

inline bool load_index(const std::filesystem::path& root, Index* out, std::string* error_out = nullptr) {
  if (!out) return false;
  const auto path = index_path(root);
  std::ifstream in(path);
  if (!in) {
    if (error_out) *error_out = "profiles index not found";
    return false;
  }

  json j;
  try {
    j = json::parse(in, nullptr, true, true);
  } catch (const std::exception& e) {
    if (error_out) *error_out = std::string("failed to parse profiles index: ") + e.what();
    return false;
  }
  if (!j.is_object()) {
    if (error_out) *error_out = "profiles index is not an object";
    return false;
  }

  Index idx;
  idx.format = j.value("format", 1);
  idx.current = j.value("current", std::string{});
  if (j.contains("profiles") && j["profiles"].is_array()) {
    for (const auto& v : j["profiles"]) {
      if (!v.is_object()) continue;
      Entry e;
      e.name = v.value("name", std::string{});
      e.rel_dir = v.value("dir", std::string{});
      e.encrypted = v.value("encrypted", false);
      if (e.name.empty() || e.rel_dir.empty()) continue;
      idx.profiles.push_back(std::move(e));
    }
  }
  *out = std::move(idx);
  return true;
}

inline bool save_index(const std::filesystem::path& root, const Index& idx, std::string* error_out = nullptr) {
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  if (ec) {
    if (error_out) *error_out = "failed to create config root: " + root.string();
    return false;
  }

  json j;
  j["format"] = idx.format;
  j["current"] = idx.current;
  j["profiles"] = json::array();
  for (const auto& p : idx.profiles) {
    j["profiles"].push_back({
        {"name", p.name},
        {"dir", p.rel_dir},
        {"encrypted", p.encrypted},
    });
  }

  std::ofstream out(index_path(root), std::ios::trunc);
  if (!out) {
    if (error_out) *error_out = "failed to write profiles index";
    return false;
  }
  out << j.dump(2);
  return true;
}

inline std::filesystem::path profile_dir(const std::filesystem::path& root, const Entry& entry) {
  return root / entry.rel_dir;
}

inline std::optional<Entry> find_profile(const Index& idx, std::string_view name) {
  for (const auto& p : idx.profiles) {
    if (p.name == name) return p;
  }
  return std::nullopt;
}

inline bool ensure_store(const std::filesystem::path& root, std::string* error_out = nullptr) {
  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  if (ec) {
    if (error_out) *error_out = "failed to create config root";
    return false;
  }

  Index idx;
  if (load_index(root, &idx, nullptr)) return true;

  const bool has_legacy =
      std::filesystem::exists(root / "profile.json") ||
      std::filesystem::exists(root / "identity.pem") ||
      std::filesystem::exists(root / "chats") ||
      std::filesystem::exists(root / "avatars");

  idx = {};
  if (has_legacy) {
    Entry e;
    e.name = "default";
    e.rel_dir = "profiles/default";
    e.encrypted = false;
    const auto dst_dir = root / e.rel_dir;
    std::filesystem::create_directories(dst_dir, ec);
    if (ec) {
      if (error_out) *error_out = "failed to create migrated profile directory";
      return false;
    }

    if (!move_best_effort(root / "profile.json", dst_dir / "profile.json", error_out)) return false;
    if (!move_best_effort(root / "identity.pem", dst_dir / "identity.pem", error_out)) return false;
    if (!move_best_effort(root / "chats", dst_dir / "chats", error_out)) return false;
    if (!move_best_effort(root / "avatars", dst_dir / "avatars", error_out)) return false;

    idx.profiles.push_back(e);
    idx.current = e.name;
  }
  return save_index(root, idx, error_out);
}

inline bool create_profile(const std::filesystem::path& root,
                           const std::string& name,
                           bool encrypted,
                           Entry* created,
                           std::string* error_out = nullptr) {
  Index idx;
  if (!ensure_store(root, error_out)) return false;
  if (!load_index(root, &idx, error_out)) return false;

  if (name.empty()) {
    if (error_out) *error_out = "profile name cannot be empty";
    return false;
  }
  if (find_profile(idx, name).has_value()) {
    if (error_out) *error_out = "profile already exists";
    return false;
  }

  std::string slug = slugify(name);
  std::filesystem::path rel = std::filesystem::path("profiles") / slug;
  std::filesystem::path abs = root / rel;
  int suffix = 2;
  while (std::filesystem::exists(abs)) {
    rel = std::filesystem::path("profiles") / (slug + "-" + std::to_string(suffix++));
    abs = root / rel;
  }

  std::error_code ec;
  std::filesystem::create_directories(abs / "chats", ec);
  if (ec) {
    if (error_out) *error_out = "failed to create chats directory";
    return false;
  }
  std::filesystem::create_directories(abs / "avatars", ec);
  if (ec) {
    if (error_out) *error_out = "failed to create avatars directory";
    return false;
  }

  Entry e;
  e.name = name;
  e.rel_dir = rel.generic_string();
  e.encrypted = encrypted;
  idx.profiles.push_back(e);
  idx.current = e.name;
  if (!save_index(root, idx, error_out)) return false;

  if (created) *created = e;
  return true;
}

inline bool set_current(const std::filesystem::path& root,
                        std::string_view name,
                        std::string* error_out = nullptr) {
  Index idx;
  if (!load_index(root, &idx, error_out)) return false;
  if (!find_profile(idx, name).has_value()) {
    if (error_out) *error_out = "profile not found";
    return false;
  }
  idx.current = std::string(name);
  return save_index(root, idx, error_out);
}

} // namespace common::profile_store
