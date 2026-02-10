#pragma once

#include <boost/asio.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace common {

inline std::string iso_timestamp_utc() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const std::time_t t = system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif

  char buf[32];
  std::snprintf(buf,
                sizeof(buf),
                "%04d-%02d-%02dT%02d:%02d:%02dZ",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec);
  return buf;
}

inline void log(std::string_view msg) {
  std::cerr << "[" << iso_timestamp_utc() << "] " << msg << "\n";
}

inline std::string endpoint_to_string(const boost::asio::ip::tcp::endpoint& ep) {
  std::ostringstream oss;
  oss << ep.address().to_string() << ":" << ep.port();
  return oss.str();
}

inline bool is_valid_id(std::string_view id, std::size_t min_len = 10, std::size_t max_len = 128) {
  if (id.size() < min_len || id.size() > max_len) return false;
  for (unsigned char ch : id) {
    const bool ok = std::isalnum(ch) || ch == '_' || ch == '-';
    if (!ok) return false;
  }
  return true;
}

inline std::string base64url_encode(std::span<const uint8_t> data) {
  static constexpr char kB64[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);

  std::size_t i = 0;
  while (i + 3 <= data.size()) {
    const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8) |
                       (static_cast<uint32_t>(data[i + 2]));
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back(kB64[(v >> 6) & 0x3F]);
    out.push_back(kB64[v & 0x3F]);
    i += 3;
  }

  const std::size_t rem = data.size() - i;
  if (rem == 1) {
    const uint32_t v = static_cast<uint32_t>(data[i]) << 16;
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2) {
    const uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8);
    out.push_back(kB64[(v >> 18) & 0x3F]);
    out.push_back(kB64[(v >> 12) & 0x3F]);
    out.push_back(kB64[(v >> 6) & 0x3F]);
    out.push_back('=');
  }

  // Make URL-safe and strip padding.
  for (char& c : out) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }
  while (!out.empty() && out.back() == '=') out.pop_back();
  return out;
}

inline std::optional<std::vector<uint8_t>> base64url_decode(std::string_view s) {
  // Convert URL-safe base64url into standard base64 with padding.
  std::string b64;
  b64.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '-') b64.push_back('+');
    else if (c == '_') b64.push_back('/');
    else b64.push_back(c);
  }
  while ((b64.size() % 4) != 0) b64.push_back('=');

  auto val = [](unsigned char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
  };

  if (b64.size() % 4 != 0) return std::nullopt;
  std::vector<uint8_t> out;
  out.reserve((b64.size() / 4) * 3);

  for (std::size_t i = 0; i < b64.size(); i += 4) {
    int v0 = val(static_cast<unsigned char>(b64[i]));
    int v1 = val(static_cast<unsigned char>(b64[i + 1]));
    int v2 = val(static_cast<unsigned char>(b64[i + 2]));
    int v3 = val(static_cast<unsigned char>(b64[i + 3]));
    if (v0 < 0 || v1 < 0 || v2 == -1 || v3 == -1) return std::nullopt;

    const uint32_t n0 = static_cast<uint32_t>(v0);
    const uint32_t n1 = static_cast<uint32_t>(v1);
    const uint32_t n2 = (v2 == -2) ? 0u : static_cast<uint32_t>(v2);
    const uint32_t n3 = (v3 == -2) ? 0u : static_cast<uint32_t>(v3);
    const uint32_t v = (n0 << 18) | (n1 << 12) | (n2 << 6) | n3;

    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    if (v2 != -2) out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    if (v3 != -2) out.push_back(static_cast<uint8_t>(v & 0xFF));
  }
  return out;
}

inline std::string generate_id(std::size_t len = 12) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  thread_local std::mt19937_64 rng{std::random_device{}()};
  std::uniform_int_distribution<std::size_t> dist(0, sizeof(kAlphabet) - 2);
  std::string out;
  out.reserve(len);
  for (std::size_t i = 0; i < len; ++i) out.push_back(kAlphabet[dist(rng)]);
  return out;
}

struct HostPort {
  std::string host;
  uint16_t port = 0;
};

inline std::optional<HostPort> parse_host_port(std::string_view s) {
  // Supports "host:port" and "[ipv6]:port".
  auto trim = [](std::string_view v) {
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.front()))) v.remove_prefix(1);
    while (!v.empty() && std::isspace(static_cast<unsigned char>(v.back()))) v.remove_suffix(1);
    return v;
  };
  s = trim(s);
  if (s.empty()) return std::nullopt;

  std::string_view host;
  std::string_view port_str;

  if (s.front() == '[') {
    const auto rb = s.find(']');
    if (rb == std::string_view::npos) return std::nullopt;
    host = s.substr(1, rb - 1);
    if (rb + 1 >= s.size() || s[rb + 1] != ':') return std::nullopt;
    port_str = s.substr(rb + 2);
  } else {
    const auto colon = s.rfind(':');
    if (colon == std::string_view::npos) return std::nullopt;
    host = s.substr(0, colon);
    port_str = s.substr(colon + 1);
  }

  host = trim(host);
  port_str = trim(port_str);
  if (host.empty() || port_str.empty()) return std::nullopt;

  unsigned long port_ul = 0;
  try {
    port_ul = std::stoul(std::string(port_str));
  } catch (...) {
    return std::nullopt;
  }
  if (port_ul == 0 || port_ul > 65535) return std::nullopt;

  return HostPort{std::string(host), static_cast<uint16_t>(port_ul)};
}

inline uint16_t choose_default_listen_port() {
  thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_int_distribution<int> dist(30000, 40000);
  return static_cast<uint16_t>(dist(rng));
}

} // namespace common
