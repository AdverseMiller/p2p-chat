#pragma once

#include "common/util.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace common {

class Identity {
 public:
  static std::shared_ptr<Identity> load_or_create(std::string path) {
    auto id = std::shared_ptr<Identity>(new Identity());
    id->key_path_ = std::move(path);
    if (!id->load_from_disk()) {
      id->generate_new();
      id->save_to_disk_best_effort();
    }
    id->compute_public_id();
    return id;
  }

  std::string_view public_id() const { return public_id_; }

  std::string sign_challenge_b64url(std::string_view challenge_b64url) const {
    const auto msg = base64url_decode(challenge_b64url);
    if (!msg) return {};
    std::vector<uint8_t> sig(64);
    size_t siglen = sig.size();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    const int ok1 = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey_.get());
    int ok2 = 0;
    if (ok1 == 1) ok2 = EVP_DigestSign(ctx, sig.data(), &siglen, msg->data(), msg->size());
    EVP_MD_CTX_free(ctx);
    if (ok2 != 1 || siglen != 64) return {};
    return base64url_encode(std::span<const uint8_t>(sig.data(), siglen));
  }

 private:
  struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
  };
  using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

  Identity() = default;

  static std::string expand_user_path(const std::string& path) {
    if (!path.empty() && path[0] == '~') {
      const char* home = std::getenv("HOME");
      if (!home) return path;
      if (path.size() == 1) return std::string(home);
      if (path[1] == '/') return std::string(home) + path.substr(1);
    }
    return path;
  }

  bool load_from_disk() {
    const std::string p = expand_user_path(key_path_);
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return false;
    EVP_PKEY* k = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (!k) return false;
    pkey_.reset(k);
    return true;
  }

  void generate_new() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    EVP_PKEY* k = nullptr;
    if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &k) != 1 || !k) {
      EVP_PKEY_CTX_free(ctx);
      throw std::runtime_error("Ed25519 keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);
    pkey_.reset(k);
  }

  void save_to_disk_best_effort() {
    const std::string p = expand_user_path(key_path_);
    std::filesystem::path fp(p);
    std::error_code ec;
    std::filesystem::create_directories(fp.parent_path(), ec);

    FILE* f = std::fopen(p.c_str(), "wb");
    if (!f) return;
    (void)PEM_write_PrivateKey(f, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);
    std::filesystem::permissions(fp,
                                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                std::filesystem::perm_options::replace,
                                ec);
  }

  void compute_public_id() {
    std::array<uint8_t, 32> pub{};
    size_t publen = pub.size();
    if (EVP_PKEY_get_raw_public_key(pkey_.get(), pub.data(), &publen) != 1 || publen != pub.size()) {
      throw std::runtime_error("failed to get public key");
    }
    public_id_ = base64url_encode(std::span<const uint8_t>(pub.data(), pub.size()));
  }

  std::string key_path_;
  PkeyPtr pkey_{nullptr};
  std::string public_id_;
};

} // namespace common

