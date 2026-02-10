#pragma once

#include "common/util.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace common {

inline std::array<uint8_t, 32> sha256(std::span<const uint8_t> data) {
  std::array<uint8_t, 32> out{};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
  unsigned int len = 0;
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
      EVP_DigestFinal_ex(ctx, out.data(), &len) != 1 ||
      len != out.size()) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("sha256 failed");
  }
  EVP_MD_CTX_free(ctx);
  return out;
}

inline bool ed25519_verify_bytes_b64url(std::string_view pubkey_b64url,
                                        std::span<const uint8_t> msg,
                                        std::string_view sig_b64url) {
  const auto pub = base64url_decode(pubkey_b64url);
  const auto sig = base64url_decode(sig_b64url);
  if (!pub || !sig) return false;
  if (pub->size() != 32 || sig->size() != 64) return false;

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub->data(), pub->size());
  if (!pkey) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  bool ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    const int rc = EVP_DigestVerify(ctx, sig->data(), sig->size(), msg.data(), msg.size());
    ok = (rc == 1);
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

struct X25519KeyPair {
  std::array<uint8_t, 32> public_key{};
  std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)> pkey{nullptr, EVP_PKEY_free};
};

inline X25519KeyPair x25519_generate() {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id(X25519) failed");
  EVP_PKEY* k = nullptr;
  if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &k) != 1 || !k) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("X25519 keygen failed");
  }
  EVP_PKEY_CTX_free(ctx);

  X25519KeyPair out;
  out.pkey.reset(k);
  size_t publen = out.public_key.size();
  if (EVP_PKEY_get_raw_public_key(out.pkey.get(), out.public_key.data(), &publen) != 1 ||
      publen != out.public_key.size()) {
    throw std::runtime_error("X25519 get_raw_public_key failed");
  }
  return out;
}

inline std::optional<std::vector<uint8_t>> x25519_derive_shared_secret(EVP_PKEY* priv,
                                                                       std::span<const uint8_t> peer_pub) {
  if (!priv) return std::nullopt;
  if (peer_pub.size() != 32) return std::nullopt;

  EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size());
  if (!peer) return std::nullopt;

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
  if (!ctx) {
    EVP_PKEY_free(peer);
    return std::nullopt;
  }
  if (EVP_PKEY_derive_init(ctx) != 1) {
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return std::nullopt;
  }
  if (EVP_PKEY_derive_set_peer(ctx, peer) != 1) {
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return std::nullopt;
  }

  size_t outlen = 0;
  if (EVP_PKEY_derive(ctx, nullptr, &outlen) != 1 || outlen == 0) {
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return std::nullopt;
  }
  std::vector<uint8_t> out(outlen);
  if (EVP_PKEY_derive(ctx, out.data(), &outlen) != 1) {
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(ctx);
    return std::nullopt;
  }
  out.resize(outlen);
  EVP_PKEY_free(peer);
  EVP_PKEY_CTX_free(ctx);
  return out;
}

inline std::optional<std::array<uint8_t, 32>> hkdf_sha256_32(std::span<const uint8_t> ikm,
                                                             std::span<const uint8_t> salt,
                                                             std::string_view info) {
  EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  if (!kdf) return std::nullopt;
  EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx) return std::nullopt;

  std::array<uint8_t, 32> out{};

  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
  params[1] = OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t*>(salt.data()), salt.size());
  params[2] = OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t*>(ikm.data()), ikm.size());
  params[3] = OSSL_PARAM_construct_octet_string("info", const_cast<char*>(info.data()), info.size());
  params[4] = OSSL_PARAM_construct_end();

  const int ok = EVP_KDF_derive(kctx, out.data(), out.size(), params);
  EVP_KDF_CTX_free(kctx);
  if (ok != 1) return std::nullopt;
  return out;
}

struct AeadKey {
  std::array<uint8_t, 32> key{};
  std::array<uint8_t, 4> nonce_prefix{};
  uint64_t counter = 0;
};

inline std::array<uint8_t, 12> make_nonce(AeadKey& k) {
  std::array<uint8_t, 12> nonce{};
  nonce[0] = k.nonce_prefix[0];
  nonce[1] = k.nonce_prefix[1];
  nonce[2] = k.nonce_prefix[2];
  nonce[3] = k.nonce_prefix[3];
  const uint64_t c = k.counter++;
  nonce[4] = static_cast<uint8_t>((c >> 56) & 0xFF);
  nonce[5] = static_cast<uint8_t>((c >> 48) & 0xFF);
  nonce[6] = static_cast<uint8_t>((c >> 40) & 0xFF);
  nonce[7] = static_cast<uint8_t>((c >> 32) & 0xFF);
  nonce[8] = static_cast<uint8_t>((c >> 24) & 0xFF);
  nonce[9] = static_cast<uint8_t>((c >> 16) & 0xFF);
  nonce[10] = static_cast<uint8_t>((c >> 8) & 0xFF);
  nonce[11] = static_cast<uint8_t>(c & 0xFF);
  return nonce;
}

inline std::optional<std::vector<uint8_t>> aead_chacha20poly1305_encrypt(std::span<const uint8_t> key32,
                                                                         std::span<const uint8_t> nonce12,
                                                                         std::span<const uint8_t> aad,
                                                                         std::span<const uint8_t> plaintext) {
  if (key32.size() != 32 || nonce12.size() != 12) return std::nullopt;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return std::nullopt;

  std::vector<uint8_t> out;
  out.resize(plaintext.size() + 16);
  int len = 0;
  int outlen = 0;

  bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
  ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data()) == 1;
  if (!aad.empty()) {
    ok = ok && EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
  }
  ok = ok && EVP_EncryptUpdate(ctx,
                               out.data(),
                               &len,
                               plaintext.data(),
                               static_cast<int>(plaintext.size())) == 1;
  outlen = len;
  ok = ok && EVP_EncryptFinal_ex(ctx, out.data() + outlen, &len) == 1;
  outlen += len;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + plaintext.size()) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return std::nullopt;
  out.resize(plaintext.size() + 16);
  return out;
}

inline std::optional<std::vector<uint8_t>> aead_chacha20poly1305_decrypt(std::span<const uint8_t> key32,
                                                                         std::span<const uint8_t> nonce12,
                                                                         std::span<const uint8_t> aad,
                                                                         std::span<const uint8_t> ciphertext_and_tag) {
  if (key32.size() != 32 || nonce12.size() != 12) return std::nullopt;
  if (ciphertext_and_tag.size() < 16) return std::nullopt;
  const std::size_t ctlen = ciphertext_and_tag.size() - 16;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return std::nullopt;

  std::vector<uint8_t> out;
  out.resize(ctlen);
  int len = 0;
  int outlen = 0;
  bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
  ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce12.data()) == 1;
  if (!aad.empty()) {
    ok = ok && EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
  }
  ok = ok && EVP_DecryptUpdate(ctx,
                               out.data(),
                               &len,
                               ciphertext_and_tag.data(),
                               static_cast<int>(ctlen)) == 1;
  outlen = len;
  ok = ok && EVP_CIPHER_CTX_ctrl(ctx,
                                EVP_CTRL_AEAD_SET_TAG,
                                16,
                                const_cast<uint8_t*>(ciphertext_and_tag.data() + ctlen)) == 1;
  ok = ok && EVP_DecryptFinal_ex(ctx, out.data() + outlen, &len) == 1;
  outlen += len;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok) return std::nullopt;
  out.resize(outlen);
  return out;
}

} // namespace common
