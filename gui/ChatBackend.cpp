#include "gui/ChatBackend.hpp"
#include "gui/Profile.hpp"

#include "common/crypto.hpp"
#include "common/framing.hpp"
#include "common/identity.hpp"
#include "common/upnp.hpp"
#include "common/util.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using common::json;

namespace {
constexpr auto kHeartbeatInterval = std::chrono::seconds(15);
constexpr auto kPollInterval = std::chrono::seconds(4);
constexpr auto kConnectTimeout = std::chrono::seconds(10);
constexpr auto kUdpPunchInterval = std::chrono::milliseconds(250);
constexpr auto kUdpHandshakeResend = std::chrono::milliseconds(400);
constexpr auto kUdpDataResend = std::chrono::milliseconds(500);

class PeerSession : public std::enable_shared_from_this<PeerSession> {
public:
  enum class Role { Initiator, Acceptor };
  using OnReady = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnName = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnChat = std::function<void(const std::string& peer_id, const std::string& peer_name, const std::string& text)>;
  using OnClosed = std::function<void()>;

  PeerSession(tcp::socket socket,
              Role role,
              std::string self_id,
              std::shared_ptr<common::Identity> identity,
              std::function<std::string()> get_self_name,
              std::function<bool(const std::string&)> allow_peer,
              std::string expected_peer_id = {})
      : socket_(std::move(socket)),
        role_(role),
        self_id_(std::move(self_id)),
        identity_(std::move(identity)),
        get_self_name_(std::move(get_self_name)),
        allow_peer_(std::move(allow_peer)),
        expected_peer_id_(std::move(expected_peer_id)),
        writer_(std::make_shared<common::JsonWriteQueue<tcp::socket>>(socket_)) {}

  void start(OnReady on_ready, OnName on_name, OnChat on_chat, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    if (role_ == Role::Initiator) {
      start_secure_initiator();
    } else {
      wait_for_secure_hello();
    }
  }

  void start_accept_with_first(json first, OnReady on_ready, OnName on_name, OnChat on_chat, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    if (!first.contains("type") || !first["type"].is_string()) return send_error_and_close("missing type");
    const std::string type = first["type"].get<std::string>();
    if (type != "secure_hello") return send_error_and_close("expected secure_hello");
    handle_secure_hello(std::move(first));
  }

  void send_chat(std::string text) {
    if (!ready_) return;
    json inner;
    inner["type"] = "chat";
    inner["text"] = std::move(text);
    send_secure(std::move(inner));
  }

  void send_name(std::string name) {
    if (!ready_) return;
    if (name.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = std::move(name);
    send_secure(std::move(inner));
  }

  void close() {
    if (closed_) return;
    closed_ = true;
    boost::system::error_code ignored;
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    if (on_closed_) on_closed_();
  }

  std::string_view peer_id() const { return peer_id_; }
  std::string_view peer_name() const { return peer_name_; }

private:
  static constexpr std::string_view kProto = "p2p-chat-secure-v1";

  static std::vector<uint8_t> bytes(std::string_view s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                reinterpret_cast<const uint8_t*>(s.data() + s.size()));
  }

  static std::string transcript_string(std::string_view init_id,
                                       std::string_view init_eph_b64,
                                       std::string_view resp_id,
                                       std::string_view resp_eph_b64) {
    std::string t;
    t.reserve(kProto.size() + init_id.size() + init_eph_b64.size() + resp_id.size() + resp_eph_b64.size() + 16);
    t.append(kProto);
    t.push_back('|');
    t.append(init_id);
    t.push_back('|');
    t.append(init_eph_b64);
    t.push_back('|');
    t.append(resp_id);
    t.push_back('|');
    t.append(resp_eph_b64);
    return t;
  }

  void send_error_and_close(std::string message) {
    auto self = shared_from_this();
    json e;
    e["type"] = "error";
    e["message"] = std::move(message);
    common::async_write_json(socket_, e, [self](const boost::system::error_code&) { self->close(); });
  }

  void start_secure_initiator() {
    if (!identity_) return send_error_and_close("identity not loaded");
    eph_ = common::x25519_generate();
    const std::string eph_b64 = common::base64url_encode(eph_->public_key);

    // Signature binds claimed identity to initiator ephemeral key.
    const std::string sig_msg = std::string(kProto) + "|init|" + self_id_ + "|" + eph_b64;
    const std::string sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sig_msg.data()), sig_msg.size()));
    if (sig.empty()) return send_error_and_close("failed to sign");

    json hello;
    hello["type"] = "secure_hello";
    hello["id"] = self_id_;
    hello["eph"] = eph_b64;
    hello["sig"] = sig;
    writer_->send(std::move(hello));
    wait_for_secure_hello_ack();
  }

  void wait_for_secure_hello() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "secure_hello") {
        return self->send_error_and_close("expected secure_hello");
      }
      self->handle_secure_hello(std::move(j));
    });
  }

  void handle_secure_hello(json j) {
    if (!identity_) return send_error_and_close("identity not loaded");
    if (!j.contains("id") || !j["id"].is_string()) return send_error_and_close("secure_hello missing id");
    if (!j.contains("eph") || !j["eph"].is_string()) return send_error_and_close("secure_hello missing eph");
    if (!j.contains("sig") || !j["sig"].is_string()) return send_error_and_close("secure_hello missing sig");

    const std::string init_id = j["id"].get<std::string>();
    if (!common::is_valid_id(init_id)) return send_error_and_close("invalid peer id");
    if (allow_peer_ && !allow_peer_(init_id)) return send_error_and_close("not friends");

    const std::string init_eph_b64 = j["eph"].get<std::string>();
    const auto init_eph = common::base64url_decode(init_eph_b64);
    if (!init_eph || init_eph->size() != 32) return send_error_and_close("invalid eph");

    // Verify initiator signature.
    const std::string sig_msg = std::string(kProto) + "|init|" + init_id + "|" + init_eph_b64;
    const auto sig_msg_bytes = bytes(sig_msg);
    if (!common::Identity::verify_bytes_b64url(init_id, sig_msg_bytes, j["sig"].get<std::string>())) {
      return send_error_and_close("bad signature");
    }

    // Generate responder ephemeral and reply with ack signature over full transcript.
    peer_id_ = init_id;
    peer_eph_pub_ = *init_eph;
    eph_ = common::x25519_generate();
    const std::string resp_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(init_id, init_eph_b64, self_id_, resp_eph_b64);

    const std::string ack_msg = transcript_ + "|resp";
    const std::string ack_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(ack_msg.data()), ack_msg.size()));
    if (ack_sig.empty()) return send_error_and_close("failed to sign");

    json ack;
    ack["type"] = "secure_hello_ack";
    ack["id"] = self_id_;
    ack["eph"] = resp_eph_b64;
    ack["sig"] = ack_sig;
    writer_->send(std::move(ack));
    wait_for_secure_finish();
  }

  void wait_for_secure_hello_ack() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string()) return self->send_error_and_close("missing type");
      const std::string type = j["type"].get<std::string>();
      if (type == "busy") return self->send_error_and_close("peer busy");
      if (type != "secure_hello_ack") return self->send_error_and_close("expected secure_hello_ack");
      if (!j.contains("id") || !j["id"].is_string()) return self->send_error_and_close("secure_hello_ack missing id");
      if (!j.contains("eph") || !j["eph"].is_string()) return self->send_error_and_close("secure_hello_ack missing eph");
      if (!j.contains("sig") || !j["sig"].is_string()) return self->send_error_and_close("secure_hello_ack missing sig");

      const std::string resp_id = j["id"].get<std::string>();
      if (!common::is_valid_id(resp_id)) return self->send_error_and_close("invalid peer id");
      if (!self->expected_peer_id_.empty() && resp_id != self->expected_peer_id_) {
        return self->send_error_and_close("unexpected peer id");
      }
      if (self->allow_peer_ && !self->allow_peer_(resp_id)) return self->send_error_and_close("not friends");

      const std::string resp_eph_b64 = j["eph"].get<std::string>();
      const auto resp_eph = common::base64url_decode(resp_eph_b64);
      if (!resp_eph || resp_eph->size() != 32) return self->send_error_and_close("invalid eph");

      const std::string init_eph_b64 = common::base64url_encode(self->eph_->public_key);
      self->transcript_ = transcript_string(self->self_id_, init_eph_b64, resp_id, resp_eph_b64);
      const std::string ack_msg = self->transcript_ + "|resp";
      const auto ack_msg_bytes = bytes(ack_msg);
      if (!common::Identity::verify_bytes_b64url(resp_id, ack_msg_bytes, j["sig"].get<std::string>())) {
        return self->send_error_and_close("bad signature");
      }

      self->peer_id_ = resp_id;
      self->peer_eph_pub_ = *resp_eph;

      // Send finish signature binding initiator to full transcript.
      const std::string fin_msg = self->transcript_ + "|init";
      const std::string fin_sig = self->identity_->sign_bytes_b64url(std::span<const uint8_t>(
          reinterpret_cast<const uint8_t*>(fin_msg.data()), fin_msg.size()));
      if (fin_sig.empty()) return self->send_error_and_close("failed to sign");
      json fin;
      fin["type"] = "secure_finish";
      fin["sig"] = fin_sig;
      self->writer_->send(std::move(fin));

      if (!self->derive_keys()) return self->send_error_and_close("key derivation failed");
      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      self->send_name_update();
      self->read_loop_secure();
    });
  }

  void wait_for_secure_finish() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "secure_finish") {
        return self->send_error_and_close("expected secure_finish");
      }
      if (!j.contains("sig") || !j["sig"].is_string()) return self->send_error_and_close("secure_finish missing sig");
      const std::string fin_sig = j["sig"].get<std::string>();
      const std::string fin_msg = self->transcript_ + "|init";
      const auto fin_msg_bytes = bytes(fin_msg);
      if (!common::Identity::verify_bytes_b64url(self->peer_id_, fin_msg_bytes, fin_sig)) {
        return self->send_error_and_close("bad signature");
      }
      if (!self->derive_keys()) return self->send_error_and_close("key derivation failed");
      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      self->send_name_update();
      self->read_loop_secure();
    });
  }

  bool derive_keys() {
    if (!eph_) return false;
    if (peer_eph_pub_.size() != 32) return false;

    const auto shared = common::x25519_derive_shared_secret(eph_->pkey.get(), peer_eph_pub_);
    if (!shared) return false;

    const auto salt = common::sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(transcript_.data()), transcript_.size()));

    auto hkdf32 = [&](std::string_view info) -> std::optional<std::array<uint8_t, 32>> {
      return common::hkdf_sha256_32(*shared, salt, info);
    };

    const auto k_init_to_resp = hkdf32(std::string(kProto) + " key init->resp");
    const auto k_resp_to_init = hkdf32(std::string(kProto) + " key resp->init");
    const auto n_init_to_resp = hkdf32(std::string(kProto) + " nonce init->resp");
    const auto n_resp_to_init = hkdf32(std::string(kProto) + " nonce resp->init");
    if (!k_init_to_resp || !k_resp_to_init || !n_init_to_resp || !n_resp_to_init) return false;

    if (role_ == Role::Initiator) {
      send_key_.key = *k_init_to_resp;
      recv_key_.key = *k_resp_to_init;
      std::copy_n(n_init_to_resp->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_resp_to_init->data(), 4, recv_nonce_prefix_.data());
    } else {
      send_key_.key = *k_resp_to_init;
      recv_key_.key = *k_init_to_resp;
      std::copy_n(n_resp_to_init->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_init_to_resp->data(), 4, recv_nonce_prefix_.data());
    }
    send_key_.counter = 0;
    recv_expected_seq_ = 0;
    return true;
  }

  void send_name_update() {
    const auto nm = get_self_name_ ? get_self_name_() : std::string();
    if (nm.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = nm;
    send_secure(std::move(inner));
  }

  void send_secure(json inner) {
    if (!ready_) return;
    const std::string pt = inner.dump();
    const uint64_t seq = send_key_.counter; // make_nonce increments; keep seq consistent with counter pre-increment.
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = common::make_nonce(send_key_);
    const auto ct = common::aead_chacha20poly1305_encrypt(
        send_key_.key, nonce, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pt.data()), pt.size()));
    if (!ct) return close();

    json outer;
    outer["type"] = "secure_msg";
    outer["seq"] = static_cast<std::uint64_t>(seq);
    outer["ct"] = common::base64url_encode(*ct);
    writer_->send(std::move(outer));
  }

  std::array<uint8_t, 12> make_recv_nonce(uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = recv_nonce_prefix_[0];
    nonce[1] = recv_nonce_prefix_[1];
    nonce[2] = recv_nonce_prefix_[2];
    nonce[3] = recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  void read_loop_secure() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string()) {
        self->read_loop_secure();
        return;
      }
      const std::string type = j["type"].get<std::string>();
      if (type == "secure_msg") {
        if (!j.contains("seq") || !j["seq"].is_number_unsigned() || !j.contains("ct") || !j["ct"].is_string()) {
          return self->send_error_and_close("bad secure_msg");
        }
        const uint64_t seq = j["seq"].get<std::uint64_t>();
        if (seq != self->recv_expected_seq_) return self->send_error_and_close("out of order");
        const auto ct = common::base64url_decode(j["ct"].get<std::string>());
        if (!ct) return self->send_error_and_close("bad ct");
        const std::string aad = self->transcript_ + "|msg|" + std::to_string(seq);
        const auto nonce = self->make_recv_nonce(seq);
        const auto pt = common::aead_chacha20poly1305_decrypt(
            self->recv_key_.key,
            nonce,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
            *ct);
        if (!pt) return self->send_error_and_close("decrypt failed");
        self->recv_expected_seq_++;
        try {
          const std::string s(reinterpret_cast<const char*>(pt->data()), pt->size());
          json inner = json::parse(s);
          self->handle_inner(std::move(inner));
        } catch (...) {
          return self->send_error_and_close("bad inner json");
        }
      }
      self->read_loop_secure();
    });
  }

  void handle_inner(json inner) {
    if (!inner.contains("type") || !inner["type"].is_string()) return;
    const std::string t = inner["type"].get<std::string>();
    if (t == "chat") {
      if (inner.contains("text") && inner["text"].is_string()) {
        const std::string text = inner["text"].get<std::string>();
        if (on_chat_) on_chat_(peer_id_, peer_name_, text);
      }
      return;
    }
    if (t == "name") {
      if (inner.contains("name") && inner["name"].is_string()) {
        peer_name_ = inner["name"].get<std::string>();
        if (on_name_) on_name_(peer_id_, peer_name_);
      }
      return;
    }
  }

  tcp::socket socket_;
  Role role_;
  std::string self_id_;
  std::shared_ptr<common::Identity> identity_;
  std::function<std::string()> get_self_name_;
  std::string peer_id_;
  std::string peer_name_;
  std::string expected_peer_id_;
  std::function<bool(const std::string&)> allow_peer_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;
  bool ready_ = false;
  bool closed_ = false;
  OnReady on_ready_;
  OnName on_name_;
  OnChat on_chat_;
  OnClosed on_closed_;

  std::optional<common::X25519KeyPair> eph_;
  std::vector<uint8_t> peer_eph_pub_;
  std::string transcript_;
  common::AeadKey send_key_;
  common::AeadKey recv_key_;
  std::array<uint8_t, 4> recv_nonce_prefix_{};
  uint64_t recv_expected_seq_ = 0;
};

class UdpPeerSession : public std::enable_shared_from_this<UdpPeerSession> {
public:
  enum class Role { Initiator, Acceptor };
  using OnReady = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnName = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnChat = std::function<void(const std::string& peer_id, const std::string& peer_name, const std::string& text)>;
  using OnClosed = std::function<void()>;

  UdpPeerSession(udp::socket& socket,
                 udp::endpoint peer_ep,
                 Role role,
                 std::string self_id,
                 std::shared_ptr<common::Identity> identity,
                 std::function<std::string()> get_self_name,
                 std::function<bool(const std::string&)> allow_peer,
                 std::string expected_peer_id = {})
      : socket_(socket),
        peer_ep_(std::move(peer_ep)),
        role_(role),
        self_id_(std::move(self_id)),
        identity_(std::move(identity)),
        get_self_name_(std::move(get_self_name)),
        allow_peer_(std::move(allow_peer)),
        expected_peer_id_(std::move(expected_peer_id)),
        punch_timer_(socket_.get_executor()),
        hs_timer_(socket_.get_executor()),
        data_timer_(socket_.get_executor()),
        deadline_timer_(socket_.get_executor()),
        keepalive_timer_(socket_.get_executor()) {}

  void start(OnReady on_ready, OnName on_name, OnChat on_chat, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    schedule_punch();
    schedule_deadline();
    if (role_ == Role::Initiator) {
      send_secure_hello();
    }
  }

  void start_accept_with_first(const json& first, const udp::endpoint& from, OnReady on_ready, OnName on_name,
                               OnChat on_chat, OnClosed on_closed) {
    peer_ep_ = from;
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    schedule_punch();
    schedule_deadline();
    handle_datagram(first, from);
  }

  void handle_datagram(const json& j, const udp::endpoint& from) {
    if (closed_) return;
    // Lock peer endpoint once we have it (initiator already has it; acceptor learns it from first packet).
    if (peer_ep_.port() != 0 && from != peer_ep_) {
      // Before the handshake is confirmed, allow the peer's NAT mapping to "settle" to a final port.
      if (!ready_confirmed_ && from.address() == peer_ep_.address()) {
        peer_ep_ = from;
      } else {
        return;
      }
    }

    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();
    if (type == "punch") return;
    if (type == "secure_hello") return handle_secure_hello(j);
    if (type == "secure_hello_ack") return handle_secure_hello_ack(j);
    if (type == "secure_finish") return handle_secure_finish(j);
    if (type == "secure_msg") return handle_secure_msg(j);
    if (type == "ack") return handle_ack(j);
    if (type == "busy" || type == "error") return close();
  }

  void send_chat(std::string text) {
    if (text.empty()) return;
    json inner;
    inner["type"] = "chat";
    inner["text"] = std::move(text);
    enqueue_secure(std::move(inner));
  }

  void send_name(std::string name) {
    if (name.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = std::move(name);
    enqueue_secure(std::move(inner));
  }

  void close() {
    if (closed_) return;
    closed_ = true;
    punch_timer_.cancel();
    hs_timer_.cancel();
    data_timer_.cancel();
    deadline_timer_.cancel();
    keepalive_timer_.cancel();
    if (on_closed_) on_closed_();
  }

  std::string_view peer_id() const { return peer_id_; }
  std::string_view peer_name() const { return peer_name_; }
  const udp::endpoint& peer_endpoint() const { return peer_ep_; }

private:
  static constexpr std::string_view kProto = "p2p-chat-secure-v1";

  static std::vector<uint8_t> bytes(std::string_view s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                reinterpret_cast<const uint8_t*>(s.data() + s.size()));
  }

  static std::string transcript_string(std::string_view init_id,
                                       std::string_view init_eph_b64,
                                       std::string_view resp_id,
                                       std::string_view resp_eph_b64) {
    std::string t;
    t.reserve(kProto.size() + init_id.size() + init_eph_b64.size() + resp_id.size() + resp_eph_b64.size() + 16);
    t.append(kProto);
    t.push_back('|');
    t.append(init_id);
    t.push_back('|');
    t.append(init_eph_b64);
    t.push_back('|');
    t.append(resp_id);
    t.push_back('|');
    t.append(resp_eph_b64);
    return t;
  }

  void send_datagram(const json& j) {
    auto framed = common::frame_json_bytes(j);
    if (!framed) return;
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(*framed));
    auto self = shared_from_this();
    socket_.async_send_to(boost::asio::buffer(*buf), peer_ep_, [self, buf](const boost::system::error_code&, std::size_t) {});
  }

  void send_punch_once() {
    json p;
    p["type"] = "punch";
    send_datagram(p);
  }

  void schedule_punch() {
    if (closed_) return;
    if (punch_remaining_ == 0) return;
    send_punch_once();
    punch_remaining_--;
    auto self = shared_from_this();
    punch_timer_.expires_after(kUdpPunchInterval);
    punch_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      self->schedule_punch();
    });
  }

  void schedule_deadline() {
    auto self = shared_from_this();
    deadline_timer_.expires_after(std::chrono::seconds(25));
    deadline_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_) return;
      if (!self->ready_confirmed_) self->close();
    });
  }

  void schedule_keepalive() {
    if (closed_ || !ready_confirmed_) return;
    auto self = shared_from_this();
    keepalive_timer_.expires_after(std::chrono::seconds(15));
    keepalive_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_) return;
      if (self->ready_confirmed_) self->send_punch_once();
      self->schedule_keepalive();
    });
  }

  void send_secure_hello() {
    if (!identity_) return close();
    if (hello_sent_) return;
    eph_ = common::x25519_generate();
    const std::string eph_b64 = common::base64url_encode(eph_->public_key);
    const std::string sig_msg = std::string(kProto) + "|init|" + self_id_ + "|" + eph_b64;
    const std::string sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sig_msg.data()), sig_msg.size()));
    if (sig.empty()) return close();

    json hello;
    hello["type"] = "secure_hello";
    hello["id"] = self_id_;
    hello["eph"] = eph_b64;
    hello["sig"] = sig;

    hello_sent_ = true;
    last_hs_msg_ = hello;
    send_datagram(hello);
    schedule_hs_resend();
  }

  void schedule_hs_resend() {
    if (closed_) return;
    if (ready_confirmed_) return;
    if (last_hs_msg_.is_null()) return;
    auto self = shared_from_this();
    hs_timer_.expires_after(kUdpHandshakeResend);
    hs_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_ || self->ready_confirmed_) return;
      if (self->last_hs_msg_.is_null()) return;
      if (++self->hs_retries_ > 30) return self->close();
      self->send_datagram(self->last_hs_msg_);
      self->schedule_hs_resend();
    });
  }

  void handle_secure_hello(const json& j) {
    if (role_ != Role::Acceptor) return;
    if (!identity_) return close();
    if (!j.contains("id") || !j["id"].is_string()) return close();
    if (!j.contains("eph") || !j["eph"].is_string()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();

    const std::string init_id = j["id"].get<std::string>();
    if (!common::is_valid_id(init_id)) return close();
    if (allow_peer_ && !allow_peer_(init_id)) return close();

    const std::string init_eph_b64 = j["eph"].get<std::string>();
    const auto init_eph = common::base64url_decode(init_eph_b64);
    if (!init_eph || init_eph->size() != 32) return close();

    const std::string sig_msg = std::string(kProto) + "|init|" + init_id + "|" + init_eph_b64;
    const auto sig_msg_bytes = bytes(sig_msg);
    if (!common::Identity::verify_bytes_b64url(init_id, sig_msg_bytes, j["sig"].get<std::string>())) return close();

    peer_id_ = init_id;
    peer_eph_pub_ = *init_eph;
    eph_ = common::x25519_generate();
    const std::string resp_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(init_id, init_eph_b64, self_id_, resp_eph_b64);

    const std::string ack_msg = transcript_ + "|resp";
    const std::string ack_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(ack_msg.data()), ack_msg.size()));
    if (ack_sig.empty()) return close();

    json ack;
    ack["type"] = "secure_hello_ack";
    ack["id"] = self_id_;
    ack["eph"] = resp_eph_b64;
    ack["sig"] = ack_sig;
    last_hs_msg_ = ack;
    send_datagram(ack);
    // Wait for finish; keep resending ack for a short while (duplicate hellos will also refresh it).
    schedule_hs_resend();
  }

  void handle_secure_hello_ack(const json& j) {
    if (role_ != Role::Initiator) return;
    if (!identity_ || !eph_) return close();
    if (!j.contains("id") || !j["id"].is_string()) return close();
    if (!j.contains("eph") || !j["eph"].is_string()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();

    const std::string resp_id = j["id"].get<std::string>();
    if (!common::is_valid_id(resp_id)) return close();
    if (!expected_peer_id_.empty() && resp_id != expected_peer_id_) return close();
    if (allow_peer_ && !allow_peer_(resp_id)) return close();

    const std::string resp_eph_b64 = j["eph"].get<std::string>();
    const auto resp_eph = common::base64url_decode(resp_eph_b64);
    if (!resp_eph || resp_eph->size() != 32) return close();

    const std::string init_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(self_id_, init_eph_b64, resp_id, resp_eph_b64);
    const std::string ack_msg = transcript_ + "|resp";
    const auto ack_msg_bytes = bytes(ack_msg);
    if (!common::Identity::verify_bytes_b64url(resp_id, ack_msg_bytes, j["sig"].get<std::string>())) return close();

    peer_id_ = resp_id;
    peer_eph_pub_ = *resp_eph;

    const std::string fin_msg = transcript_ + "|init";
    const std::string fin_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(fin_msg.data()), fin_msg.size()));
    if (fin_sig.empty()) return close();
    json fin;
    fin["type"] = "secure_finish";
    fin["sig"] = fin_sig;
    last_hs_msg_ = fin;
    send_datagram(fin);

    if (!derive_keys()) return close();
    ready_ = true;
    if (on_ready_) on_ready_(peer_id_, peer_name_);
    send_name_update();
    try_send_next();
    // Keep resending finish until the peer proves readiness (ack/secure_msg).
    schedule_hs_resend();
  }

  void handle_secure_finish(const json& j) {
    if (role_ != Role::Acceptor) return;
    if (!identity_ || transcript_.empty() || peer_id_.empty()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();
    const std::string fin_sig = j["sig"].get<std::string>();
    const std::string fin_msg = transcript_ + "|init";
    const auto fin_msg_bytes = bytes(fin_msg);
    if (!common::Identity::verify_bytes_b64url(peer_id_, fin_msg_bytes, fin_sig)) return close();

    if (!derive_keys()) return close();
    ready_ = true;
    ready_confirmed_ = true; // acceptor knows both sides are ready at this point
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    schedule_keepalive();
    if (on_ready_) on_ready_(peer_id_, peer_name_);
    send_name_update();
    try_send_next();
  }

  bool derive_keys() {
    if (!eph_) return false;
    if (peer_eph_pub_.size() != 32) return false;

    const auto shared = common::x25519_derive_shared_secret(eph_->pkey.get(), peer_eph_pub_);
    if (!shared) return false;

    const auto salt = common::sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(transcript_.data()), transcript_.size()));

    auto hkdf32 = [&](std::string_view info) -> std::optional<std::array<uint8_t, 32>> {
      return common::hkdf_sha256_32(*shared, salt, info);
    };

    const auto k_init_to_resp = hkdf32(std::string(kProto) + " key init->resp");
    const auto k_resp_to_init = hkdf32(std::string(kProto) + " key resp->init");
    const auto n_init_to_resp = hkdf32(std::string(kProto) + " nonce init->resp");
    const auto n_resp_to_init = hkdf32(std::string(kProto) + " nonce resp->init");
    const auto ak_init_to_resp = hkdf32(std::string(kProto) + " ack key init->resp");
    const auto ak_resp_to_init = hkdf32(std::string(kProto) + " ack key resp->init");
    const auto an_init_to_resp = hkdf32(std::string(kProto) + " ack nonce init->resp");
    const auto an_resp_to_init = hkdf32(std::string(kProto) + " ack nonce resp->init");
    if (!k_init_to_resp || !k_resp_to_init || !n_init_to_resp || !n_resp_to_init ||
        !ak_init_to_resp || !ak_resp_to_init || !an_init_to_resp || !an_resp_to_init) return false;

    if (role_ == Role::Initiator) {
      send_key_.key = *k_init_to_resp;
      recv_key_.key = *k_resp_to_init;
      std::copy_n(n_init_to_resp->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_resp_to_init->data(), 4, recv_nonce_prefix_.data());

      ack_send_key_ = *ak_resp_to_init;
      ack_recv_key_ = *ak_init_to_resp;
      std::copy_n(an_resp_to_init->data(), 4, ack_send_nonce_prefix_.data());
      std::copy_n(an_init_to_resp->data(), 4, ack_recv_nonce_prefix_.data());
    } else {
      send_key_.key = *k_resp_to_init;
      recv_key_.key = *k_init_to_resp;
      std::copy_n(n_resp_to_init->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_init_to_resp->data(), 4, recv_nonce_prefix_.data());

      ack_send_key_ = *ak_init_to_resp;
      ack_recv_key_ = *ak_resp_to_init;
      std::copy_n(an_init_to_resp->data(), 4, ack_send_nonce_prefix_.data());
      std::copy_n(an_resp_to_init->data(), 4, ack_recv_nonce_prefix_.data());
    }
    send_key_.counter = 0;
    recv_expected_seq_ = 0;
    return true;
  }

  void send_name_update() {
    const auto nm = get_self_name_ ? get_self_name_() : std::string();
    if (nm.empty()) return;
    send_name(nm);
  }

  void enqueue_secure(json inner) {
    if (closed_) return;
    send_queue_.push_back(std::move(inner));
    // Cap pre-handshake queue size.
    if (send_queue_.size() > 256) send_queue_.pop_front();
    if (ready_) try_send_next();
  }

  void try_send_next() {
    if (!ready_ || closed_ || inflight_) return;
    if (send_queue_.empty()) return;
    json inner = std::move(send_queue_.front());
    send_queue_.pop_front();

    const std::string pt = inner.dump();
    const uint64_t seq = send_key_.counter;
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = common::make_nonce(send_key_);
    const auto ct = common::aead_chacha20poly1305_encrypt(
        send_key_.key, nonce, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pt.data()), pt.size()));
    if (!ct) return close();

    json outer;
    outer["type"] = "secure_msg";
    outer["seq"] = static_cast<std::uint64_t>(seq);
    outer["ct"] = common::base64url_encode(*ct);

    inflight_ = true;
    inflight_seq_ = seq;
    inflight_outer_ = outer;
    inflight_retries_ = 0;
    send_datagram(outer);
    schedule_data_resend();
  }

  void schedule_data_resend() {
    if (closed_) return;
    if (!inflight_) return;
    auto self = shared_from_this();
    data_timer_.expires_after(kUdpDataResend);
    data_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_ || !self->inflight_) return;
      if (++self->inflight_retries_ > 12) return self->close();
      self->send_datagram(self->inflight_outer_);
      self->schedule_data_resend();
    });
  }

  std::array<uint8_t, 12> make_recv_nonce(uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = recv_nonce_prefix_[0];
    nonce[1] = recv_nonce_prefix_[1];
    nonce[2] = recv_nonce_prefix_[2];
    nonce[3] = recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  std::array<uint8_t, 12> make_ack_nonce(std::array<uint8_t, 4> prefix, uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = prefix[0];
    nonce[1] = prefix[1];
    nonce[2] = prefix[2];
    nonce[3] = prefix[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  void send_ack(uint64_t seq) {
    if (!ready_) return;
    const std::string aad = transcript_ + "|ack|" + std::to_string(seq);
    const auto nonce = make_ack_nonce(ack_send_nonce_prefix_, seq);
    const auto tag = common::aead_chacha20poly1305_encrypt(
        ack_send_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>{});
    if (!tag || tag->size() != 16) return;
    json a;
    a["type"] = "ack";
    a["seq"] = static_cast<std::uint64_t>(seq);
    a["tag"] = common::base64url_encode(*tag);
    send_datagram(a);
  }

  void handle_ack(const json& j) {
    if (!inflight_ || !ready_) return;
    if (!j.contains("seq") || !j["seq"].is_number_unsigned()) return;
    if (!j.contains("tag") || !j["tag"].is_string()) return;
    const uint64_t seq = j["seq"].get<std::uint64_t>();
    if (seq != inflight_seq_) return;
    const auto tag = common::base64url_decode(j["tag"].get<std::string>());
    if (!tag || tag->size() != 16) return;
    const std::string aad = transcript_ + "|ack|" + std::to_string(seq);
    const auto nonce = make_ack_nonce(ack_recv_nonce_prefix_, seq);
    const auto pt = common::aead_chacha20poly1305_decrypt(
        ack_recv_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        *tag);
    if (!pt || !pt->empty()) return;

    inflight_ = false;
    ready_confirmed_ = true;
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    data_timer_.cancel();
    schedule_keepalive();
    try_send_next();
  }

  void handle_secure_msg(const json& j) {
    if (!ready_) return;
    if (!j.contains("seq") || !j["seq"].is_number_unsigned()) return;
    if (!j.contains("ct") || !j["ct"].is_string()) return;
    const uint64_t seq = j["seq"].get<std::uint64_t>();

    if (seq < recv_expected_seq_) {
      send_ack(seq);
      return;
    }
    if (seq != recv_expected_seq_) return;

    const auto ct = common::base64url_decode(j["ct"].get<std::string>());
    if (!ct) return;
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = make_recv_nonce(seq);
    const auto pt = common::aead_chacha20poly1305_decrypt(
        recv_key_.key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        *ct);
    if (!pt) return;
    recv_expected_seq_++;
    send_ack(seq);

    ready_confirmed_ = true;
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    schedule_keepalive();

    try {
      const std::string s(reinterpret_cast<const char*>(pt->data()), pt->size());
      json inner = json::parse(s);
      handle_inner(std::move(inner));
    } catch (...) {
      return;
    }
  }

  void handle_inner(json inner) {
    if (!inner.contains("type") || !inner["type"].is_string()) return;
    const std::string t = inner["type"].get<std::string>();
    if (t == "chat") {
      if (inner.contains("text") && inner["text"].is_string()) {
        const std::string text = inner["text"].get<std::string>();
        if (on_chat_) on_chat_(peer_id_, peer_name_, text);
      }
      return;
    }
    if (t == "name") {
      if (inner.contains("name") && inner["name"].is_string()) {
        peer_name_ = inner["name"].get<std::string>();
        if (on_name_) on_name_(peer_id_, peer_name_);
      }
      return;
    }
  }

  udp::socket& socket_;
  udp::endpoint peer_ep_;
  Role role_;
  std::string self_id_;
  std::shared_ptr<common::Identity> identity_;
  std::function<std::string()> get_self_name_;
  std::string peer_id_;
  std::string peer_name_;
  std::string expected_peer_id_;
  std::function<bool(const std::string&)> allow_peer_;
  bool ready_ = false;
  bool closed_ = false;
  bool hello_sent_ = false;
  bool ready_confirmed_ = false;

  OnReady on_ready_;
  OnName on_name_;
  OnChat on_chat_;
  OnClosed on_closed_;

  boost::asio::steady_timer punch_timer_;
  boost::asio::steady_timer hs_timer_;
  boost::asio::steady_timer data_timer_;
  boost::asio::steady_timer deadline_timer_;
  boost::asio::steady_timer keepalive_timer_;
  int punch_remaining_ = 24;
  int hs_retries_ = 0;

  std::optional<common::X25519KeyPair> eph_;
  std::vector<uint8_t> peer_eph_pub_;
  std::string transcript_;

  json last_hs_msg_{};

  common::AeadKey send_key_;
  common::AeadKey recv_key_;
  std::array<uint8_t, 4> recv_nonce_prefix_{};
  uint64_t recv_expected_seq_ = 0;

  std::array<uint8_t, 32> ack_send_key_{};
  std::array<uint8_t, 32> ack_recv_key_{};
  std::array<uint8_t, 4> ack_send_nonce_prefix_{};
  std::array<uint8_t, 4> ack_recv_nonce_prefix_{};

  std::deque<json> send_queue_;
  bool inflight_ = false;
  uint64_t inflight_seq_ = 0;
  json inflight_outer_{};
  int inflight_retries_ = 0;
};

class RendezvousClient : public std::enable_shared_from_this<RendezvousClient> {
public:
  struct Config {
    std::string server_host;
    uint16_t server_port = 0;
    std::string id;
    uint16_t listen_port = 0;
    uint16_t external_port_hint = 0;
    std::function<std::string(std::string_view)> sign_challenge;
    std::function<void(std::string)> log;
  };

  struct LookupResult {
    bool ok = false;
    std::string target_id;
    std::string ip;
    std::string udp_ip;
    uint16_t port = 0;
    uint16_t udp_port = 0;
    bool reachable = false;
  };

  using OnLookup = std::function<void(LookupResult)>;
  using OnFriendRequest = std::function<void(const std::string& from_id, const std::string& intro)>;
  using OnFriendAccept = std::function<void(const std::string& from_id)>;

  RendezvousClient(boost::asio::io_context& io, Config cfg)
      : io_(io),
        cfg_(std::move(cfg)),
        socket_(io),
        resolver_(io),
        heartbeat_timer_(io),
        poll_timer_(io),
        reconnect_timer_(io) {}

  void start(std::function<void()> on_registered, OnFriendRequest on_friend_request, OnFriendAccept on_friend_accept) {
    on_registered_ = std::move(on_registered);
    on_friend_request_ = std::move(on_friend_request);
    on_friend_accept_ = std::move(on_friend_accept);
    schedule_reconnect(/*immediate*/ true);
  }

  void stop() {
    stopped_ = true;
    boost::system::error_code ignored;
    heartbeat_timer_.cancel();
    poll_timer_.cancel();
    reconnect_timer_.cancel();
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
  }

  std::string_view id() const { return id_; }
  bool reachable() const { return reachable_; }
  uint16_t external_port() const { return external_port_; }
  uint16_t udp_port() const { return udp_port_; }
  std::string_view observed_ip() const { return observed_ip_; }

  void enable_polling(bool enabled) {
    polling_enabled_ = enabled;
    if (!polling_enabled_) {
      poll_timer_.cancel();
      return;
    }
    if (can_send()) schedule_poll();
  }

  void send_lookup(std::string target_id, OnLookup cb) {
    pending_lookups_.push_back({std::move(target_id), std::move(cb)});
    const std::string tid = pending_lookups_.back().target_id;
    enqueue_or_send([this, tid] {
      json j;
      j["type"] = "lookup";
      j["from_id"] = id_;
      j["target_id"] = tid;
      writer_->send(std::move(j));
    });
  }

  void send_friend_request(const std::string& to_id, std::string intro) {
    enqueue_or_send([this, to_id, intro = std::move(intro)]() mutable {
      json j;
      j["type"] = "friend_request";
      j["from_id"] = id_;
      j["to_id"] = to_id;
      j["intro"] = std::move(intro);
      writer_->send(std::move(j));
    });
  }

  void send_friend_accept(const std::string& requester_id) {
    enqueue_or_send([this, requester_id] {
      json j;
      j["type"] = "friend_accept";
      j["from_id"] = id_;
      j["to_id"] = requester_id;
      writer_->send(std::move(j));
    });
  }

private:
  bool can_send() const { return writer_ && socket_.is_open() && !id_.empty() && !stopped_; }

  void log(std::string msg) {
    if (cfg_.log) {
      cfg_.log(std::move(msg));
      return;
    }
    common::log(msg);
  }

  void enqueue_or_send(std::function<void()> fn) {
    if (can_send()) {
      fn();
      return;
    }
    pending_actions_.push_back(std::move(fn));
  }

  void flush_pending() {
    while (can_send() && !pending_actions_.empty()) {
      auto fn = std::move(pending_actions_.front());
      pending_actions_.pop_front();
      fn();
    }
  }

  struct PendingLookup {
    std::string target_id;
    OnLookup cb;
  };

  void schedule_reconnect(bool immediate) {
    if (stopped_) return;

    boost::system::error_code ignored;
    resolver_.cancel();
    heartbeat_timer_.cancel();
    poll_timer_.cancel();
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    writer_.reset();

    id_.clear();
    observed_ip_.clear();
    udp_ip_.clear();
    reachable_ = false;
    external_port_ = 0;
    udp_port_ = 0;

    const int delay = immediate ? 0 : reconnect_backoff_secs_;
    reconnect_backoff_secs_ = std::min(reconnect_backoff_secs_ * 2, 30);

    if (delay == 0) {
      log("rendezvous: connecting…");
    } else {
      log("rendezvous: reconnecting in " + std::to_string(delay) + "s…");
    }

    reconnect_timer_.expires_after(std::chrono::seconds(delay));
    auto self = shared_from_this();
    reconnect_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_) return;
      self->do_resolve();
    });
  }

  void do_resolve() {
    if (stopped_) return;
    auto self = shared_from_this();
    resolver_.async_resolve(cfg_.server_host, std::to_string(cfg_.server_port),
                            [self](const boost::system::error_code& ec, tcp::resolver::results_type results) {
                              if (ec || self->stopped_) return self->schedule_reconnect(false);
                              self->connect(results);
                            });
  }

  void connect(const tcp::resolver::results_type& results) {
    auto self = shared_from_this();
    auto timer = std::make_shared<boost::asio::steady_timer>(io_);
    timer->expires_after(kConnectTimeout);
    timer->async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      self->schedule_reconnect(false);
    });

    boost::asio::async_connect(socket_, results,
                               [self, timer](const boost::system::error_code& ec, const tcp::endpoint&) {
                                 timer->cancel();
                                 if (ec) return self->schedule_reconnect(false);
                                 self->writer_ = std::make_shared<common::JsonWriteQueue<tcp::socket>>(self->socket_);
                                 self->reconnect_backoff_secs_ = 1;
                                 self->send_register_init();
                                 self->read_loop();
                               });
  }

  void send_register_init() {
    json j;
    j["type"] = "register_init";
    j["id"] = cfg_.id;
    j["listen_port"] = cfg_.listen_port;
    j["external_port_hint"] = cfg_.external_port_hint;
    writer_->send(std::move(j));
  }

  void schedule_heartbeat() {
    if (!can_send()) return;
    heartbeat_timer_.expires_after(kHeartbeatInterval);
    auto self = shared_from_this();
    heartbeat_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_) return;
      if (!self->can_send()) return;
      json hb;
      hb["type"] = "heartbeat";
      hb["id"] = self->id_;
      self->writer_->send(std::move(hb));
      self->schedule_heartbeat();
    });
  }

  void schedule_poll() {
    if (!polling_enabled_ || !can_send()) return;
    poll_timer_.expires_after(kPollInterval);
    auto self = shared_from_this();
    poll_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_ || !self->polling_enabled_) return;
      if (!self->can_send()) return;
      json p;
      p["type"] = "poll";
      p["id"] = self->id_;
      self->writer_->send(std::move(p));
      self->schedule_poll();
    });
  }

  void read_loop() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->schedule_reconnect(false);
      self->handle_message(j);
      self->read_loop();
    });
  }

  void handle_message(const json& j) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();

    if (type == "register_challenge") {
      if (!cfg_.sign_challenge) return stop();
      if (!j.contains("challenge") || !j["challenge"].is_string()) return stop();
      const std::string challenge = j["challenge"].get<std::string>();
      const std::string sig = cfg_.sign_challenge(challenge);
      if (sig.empty()) return stop();
      json fin;
      fin["type"] = "register_finish";
      fin["id"] = cfg_.id;
      fin["signature"] = sig;
      if (!writer_) return schedule_reconnect(false);
      writer_->send(std::move(fin));
      return;
    }

    if (type == "register_ok") {
      if (!j.contains("id") || !j["id"].is_string()) return;
      id_ = j["id"].get<std::string>();
      observed_ip_ = (j.contains("observed_ip") && j["observed_ip"].is_string()) ? j["observed_ip"].get<std::string>() : "";
      reachable_ = j.contains("reachable") && j["reachable"].is_boolean() ? j["reachable"].get<bool>() : false;
      external_port_ = j.contains("external_port") && j["external_port"].is_number_integer()
                           ? static_cast<uint16_t>(j["external_port"].get<int>())
                           : 0;
      // udp_ip is the best contact address for UDP punching.
      if (j.contains("udp_ip") && j["udp_ip"].is_string()) udp_ip_ = j["udp_ip"].get<std::string>();
      udp_port_ = j.contains("udp_port") && j["udp_port"].is_number_integer()
                      ? static_cast<uint16_t>(j["udp_port"].get<int>())
                      : 0;
      if (!udp_ip_.empty() && common::is_private_ipv4(udp_ip_)) {
        log("warning: rendezvous sees your UDP address as private (" + udp_ip_ +
            "); hole punching will not work for internet peers unless rendezvous is on a public IP");
      } else if (!observed_ip_.empty() && common::is_private_ipv4(observed_ip_)) {
        log("warning: rendezvous sees your TCP address as private (" + observed_ip_ +
            "); run rendezvous on a public IP for internet discovery");
      }
      schedule_heartbeat();
      if (polling_enabled_) schedule_poll();
      flush_pending();
      if (on_registered_) on_registered_();
      return;
    }

    if (type == "lookup_result") {
      LookupResult r;
      r.ok = j.contains("ok") && j["ok"].is_boolean() ? j["ok"].get<bool>() : false;
      r.target_id = (j.contains("target_id") && j["target_id"].is_string()) ? j["target_id"].get<std::string>() : "";
      r.ip = (j.contains("ip") && j["ip"].is_string()) ? j["ip"].get<std::string>() : "";
      r.udp_ip = (j.contains("udp_ip") && j["udp_ip"].is_string()) ? j["udp_ip"].get<std::string>() : "";
      r.reachable = j.contains("reachable") && j["reachable"].is_boolean() ? j["reachable"].get<bool>() : false;
      r.port = j.contains("port") && j["port"].is_number_integer() ? static_cast<uint16_t>(j["port"].get<int>()) : 0;
      r.udp_port = j.contains("udp_port") && j["udp_port"].is_number_integer()
                       ? static_cast<uint16_t>(j["udp_port"].get<int>())
                       : 0;
      for (auto it = pending_lookups_.begin(); it != pending_lookups_.end(); ++it) {
        if (it->target_id == r.target_id) {
          auto cb = std::move(it->cb);
          pending_lookups_.erase(it);
          cb(std::move(r));
          return;
        }
      }
      return;
    }

    if (type == "poll_result") {
      if (j.contains("friend_requests") && j["friend_requests"].is_array()) {
        for (const auto& fr : j["friend_requests"]) {
          if (!fr.is_object()) continue;
          if (!fr.contains("from_id") || !fr["from_id"].is_string()) continue;
          std::string intro;
          if (fr.contains("intro") && fr["intro"].is_string()) intro = fr["intro"].get<std::string>();
          if (on_friend_request_) on_friend_request_(fr["from_id"].get<std::string>(), intro);
        }
      }
      if (j.contains("friend_accepts") && j["friend_accepts"].is_array()) {
        for (const auto& fa : j["friend_accepts"]) {
          if (!fa.is_object()) continue;
          if (!fa.contains("from_id") || !fa["from_id"].is_string()) continue;
          if (on_friend_accept_) on_friend_accept_(fa["from_id"].get<std::string>());
        }
      }
      return;
    }
  }

  boost::asio::io_context& io_;
  Config cfg_;

  tcp::socket socket_;
  tcp::resolver resolver_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;

  boost::asio::steady_timer heartbeat_timer_;
  boost::asio::steady_timer poll_timer_;
  boost::asio::steady_timer reconnect_timer_;
  bool polling_enabled_ = false;
  bool stopped_ = false;

  std::string id_;
  std::string observed_ip_;
  std::string udp_ip_;
  bool reachable_ = false;
  uint16_t external_port_ = 0;
  uint16_t udp_port_ = 0;
  int reconnect_backoff_secs_ = 1;

  std::vector<PendingLookup> pending_lookups_;
  std::deque<std::function<void()>> pending_actions_;
  std::function<void()> on_registered_;
  OnFriendRequest on_friend_request_;
  OnFriendAccept on_friend_accept_;

public:
  // Change external port hint and force a re-register (so server can re-probe reachability).
  void reprobe_with_external_port_hint(uint16_t hint) {
    cfg_.external_port_hint = hint;
    schedule_reconnect(/*immediate*/ true);
  }
};

} // namespace

struct ChatBackend::Impl {
  ChatBackend* q = nullptr;

  std::mutex m;
  std::unordered_set<std::string> accepted_friends;
  std::unordered_map<std::string, std::deque<std::string>> queued_outgoing;
  std::unordered_map<std::string, std::string> peer_names;
  std::string self_name;

  boost::asio::io_context io;
  std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work;
  std::thread io_thread;

  std::shared_ptr<common::Identity> identity;
  common::UpnpManager upnp;
  bool owns_upnp_mapping = false;
  uint16_t external_port_hint = 0;
  uint16_t listen_port = 0;
  bool upnp_attempted = false;
  bool no_upnp = false;

  tcp::acceptor acceptor{io};
  udp::socket udp_socket{io};
  udp::resolver udp_resolver{io};
  udp::endpoint udp_server_ep;
  bool udp_server_ready = false;
  bool udp_resolving = false;
  bool udp_announce_confirmed = false;
  boost::asio::steady_timer udp_announce_timer{io};
  std::string server_host;
  uint16_t server_port = 0;

  std::shared_ptr<RendezvousClient> rendezvous;
  std::unordered_map<std::string, std::shared_ptr<PeerSession>> tcp_sessions;
  std::unordered_map<std::string, std::shared_ptr<UdpPeerSession>> udp_sessions;
  std::unordered_map<std::string, std::string> udp_ep_to_peer;
  std::unordered_map<std::string, RendezvousClient::LookupResult> last_lookup;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_connect_attempt;
  boost::asio::steady_timer friend_connect_timer{io};
  bool friend_connect_running = false;

  void postToQt(std::function<void()> fn) {
    QMetaObject::invokeMethod(q, [fn = std::move(fn)] { fn(); }, Qt::QueuedConnection);
  }

  bool isAccepted(const std::string& id) {
    std::lock_guard lk(m);
    return accepted_friends.find(id) != accepted_friends.end();
  }

  std::string getSelfName() {
    std::lock_guard lk(m);
    return self_name;
  }

  void setAccepted(const std::string& id, bool ok) {
    std::lock_guard lk(m);
    if (ok) accepted_friends.insert(id);
    else accepted_friends.erase(id);
  }

  void queueOutgoing(const std::string& peer, std::string text) {
    std::lock_guard lk(m);
    queued_outgoing[peer].push_back(std::move(text));
  }

  void flushOutgoing(const std::string& peer) {
    std::deque<std::string> msgs;
    {
      std::lock_guard lk(m);
      auto it = queued_outgoing.find(peer);
      if (it == queued_outgoing.end()) return;
      msgs = std::move(it->second);
      queued_outgoing.erase(it);
    }
    auto u = udp_sessions.find(peer);
    if (u != udp_sessions.end() && u->second) {
      while (!msgs.empty()) {
        u->second->send_chat(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
    auto t = tcp_sessions.find(peer);
    if (t != tcp_sessions.end() && t->second) {
      while (!msgs.empty()) {
        t->second->send_chat(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
  }

  void bindAcceptor(uint16_t port) {
    boost::system::error_code ec;
    tcp::endpoint ep(boost::asio::ip::address_v4::any(), port);
    acceptor.open(ep.protocol(), ec);
    acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    acceptor.bind(ep, ec);
    if (ec) throw std::runtime_error("bind failed");
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) throw std::runtime_error("listen failed");
  }

  void bindUdp(uint16_t port) {
    boost::system::error_code ec;
    udp_socket.open(udp::v4(), ec);
    if (ec) throw std::runtime_error("udp open failed");
    udp_socket.bind(udp::endpoint(boost::asio::ip::address_v4::any(), port), ec);
    if (ec) throw std::runtime_error("udp bind failed");
    udp_read_loop();
  }

  void udp_read_loop() {
    auto buf = std::make_shared<std::array<uint8_t, common::kMaxFrameSize + 4>>();
    auto remote = std::make_shared<udp::endpoint>();
    udp_socket.async_receive_from(boost::asio::buffer(*buf), *remote,
                                  [this, buf, remote](const boost::system::error_code& ec, std::size_t n) {
                                    if (ec) return;
                                    if (n == 0) return udp_read_loop();
                                    const auto jopt = common::parse_framed_json_bytes(
                                        std::span<const uint8_t>(buf->data(), n), common::kMaxFrameSize);
                                    if (!jopt) return udp_read_loop();
                                    handle_udp_datagram(*jopt, *remote);
                                    udp_read_loop();
                                  });
  }

  void handle_udp_datagram(const json& j, const udp::endpoint& from) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();
    if (type == "udp_announce_ok") {
      if (!udp_announce_confirmed) {
        udp_announce_confirmed = true;
        postToQt([this] { emit q->logLine("udp rendezvous announce confirmed"); });
      }
      return;
    }

    const std::string epkey = common::endpoint_to_string(from);
    if (auto it = udp_ep_to_peer.find(epkey); it != udp_ep_to_peer.end()) {
      const std::string& pid = it->second;
      if (auto sit = udp_sessions.find(pid); sit != udp_sessions.end() && sit->second) {
        sit->second->handle_datagram(j, from);
        return;
      }
      udp_ep_to_peer.erase(it);
    }

    // Route by claimed peer ID for handshake packets (endpoint may not be mapped yet).
    if ((type == "secure_hello" || type == "secure_hello_ack") && j.contains("id") && j["id"].is_string()) {
      const std::string pid = j["id"].get<std::string>();
      if (auto sit = udp_sessions.find(pid); sit != udp_sessions.end() && sit->second) {
        udp_ep_to_peer[epkey] = pid;
        sit->second->handle_datagram(j, from);
        return;
      }

      if (type == "secure_hello") {
        if (!isAccepted(pid)) return;
        const std::string selfId = std::string(identity->public_id());
        auto session = std::make_shared<UdpPeerSession>(
            udp_socket, from, UdpPeerSession::Role::Acceptor, selfId, identity, [this] { return getSelfName(); },
            [this](const std::string& x) { return isAccepted(x); });
        udp_sessions[pid] = session;
        udp_ep_to_peer[epkey] = pid;

        std::weak_ptr<UdpPeerSession> weak = session;
        session->start_accept_with_first(
            j, from,
            [this](const std::string& peer_id, const std::string& peer_name) {
              {
                std::lock_guard lk(m);
                if (!peer_name.empty()) peer_names[peer_id] = peer_name;
              }
              postToQt([this, peer_id] {
                emit q->logLine("peer connected (udp): " + QString::fromStdString(peer_id));
              });
              flushOutgoing(peer_id);
            },
            [this](const std::string& peer_id, const std::string& peer_name) {
              if (peer_name.empty()) return;
              {
                std::lock_guard lk(m);
                peer_names[peer_id] = peer_name;
              }
              postToQt([this, peer_id, peer_name] {
                emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
              });
            },
            [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
              std::string label = peer_name.empty() ? peer_id : peer_name;
              postToQt([this, peer_id, label, text] {
                emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                        QString::fromStdString(text), true);
              });
            },
            [this, pid, epkey, weak]() {
              auto s = weak.lock();
              if (!s) return;
              auto it = udp_sessions.find(pid);
              if (it != udp_sessions.end() && it->second == s) udp_sessions.erase(it);
              if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == pid) {
                udp_ep_to_peer.erase(mit);
              }
            });
        return;
      }
    }
  }

  void send_udp_to(const udp::endpoint& to, const json& j) {
    auto framed = common::frame_json_bytes(j);
    if (!framed) return;
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(*framed));
    udp_socket.async_send_to(boost::asio::buffer(*buf), to,
                             [buf](const boost::system::error_code&, std::size_t) {});
  }

  void resolve_udp_server(std::function<void()> on_ready = {}) {
    if (udp_resolving) return;
    udp_server_ready = false;
    if (server_host.empty() || server_port == 0) return;
    udp_resolving = true;
    udp_resolver.async_resolve(
        server_host,
        std::to_string(server_port),
        [this, on_ready = std::move(on_ready)](const boost::system::error_code& ec, udp::resolver::results_type res) {
          udp_resolving = false;
          if (ec) {
            postToQt([this, msg = QString("udp rendezvous resolve failed: %1").arg(QString::fromUtf8(ec.message()))] {
              emit q->logLine(msg);
            });
            return;
          }

          std::optional<udp::endpoint> chosen;
          for (const auto& r : res) {
            const auto ep = r.endpoint();
            if (ep.address().is_v4()) {
              chosen = ep;
              break;
            }
          }
          if (!chosen) {
            // We only open a v4 UDP socket, so an IPv6-only rendezvous host won't work for UDP punching.
            postToQt([this] { emit q->logLine("udp rendezvous resolved to IPv6 only; UDP socket is IPv4"); });
            return;
          }

          udp_server_ep = *chosen;
          udp_server_ready = true;
          postToQt([this, ep = QString::fromStdString(common::endpoint_to_string(udp_server_ep))] {
            emit q->logLine(QString("udp rendezvous endpoint: %1").arg(ep));
          });
          if (on_ready) on_ready();
        });
  }

  void schedule_udp_announce(bool immediate) {
    if (!identity) return;
    const auto delay = immediate ? std::chrono::seconds(0) : std::chrono::seconds(20);
    udp_announce_timer.expires_after(delay);
    udp_announce_timer.async_wait([this](const boost::system::error_code& ec) {
      if (ec) return;
      if (!udp_server_ready) {
        resolve_udp_server([this] { send_udp_announce_once(); });
      } else {
        send_udp_announce_once();
      }
      schedule_udp_announce(false);
    });
  }

  void send_udp_announce_once() {
    if (!udp_server_ready || !identity) return;
    const std::string id = std::string(identity->public_id());
    const auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    const std::string msg = "p2p-chat-udp-announce|" + id + "|" + std::to_string(ts);
    const std::string sig = identity->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
    if (sig.empty()) return;
    json a;
    a["type"] = "udp_announce";
    a["id"] = id;
    a["ts"] = ts;
    a["sig"] = sig;
    send_udp_to(udp_server_ep, a);
  }

  void acceptLoop() {
    acceptor.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
      if (ec) return;
      handleIncomingSocket(std::move(socket));
      acceptLoop();
    });
  }

  void handleIncomingSocket(tcp::socket socket) {
    auto sock = std::make_shared<tcp::socket>(std::move(socket));
    common::async_read_json(*sock, common::kMaxFrameSize, [this, sock](const boost::system::error_code& ec, json j) {
      if (ec) return;
      if (!j.contains("type") || !j["type"].is_string()) return;
      const std::string type = j["type"].get<std::string>();

      if (type == "probe") {
        if (!j.contains("challenge") || !j["challenge"].is_string()) return;
        const std::string challenge = j["challenge"].get<std::string>();
        json resp;
        resp["type"] = "probe_ok";
        resp["id"] = std::string(identity->public_id());
        resp["signature"] = identity->sign_challenge_b64url(challenge);
        common::async_write_json(*sock, resp, [sock](const boost::system::error_code&) {
          boost::system::error_code ignored;
          sock->shutdown(tcp::socket::shutdown_both, ignored);
          sock->close(ignored);
        });
        return;
      }

      if (type == "hello") {
        auto writer = std::make_shared<common::JsonWriteQueue<tcp::socket>>(*sock);
        json e;
        e["type"] = "error";
        e["message"] = "legacy protocol not supported; upgrade required";
        writer->send(std::move(e));
        boost::system::error_code ignored;
        sock->shutdown(tcp::socket::shutdown_both, ignored);
        sock->close(ignored);
        return;
      }

      if (type == "secure_hello") {
        startPeerAcceptWithFirst(std::move(*sock), std::move(j));
        return;
      }
    });
  }

  void startPeerAcceptWithFirst(tcp::socket socket, json first) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    auto session = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Acceptor, std::move(selfId), identity,
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); });
    std::weak_ptr<PeerSession> weak = session;
    session->start_accept_with_first(
        std::move(first),
        [this, weak](const std::string& peer_id, const std::string& peer_name) {
          if (auto s = weak.lock()) tcp_sessions[peer_id] = std::move(s);
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
        },
        [this](const std::string& peer_id, const std::string& peer_name) {
          if (peer_name.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id, peer_name] {
            emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
          });
        },
        [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
          std::string label = peer_name.empty() ? peer_id : peer_name;
          postToQt([this, peer_id, label, text] {
            emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this, weak]() {
          auto s = weak.lock();
          if (!s) return;
          const std::string pid = std::string(s->peer_id());
          if (pid.empty()) return;
          auto it = tcp_sessions.find(pid);
          if (it != tcp_sessions.end() && it->second == s) tcp_sessions.erase(it);
        });
  }

  void connectToPeer(const std::string& peer_id, const std::string& ip, uint16_t port, bool silent) {
    if (tcp_sessions.find(peer_id) != tcp_sessions.end()) return;
    auto sock = std::make_shared<tcp::socket>(io);
    auto timer = std::make_shared<boost::asio::steady_timer>(io);
    timer->expires_after(kConnectTimeout);
    timer->async_wait([sock](const boost::system::error_code& ec) {
      if (ec) return;
      boost::system::error_code ignored;
      sock->close(ignored);
    });

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(ip, ec);
    if (ec) return;
    tcp::endpoint ep(addr, port);

    sock->async_connect(ep, [this, sock, timer, peer_id, silent](const boost::system::error_code& ec2) {
      timer->cancel();
      if (ec2) {
        if (!silent) {
          postToQt([this, peer_id] {
            emit q->deliveryError(QString::fromStdString(peer_id), "connect failed");
          });
        }
        return;
      }
      startPeerInitiator(std::move(*sock), peer_id);
    });
  }

  void connectToPeerUdp(const std::string& peer_id,
                        const std::string& udp_ip,
                        uint16_t udp_port,
                        const std::string& tcp_ip,
                        uint16_t tcp_port,
                        bool tcp_reachable,
                        bool silent) {
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(udp_ip, ec);
    if (ec) return;
    udp::endpoint ep(addr, udp_port);

    if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second) {
      if (it->second->peer_endpoint() == ep) return;
      it->second->close();
      udp_sessions.erase(it);
    }

    const std::string selfId = std::string(identity->public_id());
    const auto role = (selfId < peer_id) ? UdpPeerSession::Role::Initiator : UdpPeerSession::Role::Acceptor;

    auto udp_ready = std::make_shared<std::atomic<bool>>(false);
    auto session = std::make_shared<UdpPeerSession>(
        udp_socket,
        ep,
        role,
        selfId,
        identity,
        [this] { return getSelfName(); },
        [this](const std::string& pid) { return isAccepted(pid); },
        peer_id);

    udp_sessions[peer_id] = session;
    udp_ep_to_peer[common::endpoint_to_string(ep)] = peer_id;

    const std::string epkey = common::endpoint_to_string(ep);
    std::weak_ptr<UdpPeerSession> weak = session;
    session->start(
        [this, udp_ready](const std::string& pid, const std::string& pname) {
          udp_ready->store(true);
          {
            std::lock_guard lk(m);
            if (!pname.empty()) peer_names[pid] = pname;
          }
          postToQt([this, pid] { emit q->logLine("peer connected (udp): " + QString::fromStdString(pid)); });
          flushOutgoing(pid);
        },
        [this](const std::string& pid, const std::string& pname) {
          if (pname.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[pid] = pname;
          }
          postToQt([this, pid, pname] {
            emit q->peerNameUpdated(QString::fromStdString(pid), QString::fromStdString(pname));
          });
        },
        [this](const std::string& pid, const std::string& pname, const std::string& text) {
          std::string label = pname.empty() ? pid : pname;
          postToQt([this, pid, label, text] {
            emit q->messageReceived(QString::fromStdString(pid), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this, weak, udp_ready, peer_id, epkey, tcp_ip, tcp_port, tcp_reachable, silent, role]() {
          const bool ok = udp_ready->load();
          auto s = weak.lock();
          if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second == s) udp_sessions.erase(it);
          if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == peer_id) {
            udp_ep_to_peer.erase(mit);
          }
          if (!ok && role == UdpPeerSession::Role::Initiator) udp_failed_fallback(peer_id, tcp_ip, tcp_port, tcp_reachable, silent);
        });

    // Flush queued messages into the session (session will send once ready).
    flushOutgoing(peer_id);
  }

  void udp_failed_fallback(const std::string& peer_id,
                           const std::string& ip,
                           uint16_t tcp_port,
                           bool tcp_reachable,
                           bool silent) {
    // UDP is the default. If it fails, try direct TCP if the peer is reachable; otherwise attempt UPnP so the peer can
    // connect to us via TCP (classic rendezvous mode).
    if (tcp_reachable && tcp_port != 0) {
      connectToPeer(peer_id, ip, tcp_port, silent);
      return;
    }
    if (!rendezvous) return;
    if (!no_upnp && !upnp_attempted) {
      upnp_attempted = true;
      // Try UPnP only after UDP failed.
      const auto map = upnp.try_map(listen_port, "p2p_chat_gui (miniupnpc)");
      owns_upnp_mapping = map.ok;
      if (map.ok) {
        external_port_hint = map.external_port;
        rendezvous->reprobe_with_external_port_hint(external_port_hint);
      }
    }
    if (!silent) {
      postToQt([this, peer_id] {
        emit q->deliveryError(QString::fromStdString(peer_id), "delivery failed (udp/tcp unavailable)");
      });
    }
  }

  void startPeerInitiator(tcp::socket socket, std::string expected_peer_id) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    const std::string peer_key = expected_peer_id;
    auto session = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Initiator, std::move(selfId), identity,
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); },
        std::move(expected_peer_id));

    // Store by expected peer id so we don't attempt another connect while handshaking.
    tcp_sessions[peer_key] = session;
    std::weak_ptr<PeerSession> weak = session;
    session->start(
        [this, weak](const std::string& peer_id, const std::string& peer_name) {
          if (auto s = weak.lock()) tcp_sessions[peer_id] = std::move(s);
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
        },
        [this](const std::string& peer_id, const std::string& peer_name) {
          if (peer_name.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id, peer_name] {
            emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
          });
        },
        [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
          std::string label = peer_name.empty() ? peer_id : peer_name;
          postToQt([this, peer_id, label, text] {
            emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this, weak, peer_key]() {
          auto s = weak.lock();
          if (!s) return;
          auto it = tcp_sessions.find(peer_key);
          if (it != tcp_sessions.end() && it->second == s) tcp_sessions.erase(it);
        });
  }

  void attemptDelivery(const std::string& peer_id, bool silent) {
    if (!rendezvous) return;
    if (!isAccepted(peer_id)) return;
    const auto now = std::chrono::steady_clock::now();
    if (auto it = last_connect_attempt.find(peer_id); it != last_connect_attempt.end()) {
      if (now - it->second < std::chrono::seconds(3)) return;
    }
    last_connect_attempt[peer_id] = now;

    rendezvous->send_lookup(peer_id, [this, silent](RendezvousClient::LookupResult r) {
      if (!r.ok) {
        if (!silent) {
          postToQt([this, tid = r.target_id] {
            emit q->deliveryError(QString::fromStdString(tid), "lookup failed (offline?)");
          });
        }
        return;
      }
      last_lookup[r.target_id] = r;
      if (r.udp_port != 0) {
        // UDP hole punching is the default (works even if both peers are NATed).
        const std::string udp_ip = r.udp_ip.empty() ? r.ip : r.udp_ip;
        connectToPeerUdp(r.target_id, udp_ip, r.udp_port, r.ip, r.port, r.reachable, silent);
        return;
      }
      // No UDP info. Try direct TCP if possible; otherwise request connect (may succeed if we become reachable later).
      if (r.reachable && r.port != 0) {
        connectToPeer(r.target_id, r.ip, r.port, silent);
        return;
      }
      udp_failed_fallback(r.target_id, r.ip, r.port, r.reachable, silent);
    });
  }

  void closePeerSessions(const std::string& peer_id) {
    if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second) {
      const auto epkey = common::endpoint_to_string(it->second->peer_endpoint());
      it->second->close();
      udp_sessions.erase(it);
      if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == peer_id) {
        udp_ep_to_peer.erase(mit);
      }
    }
    if (auto it = tcp_sessions.find(peer_id); it != tcp_sessions.end() && it->second) {
      it->second->close();
      tcp_sessions.erase(it);
    }
  }

  void scheduleFriendConnect(bool immediate) {
    if (immediate) {
      if (friend_connect_running) return;
      friend_connect_running = true;
    }
    const auto delay = immediate ? std::chrono::seconds(0) : std::chrono::seconds(5);
    friend_connect_timer.expires_after(delay);
    friend_connect_timer.async_wait([this](const boost::system::error_code& ec) {
      if (ec) return;
      std::vector<std::string> friends;
      {
        std::lock_guard lk(m);
        friends.assign(accepted_friends.begin(), accepted_friends.end());
      }
      for (const auto& f : friends) attemptDelivery(f, /*silent*/ true);
      scheduleFriendConnect(false);
    });
  }
};

ChatBackend::ChatBackend(QObject* parent) : QObject(parent), impl_(new Impl()) {
  impl_->q = this;
}

ChatBackend::~ChatBackend() {
  stop();
  delete impl_;
}

void ChatBackend::start(const Options& opt) {
  stop();

  const QString keyPath = opt.keyPath.isEmpty() ? Profile::defaultKeyPath() : opt.keyPath;
  common::log("identity key: " + keyPath.toStdString());
  emit logLine(QString("identity key: %1").arg(keyPath));
  impl_->identity = common::Identity::load_or_create(keyPath.toStdString());
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = opt.selfName.toStdString();
  }

  // Bind acceptor.
  const uint16_t listenPort = opt.listenPort ? static_cast<uint16_t>(opt.listenPort)
                                             : common::choose_default_listen_port();
  impl_->listen_port = listenPort;
  impl_->no_upnp = opt.noUpnp;
  impl_->bindAcceptor(listenPort);
  impl_->acceptLoop();
  impl_->bindUdp(listenPort);

  // Default to UDP hole-punching; only attempt UPnP after UDP fails.
  impl_->upnp_attempted = false;
  impl_->owns_upnp_mapping = false;
  impl_->external_port_hint = opt.externalPort ? opt.externalPort : listenPort;

  RendezvousClient::Config cfg;
  cfg.server_host = opt.serverHost.toStdString();
  cfg.server_port = opt.serverPort;
  cfg.id = std::string(impl_->identity->public_id());
  cfg.listen_port = listenPort;
  cfg.external_port_hint = impl_->external_port_hint;
  cfg.sign_challenge = [id = impl_->identity](std::string_view c) { return id->sign_challenge_b64url(c); };

  impl_->server_host = cfg.server_host;
  impl_->server_port = cfg.server_port;
  impl_->schedule_udp_announce(/*immediate*/ true);

  impl_->rendezvous = std::make_shared<RendezvousClient>(impl_->io, std::move(cfg));
  impl_->rendezvous->start(
      [this]() {
        const auto selfId = QString::fromStdString(std::string(impl_->rendezvous->id()));
        const auto reachable = impl_->rendezvous->reachable();
        const auto observedIp = QString::fromStdString(std::string(impl_->rendezvous->observed_ip()));
        const auto extPort = static_cast<quint16>(impl_->rendezvous->external_port());
        emit registered(selfId, reachable, observedIp, extPort);
        impl_->rendezvous->enable_polling(true);
        impl_->scheduleFriendConnect(/*immediate*/ true);
      },
      [this](const std::string& from_id, const std::string& intro) {
        emit friendRequestReceived(QString::fromStdString(from_id), QString::fromStdString(intro));
      },
      [this](const std::string& from_id) { emit friendAccepted(QString::fromStdString(from_id)); });

  impl_->work.emplace(boost::asio::make_work_guard(impl_->io));
  impl_->io_thread = std::thread([this] { impl_->io.run(); });
}

void ChatBackend::stop() {
  if (!impl_->work) return;
  impl_->work.reset();
  if (impl_->rendezvous) impl_->rendezvous->stop();
  boost::system::error_code ignored;
  impl_->acceptor.close(ignored);
  impl_->friend_connect_timer.cancel();
  impl_->udp_announce_timer.cancel();
  impl_->udp_socket.close(ignored);
  impl_->io.stop();
  if (impl_->io_thread.joinable()) impl_->io_thread.join();
  impl_->io.restart();
  impl_->rendezvous.reset();
  impl_->tcp_sessions.clear();
  impl_->udp_sessions.clear();
  impl_->udp_ep_to_peer.clear();
  impl_->last_lookup.clear();
  impl_->last_connect_attempt.clear();
  impl_->friend_connect_running = false;
  if (impl_->owns_upnp_mapping) impl_->upnp.remove_mapping_best_effort();
  impl_->owns_upnp_mapping = false;
}

void ChatBackend::setSelfName(const QString& name) {
  const auto nm = name.toStdString();
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = nm;
  }

  // Push updated name immediately to any active session (P2P).
  boost::asio::post(impl_->io, [impl = impl_, nm] {
    for (auto& [_, s] : impl->tcp_sessions) {
      if (s) s->send_name(nm);
    }
    for (auto& [_, s] : impl->udp_sessions) {
      if (s) s->send_name(nm);
    }
  });
}

void ChatBackend::setFriendAccepted(const QString& peerId, bool accepted) {
  const auto pid = peerId.toStdString();
  impl_->setAccepted(pid, accepted);
  boost::asio::post(impl_->io, [impl = impl_, pid, accepted] {
    if (!accepted) {
      impl->closePeerSessions(pid);
      return;
    }
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::sendFriendRequest(const QString& peerId, const QString& intro) {
  const auto pid = peerId.toStdString();
  const auto in = intro.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid, in] {
    if (!impl->rendezvous) return;
    impl->rendezvous->send_friend_request(pid, in);
  });
}

void ChatBackend::acceptFriend(const QString& peerId) {
  const auto pid = peerId.toStdString();
  impl_->setAccepted(pid, true);
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    impl->rendezvous->send_friend_accept(pid);
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::sendMessage(const QString& peerId, const QString& text) {
  const auto pid = peerId.toStdString();
  if (!impl_->isAccepted(pid)) {
    emit deliveryError(peerId, "not friends");
    return;
  }
  impl_->queueOutgoing(pid, text.toStdString());
  emit messageReceived(peerId, peerId, text, false);

  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    if (impl->udp_sessions.find(pid) != impl->udp_sessions.end()) {
      impl->flushOutgoing(pid);
      return;
    }
    impl->attemptDelivery(pid, /*silent*/ false);
  });
}

void ChatBackend::disconnectPeer(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    impl->closePeerSessions(pid);
  });
}

void ChatBackend::warmConnect(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    if (!impl->isAccepted(pid)) return;
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}
