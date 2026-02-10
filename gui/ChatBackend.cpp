#include "gui/ChatBackend.hpp"

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
using common::json;

namespace {
constexpr auto kHeartbeatInterval = std::chrono::seconds(15);
constexpr auto kPollInterval = std::chrono::seconds(4);
constexpr auto kConnectTimeout = std::chrono::seconds(10);

struct ConnectRequest {
  std::string from_id;
  std::string ip;
  uint16_t port = 0;
};

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
    uint16_t port = 0;
    bool reachable = false;
  };

  using OnLookup = std::function<void(LookupResult)>;
  using OnConnectRequest = std::function<void(const ConnectRequest&)>;
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

  void start(std::function<void()> on_registered,
             OnConnectRequest on_connect_request,
             OnFriendRequest on_friend_request,
             OnFriendAccept on_friend_accept) {
    on_registered_ = std::move(on_registered);
    on_connect_request_ = std::move(on_connect_request);
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

  void send_connect_request(const std::string& to_id) {
    enqueue_or_send([this, to_id] {
      json j;
      j["type"] = "connect_request";
      j["from_id"] = id_;
      j["to_id"] = to_id;
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
    reachable_ = false;
    external_port_ = 0;

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
      r.reachable = j.contains("reachable") && j["reachable"].is_boolean() ? j["reachable"].get<bool>() : false;
      r.port = j.contains("port") && j["port"].is_number_integer() ? static_cast<uint16_t>(j["port"].get<int>()) : 0;
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
      if (j.contains("connect_requests") && j["connect_requests"].is_array()) {
        for (const auto& req : j["connect_requests"]) {
          if (!req.is_object()) continue;
          if (!req.contains("from_id") || !req["from_id"].is_string()) continue;
          if (!req.contains("ip") || !req["ip"].is_string()) continue;
          if (!req.contains("port") || !req["port"].is_number_integer()) continue;
          const int port_i = req["port"].get<int>();
          if (port_i <= 0 || port_i > 65535) continue;
          ConnectRequest r;
          r.from_id = req["from_id"].get<std::string>();
          r.ip = req["ip"].get<std::string>();
          r.port = static_cast<uint16_t>(port_i);
          if (on_connect_request_) on_connect_request_(r);
        }
      }
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
  bool reachable_ = false;
  uint16_t external_port_ = 0;
  int reconnect_backoff_secs_ = 1;

  std::vector<PendingLookup> pending_lookups_;
  std::deque<std::function<void()>> pending_actions_;
  std::function<void()> on_registered_;
  OnConnectRequest on_connect_request_;
  OnFriendRequest on_friend_request_;
  OnFriendAccept on_friend_accept_;
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

  tcp::acceptor acceptor{io};
  std::shared_ptr<RendezvousClient> rendezvous;
  std::shared_ptr<PeerSession> active_peer;

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
    if (!active_peer || std::string(active_peer->peer_id()) != peer) return;
    while (!msgs.empty()) {
      active_peer->send_chat(std::move(msgs.front()));
      msgs.pop_front();
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
        if (active_peer) {
          auto writer = std::make_shared<common::JsonWriteQueue<tcp::socket>>(*sock);
          json busy;
          busy["type"] = "busy";
          busy["message"] = "already in an active chat session";
          writer->send(std::move(busy));
          boost::system::error_code ignored;
          sock->shutdown(tcp::socket::shutdown_both, ignored);
          sock->close(ignored);
          return;
        }
        startPeerAcceptWithFirst(std::move(*sock), std::move(j));
        return;
      }
    });
  }

  void startPeerAcceptWithFirst(tcp::socket socket, json first) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    active_peer = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Acceptor, std::move(selfId), identity,
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); });

    active_peer->start_accept_with_first(
        std::move(first),
        [this](const std::string& peer_id, const std::string& peer_name) {
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
        [this]() {
          active_peer.reset();
          postToQt([this] { emit q->logLine("returned to idle"); });
        });
  }

  void connectToPeer(const std::string& peer_id, const std::string& ip, uint16_t port, bool silent) {
    if (active_peer) return;
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

  void startPeerInitiator(tcp::socket socket, std::string expected_peer_id) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    active_peer = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Initiator, std::move(selfId), identity,
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); },
        std::move(expected_peer_id));

    active_peer->start(
        [this](const std::string& peer_id, const std::string& peer_name) {
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
        [this]() {
          active_peer.reset();
          postToQt([this] { emit q->logLine("returned to idle"); });
        });
  }

  void attemptDelivery(const std::string& peer_id, bool silent) {
    if (!rendezvous) return;
    if (active_peer) return;
    if (!isAccepted(peer_id)) return;

    rendezvous->send_lookup(peer_id, [this, silent](RendezvousClient::LookupResult r) {
      if (!r.ok) {
        if (!silent) {
          postToQt([this, tid = r.target_id] {
            emit q->deliveryError(QString::fromStdString(tid), "lookup failed (offline?)");
          });
        }
        return;
      }
      if (r.reachable && r.port != 0) {
        connectToPeer(r.target_id, r.ip, r.port, silent);
        return;
      }
      if (rendezvous->reachable()) {
        rendezvous->send_connect_request(r.target_id);
        return;
      }
      if (!silent) {
        postToQt([this, tid = r.target_id] {
          emit q->deliveryError(QString::fromStdString(tid), "both unreachable; cannot connect");
        });
      }
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

  impl_->identity = common::Identity::load_or_create(opt.keyPath.toStdString());
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = opt.selfName.toStdString();
  }

  // Bind acceptor.
  const uint16_t listenPort = opt.listenPort ? static_cast<uint16_t>(opt.listenPort)
                                             : common::choose_default_listen_port();
  impl_->bindAcceptor(listenPort);
  impl_->acceptLoop();

  // External port hint selection + optional UPnP.
  if (!opt.noUpnp) {
    const auto map = impl_->upnp.try_map(listenPort, "p2p_chat_gui (miniupnpc)");
    impl_->owns_upnp_mapping = map.ok;
    impl_->external_port_hint = map.ok ? map.external_port : 0;
    if (!impl_->external_port_hint) impl_->external_port_hint = opt.externalPort ? opt.externalPort : listenPort;
  } else {
    impl_->external_port_hint = opt.externalPort ? opt.externalPort : listenPort;
  }

  RendezvousClient::Config cfg;
  cfg.server_host = opt.serverHost.toStdString();
  cfg.server_port = opt.serverPort;
  cfg.id = std::string(impl_->identity->public_id());
  cfg.listen_port = listenPort;
  cfg.external_port_hint = impl_->external_port_hint;
  cfg.sign_challenge = [id = impl_->identity](std::string_view c) { return id->sign_challenge_b64url(c); };

  impl_->rendezvous = std::make_shared<RendezvousClient>(impl_->io, std::move(cfg));
  impl_->rendezvous->start(
      [this]() {
        const auto selfId = QString::fromStdString(std::string(impl_->rendezvous->id()));
        const auto reachable = impl_->rendezvous->reachable();
        const auto observedIp = QString::fromStdString(std::string(impl_->rendezvous->observed_ip()));
        const auto extPort = static_cast<quint16>(impl_->rendezvous->external_port());
        emit registered(selfId, reachable, observedIp, extPort);
        impl_->rendezvous->enable_polling(true);
      },
      [this](const ConnectRequest& req) {
        // Only client-only peers need connect_request.
        if (impl_->rendezvous && impl_->rendezvous->reachable()) return;
        if (!impl_->isAccepted(req.from_id)) return;
        if (impl_->active_peer) return; // queueing could be added later
        impl_->connectToPeer(req.from_id, req.ip, req.port, /*silent*/ false);
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
  impl_->io.stop();
  if (impl_->io_thread.joinable()) impl_->io_thread.join();
  impl_->io.restart();
  impl_->rendezvous.reset();
  impl_->active_peer.reset();
  if (impl_->owns_upnp_mapping) impl_->upnp.remove_mapping_best_effort();
  impl_->owns_upnp_mapping = false;
}

void ChatBackend::setSelfName(const QString& name) {
  const auto nm = name.toStdString();
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = nm;
  }

  // Pure P2P: if we're currently chatting, push the updated name immediately.
  boost::asio::post(impl_->io, [impl = impl_, nm] {
    if (!impl->active_peer) return;
    impl->active_peer->send_name(nm);
  });
}

void ChatBackend::setFriendAccepted(const QString& peerId, bool accepted) {
  impl_->setAccepted(peerId.toStdString(), accepted);
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
    // Best-effort: establish a direct connection so we can learn peer name quickly (P2P).
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
    if (impl->active_peer && std::string(impl->active_peer->peer_id()) == pid) {
      impl->flushOutgoing(pid);
      return;
    }
    impl->attemptDelivery(pid, /*silent*/ false);
  });
}

void ChatBackend::disconnectPeer(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->active_peer) return;
    if (std::string(impl->active_peer->peer_id()) != pid) return;
    impl->active_peer->close();
  });
}

void ChatBackend::warmConnect(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    if (!impl->isAccepted(pid)) return;
    if (impl->active_peer) return;
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}
