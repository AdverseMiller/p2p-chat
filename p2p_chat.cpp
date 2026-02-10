#include "common/framing.hpp"
#include "common/util.hpp"

#include <boost/asio.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <atomic>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unordered_map>

#include <unistd.h>

#ifdef HAVE_UPNP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#endif

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
  bool reachable = true;
};

struct UpnpMapping {
  bool ok = false;
  uint16_t external_port = 0;
  std::string control_url;
  std::string service_type;
  std::string lan_addr;
};

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
    const auto msg = common::base64url_decode(challenge_b64url);
    if (!msg) return {};
    std::vector<uint8_t> sig(64);
    size_t siglen = sig.size();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    const int ok1 = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey_.get());
    int ok2 = 0;
    if (ok1 == 1) {
      ok2 = EVP_DigestSign(ctx, sig.data(), &siglen, msg->data(), msg->size());
    }
    EVP_MD_CTX_free(ctx);
    if (ok2 != 1 || siglen != 64) return {};
    return common::base64url_encode(std::span<const uint8_t>(sig.data(), siglen));
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
    // Unencrypted PEM for simplicity.
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
    public_id_ = common::base64url_encode(std::span<const uint8_t>(pub.data(), pub.size()));
  }

  std::string key_path_;
  PkeyPtr pkey_{nullptr};
  std::string public_id_;
};

class UpnpManager {
 public:
  UpnpManager() = default;
  ~UpnpManager() { remove_mapping_best_effort(); }

  UpnpMapping try_map(uint16_t internal_port, std::string_view description) {
#ifdef HAVE_UPNP
    UpnpMapping out;
    int err = 0;
    UPNPDev* devlist = upnpDiscover(1500, nullptr, nullptr, 0, 0, 2, &err);
    if (!devlist) {
      common::log("UPnP: no devices discovered");
      return out;
    }

    UPNPUrls urls;
    IGDdatas data;
    char lanaddr[64] = {};
    char wanaddr[64] = {};
    std::memset(&urls, 0, sizeof(urls));
    std::memset(&data, 0, sizeof(data));

    const int igd =
        UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
    freeUPNPDevlist(devlist);
    if (igd == 0) {
      common::log("UPnP: no valid IGD found");
      FreeUPNPUrls(&urls);
      return out;
    }

    const std::string lan = lanaddr;
    const std::string control = urls.controlURL ? urls.controlURL : "";
    const std::string service = data.first.servicetype;

    if (control.empty() || service.empty() || lan.empty()) {
      common::log("UPnP: IGD info incomplete");
      FreeUPNPUrls(&urls);
      return out;
    }

    // Try preferred external ports.
    uint16_t mapped_ext = 0;
    const std::string desc(description);
    for (int i = 0; i < 10; ++i) {
      const uint16_t ext = static_cast<uint16_t>(internal_port + i);
      const std::string ext_s = std::to_string(ext);
      const std::string int_s = std::to_string(internal_port);
      const int rc = UPNP_AddPortMapping(control.c_str(),
                                         service.c_str(),
                                         ext_s.c_str(),
                                         int_s.c_str(),
                                         lan.c_str(),
                                         desc.c_str(),
                                         "TCP",
                                         nullptr,
                                         "0");
      if (rc == UPNPCOMMAND_SUCCESS) {
        mapped_ext = ext;
        break;
      }
    }

    if (mapped_ext == 0) {
      common::log("UPnP: port mapping failed");
      FreeUPNPUrls(&urls);
      return out;
    }

    out.ok = true;
    out.external_port = mapped_ext;
    out.control_url = control;
    out.service_type = service;
    out.lan_addr = lan;

    mapping_ = out;
    common::log("UPnP: mapped external TCP port " + std::to_string(mapped_ext) + " -> internal " +
                std::to_string(internal_port));
    FreeUPNPUrls(&urls);
    return out;
#else
    (void)internal_port;
    (void)description;
    common::log("UPnP unavailable; running client-only");
    return UpnpMapping{};
#endif
  }

  void remove_mapping_best_effort() {
#ifdef HAVE_UPNP
    if (!mapping_ || !mapping_->ok) return;
    const std::string ext_s = std::to_string(mapping_->external_port);
    const int rc =
        UPNP_DeletePortMapping(mapping_->control_url.c_str(), mapping_->service_type.c_str(),
                               ext_s.c_str(), "TCP", nullptr);
    if (rc == UPNPCOMMAND_SUCCESS) {
      common::log("UPnP: removed mapping for external TCP port " + ext_s);
    } else {
      common::log("UPnP: failed to remove mapping (best-effort)");
    }
    mapping_.reset();
#endif
  }

 private:
  std::optional<UpnpMapping> mapping_;
};

class PeerSession : public std::enable_shared_from_this<PeerSession> {
 public:
  enum class Role { Initiator, Acceptor };

  using OnClosed = std::function<void()>;
  using OnReady = std::function<void(const std::string& peer_id, const std::string& peer_name)>;

  PeerSession(tcp::socket socket,
              Role role,
              std::string self_id,
              std::string self_name,
              std::function<bool(const std::string&)> allow_peer)
      : socket_(std::move(socket)),
        role_(role),
        self_id_(std::move(self_id)),
        self_name_(std::move(self_name)),
        allow_peer_(std::move(allow_peer)),
        writer_(std::make_shared<common::JsonWriteQueue<tcp::socket>>(socket_)) {}

  void start(OnReady on_ready, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_closed_ = std::move(on_closed);
    if (role_ == Role::Initiator) {
      json hello;
      hello["type"] = "hello";
      hello["id"] = self_id_;
      if (!self_name_.empty()) hello["name"] = self_name_;
      writer_->send(std::move(hello));
      wait_for_hello_ack();
    } else {
      wait_for_hello();
    }
  }

  void start_accept_with_hello(json hello, OnReady on_ready, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_closed_ = std::move(on_closed);
    if (role_ != Role::Acceptor) {
      protocol_error("start_accept_with_hello used for non-acceptor");
      return;
    }
    if (!hello.contains("id") || !hello["id"].is_string()) {
      protocol_error("hello missing id");
      return;
    }
    peer_id_ = hello["id"].get<std::string>();
    if (!common::is_valid_id(peer_id_)) {
      protocol_error("peer id invalid");
      return;
    }
    if (allow_peer_ && !allow_peer_(peer_id_)) {
      send_error_and_close("not friends");
      return;
    }
    if (hello.contains("name") && hello["name"].is_string()) peer_name_ = hello["name"].get<std::string>();

    json ack;
    ack["type"] = "hello_ack";
    ack["id"] = self_id_;
    if (!self_name_.empty()) ack["name"] = self_name_;
    writer_->send(std::move(ack));

    ready_ = true;
    if (on_ready_) on_ready_(peer_id_, peer_name_);
    common::log("peer connected: " + peer_id_);
    read_loop();
  }

  void send_chat(std::string text) {
    if (!ready_) return;
    json msg;
    msg["type"] = "chat";
    msg["from"] = self_id_;
    msg["text"] = std::move(text);
    writer_->send(std::move(msg));
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

 private:
  void send_error_and_close(std::string message) {
    auto self = shared_from_this();
    json e;
    e["type"] = "error";
    e["message"] = std::move(message);
    common::async_write_json(socket_, e, [self](const boost::system::error_code&) { self->close(); });
  }

  void wait_for_hello() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->on_io_error("peer hello read", ec);
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "hello") {
        return self->protocol_error("expected hello");
      }
      if (!j.contains("id") || !j["id"].is_string()) return self->protocol_error("hello missing id");
      self->peer_id_ = j["id"].get<std::string>();
      if (!common::is_valid_id(self->peer_id_)) return self->protocol_error("peer id invalid");
      if (self->allow_peer_ && !self->allow_peer_(self->peer_id_)) {
        self->send_error_and_close("not friends");
        return;
      }
      if (j.contains("name") && j["name"].is_string()) self->peer_name_ = j["name"].get<std::string>();

      json ack;
      ack["type"] = "hello_ack";
      ack["id"] = self->self_id_;
      if (!self->self_name_.empty()) ack["name"] = self->self_name_;
      self->writer_->send(std::move(ack));

      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      common::log("peer connected: " + self->peer_id_);
      self->read_loop();
    });
  }

  void wait_for_hello_ack() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->on_io_error("peer hello_ack read", ec);
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "hello_ack") {
        return self->protocol_error("expected hello_ack");
      }
      if (!j.contains("id") || !j["id"].is_string()) return self->protocol_error("hello_ack missing id");
      self->peer_id_ = j["id"].get<std::string>();
      if (!common::is_valid_id(self->peer_id_)) return self->protocol_error("peer id invalid");
      if (j.contains("name") && j["name"].is_string()) self->peer_name_ = j["name"].get<std::string>();

      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      common::log("peer connected: " + self->peer_id_);
      self->read_loop();
    });
  }

  void read_loop() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->on_io_error("peer read", ec);
      self->handle_peer_message(j);
      self->read_loop();
    });
  }

  void handle_peer_message(const json& j) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();
    if (type == "chat") {
      if (!j.contains("text") || !j["text"].is_string()) return;
      const std::string text = j["text"].get<std::string>();
      const std::string& label = peer_name_.empty() ? peer_id_ : peer_name_;
      std::cout << "[" << label << "] " << text << "\n";
      std::cout.flush();
      return;
    }
    if (type == "busy") {
      std::string msg = "peer busy";
      if (j.contains("message") && j["message"].is_string()) msg = j["message"].get<std::string>();
      common::log("peer says busy: " + msg);
      close();
      return;
    }
    if (type == "error") {
      std::string msg = "peer error";
      if (j.contains("message") && j["message"].is_string()) msg = j["message"].get<std::string>();
      common::log("peer error: " + msg);
      close();
      return;
    }
  }

  void protocol_error(std::string_view msg) {
    common::log(std::string("protocol error: ") + std::string(msg));
    close();
  }

  void on_io_error(std::string_view where, const boost::system::error_code& ec) {
    if (ec == boost::asio::error::operation_aborted) return;
    if (ec == boost::asio::error::eof) {
      common::log(std::string(where) + ": disconnected");
    } else {
      common::log(std::string(where) + ": " + ec.message());
    }
    close();
  }

  tcp::socket socket_;
  Role role_;
  std::string self_id_;
  std::string peer_id_;
  std::string self_name_;
  std::string peer_name_;
  std::function<bool(const std::string&)> allow_peer_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;
  bool ready_ = false;
  bool closed_ = false;
  OnReady on_ready_;
  OnClosed on_closed_;
};

class RendezvousClient : public std::enable_shared_from_this<RendezvousClient> {
 public:
  struct Config {
    std::string server_host;
    uint16_t server_port = 0;
    std::string id; // public id (pubkey, base64url)
    uint16_t listen_port = 0;
    uint16_t external_port_hint = 0;
    std::function<std::string(std::string_view challenge_b64url)> sign_challenge;
  };

  struct LookupResult {
    bool ok = false;
    std::string target_id;
    std::string ip;
    uint16_t port = 0;
    bool reachable = false;
  };

  using OnLookup = std::function<void(LookupResult)>;

  RendezvousClient(boost::asio::io_context& io, Config cfg)
      : io_(io),
        cfg_(std::move(cfg)),
        socket_(io),
        resolver_(io),
        heartbeat_timer_(io),
        poll_timer_(io) {}

  using OnConnectRequest = std::function<void(const ConnectRequest&)>;
  using OnFriendRequest = std::function<void(const std::string& from_id, const std::string& intro)>;
  using OnFriendAccept = std::function<void(const std::string& from_id)>;

  void start(std::function<void()> on_registered,
             OnConnectRequest on_connect_request,
             OnFriendRequest on_friend_request,
             OnFriendAccept on_friend_accept) {
    on_registered_ = std::move(on_registered);
    on_connect_request_ = std::move(on_connect_request);
    on_friend_request_ = std::move(on_friend_request);
    on_friend_accept_ = std::move(on_friend_accept);

    auto self = shared_from_this();
    resolver_.async_resolve(cfg_.server_host, std::to_string(cfg_.server_port),
                            [self](const boost::system::error_code& ec, tcp::resolver::results_type results) {
                              if (ec) {
                                common::log(std::string("resolve error: ") + ec.message());
                                self->stop();
                                return;
                              }
                              self->connect(results);
                            });
  }

  void stop() {
    stopped_ = true;
    boost::system::error_code ignored;
    heartbeat_timer_.cancel();
    poll_timer_.cancel();
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
  }

  bool stopped() const { return stopped_; }

  std::string_view id() const { return id_; }
  bool reachable() const { return reachable_; }
  uint16_t external_port() const { return external_port_; }
  std::string_view observed_ip() const { return observed_ip_; }

  void send_lookup(std::string target_id, OnLookup cb) {
    pending_lookups_.push_back({std::move(target_id), std::move(cb)});
    json j;
    j["type"] = "lookup";
    j["from_id"] = id_;
    j["target_id"] = pending_lookups_.back().target_id;
    writer_->send(std::move(j));
  }

  void send_connect_request(const std::string& to_id) {
    json j;
    j["type"] = "connect_request";
    j["from_id"] = id_;
    j["to_id"] = to_id;
    writer_->send(std::move(j));
  }

  void send_friend_request(const std::string& to_id, std::string intro) {
    json j;
    j["type"] = "friend_request";
    j["from_id"] = id_;
    j["to_id"] = to_id;
    j["intro"] = std::move(intro);
    writer_->send(std::move(j));
  }

  void send_friend_accept(const std::string& requester_id) {
    json j;
    j["type"] = "friend_accept";
    j["from_id"] = id_;           // acceptor
    j["to_id"] = requester_id;    // original requester to notify
    writer_->send(std::move(j));
  }

  void enable_polling(bool enabled) {
    polling_enabled_ = enabled;
    if (polling_enabled_) schedule_poll();
  }

 private:
  struct PendingLookup {
    std::string target_id;
    OnLookup cb;
  };

  void connect(const tcp::resolver::results_type& results) {
    auto self = shared_from_this();
    auto timer = std::make_shared<boost::asio::steady_timer>(io_);
    timer->expires_after(kConnectTimeout);
    timer->async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      common::log("connect to rendezvous timed out");
      self->stop();
    });

    boost::asio::async_connect(socket_, results, [self, timer](const boost::system::error_code& ec, const tcp::endpoint&) {
      timer->cancel();
      if (ec) {
        common::log(std::string("connect error: ") + ec.message());
        self->stop();
        return;
      }
      self->writer_ = std::make_shared<common::JsonWriteQueue<tcp::socket>>(self->socket_);
      common::log("connected to rendezvous");
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
    heartbeat_timer_.expires_after(kHeartbeatInterval);
    auto self = shared_from_this();
    heartbeat_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_) return;
      json hb;
      hb["type"] = "heartbeat";
      hb["id"] = self->id_;
      self->writer_->send(std::move(hb));
      self->schedule_heartbeat();
    });
  }

  void schedule_poll() {
    poll_timer_.expires_after(kPollInterval);
    auto self = shared_from_this();
    poll_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_ || !self->polling_enabled_) return;
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
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
          common::log(std::string("rendezvous read error: ") + ec.message());
        }
        self->stop();
        return;
      }
      self->handle_message(j);
      self->read_loop();
    });
  }

  void handle_message(const json& j) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();

    if (type == "register_ok") {
      if (!j.contains("id") || !j["id"].is_string()) return;
      id_ = j["id"].get<std::string>();
      observed_ip_ = (j.contains("observed_ip") && j["observed_ip"].is_string()) ? j["observed_ip"].get<std::string>() : "";
      reachable_ = j.contains("reachable") && j["reachable"].is_boolean() ? j["reachable"].get<bool>() : false;
      external_port_ = j.contains("external_port") && j["external_port"].is_number_integer()
                           ? static_cast<uint16_t>(j["external_port"].get<int>())
                           : 0;
      common::log("registered id=" + id_ + " reachable=" + std::string(reachable_ ? "true" : "false") +
                  " external_port=" + std::to_string(external_port_) + " observed_ip=" + observed_ip_);
      schedule_heartbeat();
      if (on_registered_) on_registered_();
      return;
    }

    if (type == "register_challenge") {
      if (!j.contains("id") || !j["id"].is_string()) return;
      if (!j.contains("challenge") || !j["challenge"].is_string()) return;
      const std::string cid = j["id"].get<std::string>();
      const std::string challenge = j["challenge"].get<std::string>();
      if (cid != cfg_.id) {
        common::log("register challenge id mismatch");
        stop();
        return;
      }
      if (!cfg_.sign_challenge) {
        common::log("no signer configured");
        stop();
        return;
      }
      const std::string sig = cfg_.sign_challenge(challenge);
      if (sig.empty()) {
        common::log("failed to sign challenge");
        stop();
        return;
      }
      json fin;
      fin["type"] = "register_finish";
      fin["id"] = cfg_.id;
      fin["signature"] = sig;
      writer_->send(std::move(fin));
      return;
    }

    if (type == "error") {
      const std::string msg = (j.contains("message") && j["message"].is_string()) ? j["message"].get<std::string>()
                                                                                  : "unknown error";
      common::log("server error: " + msg);
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
      // Unsolicited lookup_result; just print.
      std::cout << "lookup " << r.target_id << ": ok=" << (r.ok ? "true" : "false")
                << " reachable=" << (r.reachable ? "true" : "false") << " " << r.ip << ":" << r.port
                << "\n";
      std::cout.flush();
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
          r.reachable = true;
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
  bool polling_enabled_ = false;
  bool stopped_ = false;

  std::string id_;
  std::string observed_ip_;
  bool reachable_ = false;
  uint16_t external_port_ = 0;

  std::vector<PendingLookup> pending_lookups_;
  std::function<void()> on_registered_;
  OnConnectRequest on_connect_request_;
  OnFriendRequest on_friend_request_;
  OnFriendAccept on_friend_accept_;
};

class App : public std::enable_shared_from_this<App> {
 public:
  struct Options {
    std::string server_host;
    uint16_t server_port = 0;
    std::string display_name;
    std::string key_path;
    uint16_t listen_port = 0;
    bool no_upnp = false;
    uint16_t external_port = 0; // optional override when --no-upnp is used
  };

  App(boost::asio::io_context& io, Options opt, std::shared_ptr<Identity> identity)
      : io_(io),
        opt_(std::move(opt)),
        identity_(std::move(identity)),
        acceptor_(io),
        signals_(io, SIGINT, SIGTERM),
        stdin_(io, ::dup(STDIN_FILENO)) {}

  void run() {
    signals_.async_wait([self = shared_from_this()](const boost::system::error_code&, int) {
      common::log("signal received, shutting down");
      self->shutdown();
    });

    self_name_ = opt_.display_name;
    bind_acceptor();
    start_accept_loop();

    // Determine which external port to ask the rendezvous server to probe.
    if (!opt_.no_upnp) {
      const auto map = upnp_.try_map(listen_port_, "p2p_chat (miniupnpc)");
      owns_upnp_mapping_ = map.ok;
      external_port_hint_ = map.ok ? map.external_port : 0;
      if (!external_port_hint_) external_port_hint_ = (opt_.external_port ? opt_.external_port : listen_port_);
    } else {
      external_port_hint_ = opt_.external_port ? opt_.external_port : listen_port_;
      common::log("UPnP disabled; will let rendezvous probe reachability on port " +
                  std::to_string(external_port_hint_));
    }

    RendezvousClient::Config cfg;
    cfg.server_host = opt_.server_host;
    cfg.server_port = opt_.server_port;
    cfg.id = std::string(identity_->public_id());
    cfg.listen_port = listen_port_;
    cfg.external_port_hint = external_port_hint_;
    cfg.sign_challenge = [id = identity_](std::string_view c) { return id->sign_challenge_b64url(c); };

    rendezvous_ = std::make_shared<RendezvousClient>(io_, std::move(cfg));
    rendezvous_->start(
        [self = shared_from_this()]() { self->on_registered(); },
        [self = shared_from_this()](const ConnectRequest& req) { self->on_connect_request(req); },
        [self = shared_from_this()](const std::string& from_id, const std::string& intro) {
          self->on_friend_request(from_id, intro);
        },
        [self = shared_from_this()](const std::string& from_id) { self->on_friend_accept(from_id); });

    start_stdin_read();
  }

 private:
  enum class FriendStatus { None, OutgoingPending, IncomingPending, Accepted };

  struct FriendEntry {
    FriendStatus status = FriendStatus::None;
    std::string name;   // learned after peer connection
    std::string intro;  // last incoming intro (for UI)
  };

  static std::string_view status_to_string(FriendStatus s) {
    switch (s) {
      case FriendStatus::None:
        return "none";
      case FriendStatus::OutgoingPending:
        return "outgoing_pending";
      case FriendStatus::IncomingPending:
        return "incoming_pending";
      case FriendStatus::Accepted:
        return "accepted";
    }
    return "unknown";
  }

  FriendEntry& friend_entry(const std::string& peer_id) { return friends_[peer_id]; }

  bool is_friend_accepted(const std::string& peer_id) const {
    auto it = friends_.find(peer_id);
    return it != friends_.end() && it->second.status == FriendStatus::Accepted;
  }

  std::string display_name_for(const std::string& peer_id) const {
    auto it = friends_.find(peer_id);
    if (it != friends_.end() && !it->second.name.empty()) return it->second.name;
    return peer_id;
  }

  void queue_outgoing_message(const std::string& peer_id, std::string text) {
    pending_outgoing_[peer_id].push_back(std::move(text));
  }

  void flush_outgoing_messages(const std::string& peer_id) {
    if (!active_peer_ || std::string(active_peer_->peer_id()) != peer_id) return;
    auto it = pending_outgoing_.find(peer_id);
    if (it == pending_outgoing_.end()) return;
    while (!it->second.empty()) {
      active_peer_->send_chat(it->second.front());
      it->second.pop_front();
    }
    pending_outgoing_.erase(it);
  }

  void bind_acceptor() {
    uint16_t port = opt_.listen_port ? opt_.listen_port : common::choose_default_listen_port();
    for (int attempt = 0; attempt < 20; ++attempt) {
      boost::system::error_code ec;
      tcp::endpoint ep(boost::asio::ip::address_v4::any(), port);
      acceptor_.open(ep.protocol(), ec);
      if (ec) {
        port = common::choose_default_listen_port();
        continue;
      }
      acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
      acceptor_.bind(ep, ec);
      if (ec) {
        acceptor_.close();
        port = common::choose_default_listen_port();
        continue;
      }
      acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
      if (ec) {
        acceptor_.close();
        port = common::choose_default_listen_port();
        continue;
      }
      listen_port_ = port;
      common::log("listening for peers on 0.0.0.0:" + std::to_string(listen_port_));
      return;
    }
    throw std::runtime_error("failed to bind acceptor");
  }

  void start_accept_loop() {
    acceptor_.async_accept([self = shared_from_this()](const boost::system::error_code& ec, tcp::socket socket) {
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) common::log(std::string("accept error: ") + ec.message());
        return;
      }
      self->handle_incoming_socket(std::move(socket));
      self->start_accept_loop();
    });
  }

  void handle_incoming_socket(tcp::socket socket) {
    auto sock = std::make_shared<tcp::socket>(std::move(socket));
    boost::system::error_code ec;
    const auto ep = sock->remote_endpoint(ec);
    common::log(std::string("incoming connection from ") + (ec ? std::string("unknown") : common::endpoint_to_string(ep)));

    auto self = shared_from_this();
    common::async_read_json(*sock, common::kMaxFrameSize, [self, sock](const boost::system::error_code& ec2, json j) {
      if (ec2) return;
      if (!j.contains("type") || !j["type"].is_string()) return;
      const std::string type = j["type"].get<std::string>();

      if (type == "probe") {
        if (!j.contains("challenge") || !j["challenge"].is_string()) return;
        const std::string challenge = j["challenge"].get<std::string>();
        json resp;
        resp["type"] = "probe_ok";
        resp["id"] = std::string(self->identity_->public_id());
        resp["signature"] = self->identity_->sign_challenge_b64url(challenge);
        common::async_write_json(*sock, resp, [sock](const boost::system::error_code&) {
          boost::system::error_code ignored;
          sock->shutdown(tcp::socket::shutdown_both, ignored);
          sock->close(ignored);
        });
        return;
      }

      if (type == "hello") {
        if (self->active_peer_) {
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
        self->start_peer_session_with_hello(std::move(*sock), std::move(j));
        return;
      }
    });
  }

  void start_peer_session(tcp::socket socket, PeerSession::Role role) {
    if (!rendezvous_ || rendezvous_->id().empty()) {
      common::log("cannot start peer session before registration");
      return;
    }
    auto self = shared_from_this();
    active_peer_ =
        std::make_shared<PeerSession>(std::move(socket), role, std::string(rendezvous_->id()), self_name_,
                                      [self](const std::string& peer_id) { return self->is_friend_accepted(peer_id); });
    active_peer_->start(
        [self](const std::string& peer_id, const std::string& peer_name) { self->on_peer_ready(peer_id, peer_name); },
        [self]() {
      self->active_peer_.reset();
      common::log("returned to idle");
      if (self->rendezvous_ && !self->rendezvous_->reachable() && !self->pending_requests_.empty()) {
        auto req = self->pending_requests_.front();
        self->pending_requests_.erase(self->pending_requests_.begin());
        common::log("processing queued connect request from " + req.from_id);
        self->connect_to_peer(req.from_id, req.ip, req.port);
      }
    });
  }

  void start_peer_session_with_hello(tcp::socket socket, json hello) {
    if (!rendezvous_ || rendezvous_->id().empty()) return;
    auto self = shared_from_this();
    active_peer_ =
        std::make_shared<PeerSession>(std::move(socket), PeerSession::Role::Acceptor, std::string(rendezvous_->id()),
                                      self_name_,
                                      [self](const std::string& peer_id) { return self->is_friend_accepted(peer_id); });
    active_peer_->start_accept_with_hello(
        std::move(hello),
        [self](const std::string& peer_id, const std::string& peer_name) { self->on_peer_ready(peer_id, peer_name); },
        [self]() {
          self->active_peer_.reset();
          common::log("returned to idle");
        });
  }

  void on_peer_ready(const std::string& peer_id, const std::string& peer_name) {
    auto& f = friend_entry(peer_id);
    if (!peer_name.empty() && f.status == FriendStatus::Accepted) f.name = peer_name;
    flush_outgoing_messages(peer_id);
  }

  void attempt_delivery(const std::string& peer_id) {
    if (!rendezvous_ || active_peer_) return;
    if (!is_friend_accepted(peer_id)) return;

    rendezvous_->send_lookup(peer_id, [self = shared_from_this()](RendezvousClient::LookupResult r) {
      if (!r.ok) {
        common::log("lookup failed (peer offline?)");
        return;
      }

      if (r.reachable && r.port != 0) {
        self->connect_to_peer(r.target_id, r.ip, r.port);
        return;
      }

      if (self->rendezvous_ && self->rendezvous_->reachable()) {
        self->rendezvous_->send_connect_request(r.target_id);
        common::log("sent connect request to " + r.target_id + "; waiting for inbound connection");
        return;
      }

      common::log("direct connection not possible: both you and peer are unreachable (client-only)");
    });
  }

  void connect_to_peer(std::string peer_id, std::string ip, uint16_t port) {
    if (active_peer_) {
      common::log("already in an active chat session");
      return;
    }

    auto socket = std::make_shared<tcp::socket>(io_);
    auto timer = std::make_shared<boost::asio::steady_timer>(io_);
    timer->expires_after(kConnectTimeout);

    auto self = shared_from_this();
    timer->async_wait([socket, self](const boost::system::error_code& ec) {
      if (ec) return;
      boost::system::error_code ignored;
      socket->close(ignored);
      common::log("peer connect timed out");
    });

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(ip, ec);
    if (ec) {
      common::log("invalid peer ip: " + ip);
      return;
    }
    tcp::endpoint ep(addr, port);

    common::log("connecting to peer " + peer_id + " at " + ip + ":" + std::to_string(port));
    socket->async_connect(ep, [self, socket, timer](const boost::system::error_code& ec2) {
      timer->cancel();
      if (ec2) {
        common::log(std::string("peer connect error: ") + ec2.message());
        return;
      }
      self->start_peer_session(std::move(*socket), PeerSession::Role::Initiator);
    });
  }

  void on_registered() {
    self_name_ = opt_.display_name;
    const bool reachable = rendezvous_->reachable();
    std::cout << "Your ID: " << identity_->public_id() << "\n";
    if (!self_name_.empty()) std::cout << "Your name: " << self_name_ << "\n";
    std::cout << "Reachable (server-verified): " << (reachable ? "true" : "false") << "\n";
    if (reachable) std::cout << "External port (server-verified): " << rendezvous_->external_port() << "\n";
    std::cout << "Commands: /name <name>, /lookup <id>, /friend <id> [intro], /accept <id>, /msg <id> <text>, /quit\n";
    std::cout.flush();

    // Poll for friend/connect notifications (works for reachable and client-only modes).
    rendezvous_->enable_polling(true);
    registered_ = true;

    common::log(std::string("reachability (server): ") + (reachable ? "reachable" : "unreachable"));
  }

  void on_connect_request(const ConnectRequest& req) {
    // Only relevant if we are client-only; then auto-connect.
    if (rendezvous_ && rendezvous_->reachable()) return;
    if (!is_friend_accepted(req.from_id)) {
      common::log("ignoring connect request from non-friend " + req.from_id);
      return;
    }
    if (active_peer_) {
      pending_requests_.push_back(req);
      return;
    }
    common::log("received connect request from " + req.from_id + " -> connecting outbound");
    connect_to_peer(req.from_id, req.ip, req.port);
  }

  void on_friend_request(const std::string& from_id, const std::string& intro) {
    auto& f = friend_entry(from_id);
    if (f.status == FriendStatus::Accepted) return;
    if (f.status != FriendStatus::IncomingPending) {
      f.status = FriendStatus::IncomingPending;
      f.intro = intro;
      std::cout << "Friend request from " << from_id;
      if (!intro.empty()) std::cout << ": " << intro;
      std::cout << "\n";
      std::cout << "Use: /accept " << from_id << " (or /reject " << from_id << ")\n";
      std::cout.flush();
    }
  }

  void on_friend_accept(const std::string& from_id) {
    auto& f = friend_entry(from_id);
    f.status = FriendStatus::Accepted;
    std::cout << "Friend request accepted by " << from_id << "\n";
    std::cout.flush();
    if (pending_outgoing_.find(from_id) != pending_outgoing_.end()) attempt_delivery(from_id);
  }

  void start_stdin_read() {
    auto self = shared_from_this();
    boost::asio::async_read_until(stdin_, stdin_buf_, '\n',
                                  [self](const boost::system::error_code& ec, std::size_t) {
                                    if (ec) {
                                      if (ec != boost::asio::error::operation_aborted) {
                                        self->shutdown();
                                      }
                                      return;
                                    }
                                    std::istream is(&self->stdin_buf_);
                                    std::string line;
                                    std::getline(is, line);
                                    if (!line.empty() && line.back() == '\r') line.pop_back();
                                    self->handle_stdin_line(line);
                                    self->start_stdin_read();
                                  });
  }

  void handle_stdin_line(const std::string& line) {
    if (line == "/quit") {
      shutdown();
      return;
    }
    if (!registered_ || !rendezvous_) return;
    if (line.empty()) return;

    if (line.rfind("/name ", 0) == 0) {
      std::string name = line.substr(std::string("/name ").size());
      while (!name.empty() && name.front() == ' ') name.erase(name.begin());
      if (name.size() > 32 || name.find('\n') != std::string::npos || name.find('\r') != std::string::npos) {
        common::log("invalid name (max 32 chars, no newlines)");
        return;
      }
      self_name_ = std::move(name);
      common::log("name updated (takes effect on next connection)");
      return;
    }

    if (line.rfind("/lookup ", 0) == 0) {
      const std::string target = line.substr(std::string("/lookup ").size());
      rendezvous_->send_lookup(target, [target](RendezvousClient::LookupResult r) {
        std::cout << "lookup " << target << ": ok=" << (r.ok ? "true" : "false")
                  << " reachable=" << (r.reachable ? "true" : "false") << " " << r.ip << ":" << r.port
                  << "\n";
        std::cout.flush();
      });
      return;
    }

    if (line.rfind("/friend ", 0) == 0) {
      const std::string rest = line.substr(std::string("/friend ").size());
      const auto sp = rest.find(' ');
      const std::string peer_id = (sp == std::string::npos) ? rest : rest.substr(0, sp);
      std::string intro = (sp == std::string::npos) ? "" : rest.substr(sp + 1);
      while (!intro.empty() && intro.front() == ' ') intro.erase(intro.begin());

      if (!common::is_valid_id(peer_id)) {
        common::log("usage: /friend <id> [intro]");
        return;
      }
      auto& f = friend_entry(peer_id);
      if (f.status == FriendStatus::None) f.status = FriendStatus::OutgoingPending;
      rendezvous_->send_friend_request(peer_id, std::move(intro));
      common::log("sent friend request to " + peer_id);
      return;
    }

    if (line.rfind("/accept ", 0) == 0) {
      const std::string peer_id = line.substr(std::string("/accept ").size());
      if (!common::is_valid_id(peer_id)) {
        common::log("usage: /accept <id>");
        return;
      }
      auto& f = friend_entry(peer_id);
      f.status = FriendStatus::Accepted;
      rendezvous_->send_friend_accept(peer_id);
      common::log("accepted friend request from " + peer_id);
      if (pending_outgoing_.find(peer_id) != pending_outgoing_.end()) attempt_delivery(peer_id);
      return;
    }

    if (line.rfind("/reject ", 0) == 0) {
      const std::string peer_id = line.substr(std::string("/reject ").size());
      if (!common::is_valid_id(peer_id)) {
        common::log("usage: /reject <id>");
        return;
      }
      friends_.erase(peer_id);
      pending_outgoing_.erase(peer_id);
      common::log("rejected/removed " + peer_id);
      return;
    }

    if (line.rfind("/msg ", 0) == 0) {
      const std::string rest = line.substr(std::string("/msg ").size());
      const auto sp = rest.find(' ');
      if (sp == std::string::npos) {
        common::log("usage: /msg <id> <text>");
        return;
      }
      const std::string peer_id = rest.substr(0, sp);
      std::string text = rest.substr(sp + 1);
      while (!text.empty() && text.front() == ' ') text.erase(text.begin());
      if (text.empty() || !common::is_valid_id(peer_id)) {
        common::log("usage: /msg <id> <text>");
        return;
      }
      if (peer_id == rendezvous_->id()) {
        common::log("cannot message yourself");
        return;
      }

      if (active_peer_) {
        if (std::string(active_peer_->peer_id()) != peer_id) {
          common::log("already in an active chat session");
          return;
        }
        active_peer_->send_chat(std::move(text));
        return;
      }

      if (!is_friend_accepted(peer_id)) {
        auto& f = friend_entry(peer_id);
        if (f.status == FriendStatus::None) {
          f.status = FriendStatus::OutgoingPending;
          rendezvous_->send_friend_request(peer_id, "");
          common::log("sent friend request to " + peer_id + " (waiting for /accept)");
        } else {
          common::log("waiting for friend acceptance from " + peer_id + " (status=" +
                      std::string(status_to_string(f.status)) + ")");
        }
        queue_outgoing_message(peer_id, std::move(text));
        return;
      }

      queue_outgoing_message(peer_id, std::move(text));
      attempt_delivery(peer_id);
      return;
    }

    if (!active_peer_) {
      common::log("not in a chat session. Use /msg <id> <text>.");
      return;
    }

    // Chat line.
    active_peer_->send_chat(line);
  }

  void shutdown() {
    if (shutting_down_.exchange(true)) return;

    common::log("shutting down");
    if (active_peer_) active_peer_->close();
    if (rendezvous_) rendezvous_->stop();
    if (owns_upnp_mapping_) upnp_.remove_mapping_best_effort();

    boost::system::error_code ignored;
    acceptor_.close(ignored);
    signals_.cancel(ignored);
    stdin_.close(ignored);
    io_.stop();
  }

  boost::asio::io_context& io_;
  Options opt_;
  std::shared_ptr<Identity> identity_;
  tcp::acceptor acceptor_;
  boost::asio::signal_set signals_;

  uint16_t listen_port_ = 0;

  UpnpManager upnp_;
  uint16_t external_port_hint_ = 0;
  bool owns_upnp_mapping_ = false;

  std::shared_ptr<RendezvousClient> rendezvous_;
  bool registered_ = false;

  std::string self_name_;
  std::shared_ptr<PeerSession> active_peer_;
  std::vector<ConnectRequest> pending_requests_;
  std::unordered_map<std::string, FriendEntry> friends_;
  std::unordered_map<std::string, std::deque<std::string>> pending_outgoing_;

  boost::asio::posix::stream_descriptor stdin_;
  boost::asio::streambuf stdin_buf_;
  std::atomic<bool> shutting_down_{false};
};

std::optional<App::Options> parse_args(int argc, char** argv) {
  App::Options opt;
  auto default_key_path = []() -> std::string {
    // Keep CLI state under XDG config dir.
    // Matches the GUI's organization folder name ("p2p-chat").
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    const char* home = std::getenv("HOME");
    const std::string cfgroot = (xdg && *xdg) ? std::string(xdg)
                               : (home && *home) ? (std::string(home) + "/.config")
                                                 : std::string();

    const std::string canonical = cfgroot.empty() ? "./p2p-chat/identity.pem" : (cfgroot + "/p2p-chat/identity.pem");
    const std::string legacy = cfgroot.empty() ? "./p2p_chat/identity.pem" : (cfgroot + "/p2p_chat/identity.pem");

    // Best-effort migration from legacy underscore dir to canonical dash dir.
    try {
      if (!std::filesystem::exists(canonical) && std::filesystem::exists(legacy)) {
        std::filesystem::create_directories(std::filesystem::path(canonical).parent_path());
        std::filesystem::copy_file(legacy, canonical, std::filesystem::copy_options::skip_existing);
      }
    } catch (...) {
    }
    return canonical;
  };
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto get_val = [&](std::string_view flag) -> std::optional<std::string> {
      if (a == flag) {
        if (i + 1 >= argc) return std::nullopt;
        return std::string(argv[++i]);
      }
      return std::nullopt;
    };

    if (auto v = get_val("--server")) {
      const auto hp = common::parse_host_port(*v);
      if (!hp) return std::nullopt;
      opt.server_host = hp->host;
      opt.server_port = hp->port;
      continue;
    }
    if (a == "--no-upnp") {
      opt.no_upnp = true;
      continue;
    }
    if (auto v = get_val("--name")) {
      opt.display_name = *v;
      continue;
    }
    if (auto v = get_val("--key")) {
      opt.key_path = *v;
      continue;
    }
    if (auto v = get_val("--id")) {
      // Legacy: --id used to be a short human-readable ID. Cryptographic IDs now require a key.
      // If it looks like a public key, reject; otherwise treat as a key path.
      if (common::is_valid_id(*v) && v->size() >= 40) return std::nullopt;
      opt.key_path = *v;
      continue;
    }
    if (auto v = get_val("--listen")) {
      const int p = std::stoi(*v);
      if (p <= 0 || p > 65535) return std::nullopt;
      opt.listen_port = static_cast<uint16_t>(p);
      continue;
    }
    if (auto v = get_val("--external-port")) {
      const int p = std::stoi(*v);
      if (p <= 0 || p > 65535) return std::nullopt;
      opt.external_port = static_cast<uint16_t>(p);
      continue;
    }
    return std::nullopt;
  }

  if (opt.server_host.empty() || opt.server_port == 0) {
    // Default well-known rendezvous server.
    opt.server_host = "learn.fairuse.org";
    opt.server_port = 5555;
  }
  if (opt.key_path.empty()) opt.key_path = default_key_path();
  if (!opt.display_name.empty()) {
    if (opt.display_name.size() > 32) return std::nullopt;
    if (opt.display_name.find('\n') != std::string::npos || opt.display_name.find('\r') != std::string::npos) {
      return std::nullopt;
    }
  }
  return opt;
}

} // namespace

int main(int argc, char** argv) {
  const auto opt = parse_args(argc, argv);
  if (!opt) {
    std::cerr << "Usage: " << argv[0]
              << " [--server <host:port>] [--key <path>] [--name <name>] [--listen <port>] [--no-upnp] [--external-port <port>]\n"
              << "Default server: learn.fairuse.org:5555\n";
    return 2;
  }

  try {
    boost::asio::io_context io;
    common::log(std::string("identity key: ") + opt->key_path);
    auto identity = Identity::load_or_create(opt->key_path);
    auto app = std::make_shared<App>(io, *opt, std::move(identity));
    app->run();
    io.run();
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << "\n";
    return 1;
  }
}
