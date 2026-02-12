#include "common/framing.hpp"
#include "common/crypto.hpp"
#include "common/util.hpp"

#include <boost/asio.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using common::json;

namespace {

constexpr auto kTtl = std::chrono::seconds(60);
constexpr auto kCleanupInterval = std::chrono::seconds(5);

struct FriendRequest {
  std::string from_id;
  std::chrono::steady_clock::time_point created_at{};
};

struct Registration {
  std::string id;
  std::string raw_observed_ip;
  std::string observed_ip;
  std::string udp_ip;
  uint16_t udp_port = 0;
  std::chrono::steady_clock::time_point last_seen{};
  std::weak_ptr<void> owner_tag;
};

std::string random_challenge_b64url(std::size_t nbytes = 32) {
  std::vector<uint8_t> buf(nbytes);
  if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
    // Fallback: best-effort (not ideal).
    std::random_device rd;
    for (auto& b : buf) b = static_cast<uint8_t>(rd());
  }
  return common::base64url_encode(buf);
}

class RendezvousServer;

class ClientSession : public std::enable_shared_from_this<ClientSession> {
 public:
  ClientSession(RendezvousServer& server, tcp::socket socket);

  void start();
  void stop();

  std::string_view id() const { return id_; }
  std::string observed_ip() const { return observed_ip_; }
  std::shared_ptr<void> owner_tag() const { return owner_tag_; }

  void send(json msg) { writer_->send(std::move(msg)); }

 private:
  friend class RendezvousServer;

  void do_read();
  void handle_message(const json& msg);
  void send_error(std::string_view message);
  void send_register_ok();

  RendezvousServer& server_;
  tcp::socket socket_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;

  std::string id_;
  std::string observed_ip_;
  std::shared_ptr<void> owner_tag_ = std::make_shared<int>(1);
  bool stopped_ = false;

  // Registration/auth handshake
  struct PendingAuth {
    std::string id;
    std::string challenge_b64url;
  };
  std::optional<PendingAuth> pending_auth_;
};

class RendezvousServer {
 public:
  explicit RendezvousServer(boost::asio::io_context& io)
      : io_(io), acceptor_(io), udp_socket_(io), cleanup_timer_(io), public_ip_timer_(io) {}

  void set_public_ip_fetch_enabled(bool enabled) { public_ip_fetch_enabled_ = enabled; }

  void listen(const tcp::endpoint& ep) {
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();

    // Also listen on UDP for NAT-mapping discovery and hole-punching assist.
    boost::system::error_code ec;
    udp_socket_.open(udp::v4(), ec);
    if (!ec) {
      udp_socket_.bind(udp::endpoint(ep.address(), ep.port()), ec);
    }
    if (!ec) {
      udp_read_loop();
    } else {
      common::log(std::string("udp bind failed: ") + ec.message());
    }

    common::log(std::string("rendezvous_server listening on ") + common::endpoint_to_string(ep));
    // Warm public IP cache early to reduce races for LAN clients.
    ensure_public_ip_fresh();
    do_accept();
    schedule_cleanup();
  }

  void stop() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
    udp_socket_.close(ignored);
    cleanup_timer_.cancel();
    public_ip_timer_.cancel();
  }

  std::optional<Registration> get_registration(std::string_view id) {
    auto it = regs_.find(std::string(id));
    if (it == regs_.end()) return std::nullopt;
    if (is_expired(it->second)) return std::nullopt;
    return it->second;
  }

  std::string_view public_ip() const { return public_ip_; }

  void ensure_public_ip_fresh(std::function<void()> on_done = {}) {
    using namespace std::chrono;
    const auto now = steady_clock::now();
    if (on_done) public_ip_waiters_.push_back(std::move(on_done));
    if (!public_ip_fetch_enabled_) {
      auto w = std::move(public_ip_waiters_);
      public_ip_waiters_.clear();
      for (auto& fn : w) {
        if (fn) fn();
      }
      return;
    }
    if (public_ip_fetching_) return;
    if (!public_ip_.empty() && (now - public_ip_last_) < minutes(10)) {
      auto self = this;
      boost::asio::post(io_, [self] {
        auto w = std::move(self->public_ip_waiters_);
        self->public_ip_waiters_.clear();
        for (auto& fn : w) {
          if (fn) fn();
        }
      });
      return;
    }
    public_ip_fetching_ = true;
    common::log("public_ip: fetching from ifconfig.me");

    auto resolver = std::make_shared<tcp::resolver>(io_);
    auto sock = std::make_shared<tcp::socket>(io_);
    auto buf = std::make_shared<boost::asio::streambuf>();
    auto req = std::make_shared<std::string>(
        "GET /ip HTTP/1.1\r\n"
        "Host: ifconfig.me\r\n"
        "User-Agent: p2p-chat-rendezvous\r\n"
        "Connection: close\r\n"
        "\r\n");

    auto finish = [this, resolver, sock, buf, req](std::string ip) {
      public_ip_fetching_ = false;
      if (!ip.empty()) {
        public_ip_ = std::move(ip);
        public_ip_last_ = std::chrono::steady_clock::now();
        common::log("public_ip: " + public_ip_);
      } else if (public_ip_.empty()) {
        common::log("public_ip: unavailable");
      }
      public_ip_timer_.cancel();
      boost::system::error_code ignored;
      sock->close(ignored);
      resolver->cancel();

      auto w = std::move(public_ip_waiters_);
      public_ip_waiters_.clear();
      for (auto& fn : w) {
        if (fn) fn();
      }
    };

    public_ip_timer_.expires_after(std::chrono::seconds(3));
    public_ip_timer_.async_wait([sock](const boost::system::error_code& ec) {
      if (ec) return;
      boost::system::error_code ignored;
      sock->close(ignored);
    });

    resolver->async_resolve("ifconfig.me", "80",
                            [sock, buf, req, finish](const boost::system::error_code& ec,
                                                    tcp::resolver::results_type results) mutable {
                              if (ec) return finish({});
                              boost::asio::async_connect(
                                  *sock,
                                  results,
                                  [sock, buf, req, finish](const boost::system::error_code& ec2, const tcp::endpoint&) mutable {
                                    if (ec2) return finish({});
                                    boost::asio::async_write(
                                        *sock,
                                        boost::asio::buffer(*req),
                                        [sock, buf, finish](const boost::system::error_code& ec3, std::size_t) mutable {
                                          if (ec3) return finish({});
                                          boost::asio::async_read(
                                              *sock,
                                              *buf,
                                              boost::asio::transfer_all(),
                                              [buf, finish](const boost::system::error_code& ec4, std::size_t) mutable {
                                                // transfer_all completes with eof.
                                                if (ec4 && ec4 != boost::asio::error::eof) return finish({});
                                                std::istream is(buf.get());
                                                std::string resp((std::istreambuf_iterator<char>(is)),
                                                                 std::istreambuf_iterator<char>());
                                                auto pos = resp.find("\r\n\r\n");
                                                std::string body =
                                                    (pos == std::string::npos) ? resp : resp.substr(pos + 4);
                                                while (!body.empty() && (body.back() == '\n' || body.back() == '\r' ||
                                                                         body.back() == ' ' || body.back() == '\t')) {
                                                  body.pop_back();
                                                }
                                                while (!body.empty() && (body.front() == ' ' || body.front() == '\t' ||
                                                                         body.front() == '\r' || body.front() == '\n')) {
                                                  body.erase(body.begin());
                                                }
                                                const auto ws = body.find_first_of(" \t\r\n");
                                                if (ws != std::string::npos) body.resize(ws);
                                                boost::system::error_code ecip;
                                                (void)boost::asio::ip::make_address_v4(body, ecip);
                                                if (ecip) return finish({});
                                                finish(body);
                                              });
                                        });
                                  });
                            });
  }

  bool set_public_ip(std::string ip) {
    boost::system::error_code ec;
    (void)boost::asio::ip::make_address_v4(ip, ec);
    if (ec) return false;
    if (common::is_private_ipv4(ip)) return false;
    public_ip_ = std::move(ip);
    public_ip_last_ = std::chrono::steady_clock::now();
    common::log("public_ip: configured " + public_ip_);
    return true;
  }

  std::string best_udp_ip_for(const Registration& target, std::string_view requester_observed_ip) {
    std::string candidate = !target.udp_ip.empty() ? target.udp_ip : target.observed_ip;
    if (candidate.empty()) return candidate;

    if (!common::is_private_ipv4(candidate)) return candidate;

    // If the requester appears to be on a private network too, prefer private discovery (LAN clients).
    if (!requester_observed_ip.empty() && common::is_private_ipv4(requester_observed_ip)) return candidate;

    // Public requester; hand out server public IP as a best-effort WAN contact IP.
    ensure_public_ip_fresh();
    if (!public_ip_.empty()) return public_ip_;
    return candidate;
  }

  bool register_client(const std::shared_ptr<ClientSession>& session,
                       std::string id,
                       std::string* out_final_id,
                       std::string* out_observed_ip,
                       std::string* out_error) {
    if (!common::is_valid_id(id)) {
      *out_error = "invalid id (allowed: [A-Za-z0-9_-], length 10..128)";
      return false;
    }

    const auto remote_ep = session_remote_endpoint(session);
    const std::string raw_ip = remote_ep ? remote_ep->address().to_string() : "unknown";
    std::string observed_ip = raw_ip;
    if (common::is_private_ipv4(raw_ip)) {
      ensure_public_ip_fresh();
      // Best-effort: if we already know our public IP, advertise it for local-LAN clients.
      if (!public_ip_.empty()) observed_ip = public_ip_;
    }

    const std::string final_id = std::move(id);

    const auto now = std::chrono::steady_clock::now();

    // Cryptographic IDs are authenticated via challenge-response; allow replacing an existing
    // registration for the same ID (e.g., reconnects) even if a previous session is still alive.

    Registration reg;
    reg.id = final_id;
    reg.raw_observed_ip = raw_ip;
    reg.observed_ip = observed_ip;
    reg.udp_ip = observed_ip;
    reg.last_seen = now;
    reg.owner_tag = session->owner_tag();

    // If we already observed a UDP mapping for this ID, attach it.
    if (auto it = udp_seen_.find(final_id); it != udp_seen_.end()) {
      reg.udp_ip = it->second.ip;
      reg.udp_port = it->second.port;
    }
    regs_[final_id] = reg;

    *out_final_id = final_id;
    *out_observed_ip = observed_ip;
    common::log("register id=" + final_id + " observed_ip=" + observed_ip +
                " udp_ip=" + reg.udp_ip +
                " udp_port=" + std::to_string(reg.udp_port));
    return true;
  }

  bool touch(std::string_view id, std::string* out_error) {
    auto it = regs_.find(std::string(id));
    if (it == regs_.end() || is_expired(it->second)) {
      *out_error = "unknown or expired id";
      return false;
    }
    // If this client was observed on a private LAN address but we now know our public IP, advertise the public IP.
    if (common::is_private_ipv4(it->second.raw_observed_ip)) {
      ensure_public_ip_fresh();
      if (!public_ip_.empty()) {
        it->second.observed_ip = public_ip_;
      }
    }
    it->second.last_seen = std::chrono::steady_clock::now();
    return true;
  }

  void enqueue_friend_request(std::string from_id,
                              std::string to_id,
                              std::string* out_error) {
    if (!get_registration(from_id)) {
      *out_error = "from_id not registered";
      return;
    }
    if (!get_registration(to_id)) {
      *out_error = "to_id not registered";
      return;
    }
    FriendRequest fr;
    fr.from_id = std::move(from_id);
    fr.created_at = std::chrono::steady_clock::now();
    pending_friend_requests_[std::move(to_id)].push_back(std::move(fr));
  }

  void accept_friend(std::string from_id, std::string to_id, std::string* out_error) {
    // from_id = acceptor, to_id = original requester to notify
    if (!get_registration(from_id)) {
      *out_error = "from_id not registered";
      return;
    }
    if (!get_registration(to_id)) {
      *out_error = "to_id not registered";
      return;
    }
    pending_friend_accepts_[std::move(to_id)].push_back(std::move(from_id));
  }

  std::vector<FriendRequest> take_pending_friend_requests(std::string_view id) {
    auto it = pending_friend_requests_.find(std::string(id));
    if (it == pending_friend_requests_.end()) return {};
    auto out = std::move(it->second);
    pending_friend_requests_.erase(it);
    return out;
  }

  std::vector<std::string> take_pending_friend_accepts(std::string_view id) {
    auto it = pending_friend_accepts_.find(std::string(id));
    if (it == pending_friend_accepts_.end()) return {};
    auto out = std::move(it->second);
    pending_friend_accepts_.erase(it);
    return out;
  }

  void cleanup_expired() {
    const auto now = std::chrono::steady_clock::now();
    std::vector<std::string> to_erase;
    for (const auto& [id, reg] : regs_) {
      if (now - reg.last_seen > kTtl) to_erase.push_back(id);
    }
    for (const auto& id : to_erase) {
      regs_.erase(id);
      pending_friend_requests_.erase(id);
      pending_friend_accepts_.erase(id);
      common::log("expired id=" + id);
    }

    std::vector<std::string> udp_erase;
    for (const auto& [id, seen] : udp_seen_) {
      if (now - seen.last_seen > kTtl) udp_erase.push_back(id);
    }
    for (const auto& id : udp_erase) udp_seen_.erase(id);
  }

 private:
  friend class ClientSession;

  void do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
      if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
          common::log(std::string("accept error: ") + ec.message());
        }
        return;
      }
      auto session = std::make_shared<ClientSession>(*this, std::move(socket));
      session->start();
      do_accept();
    });
  }

  void schedule_cleanup() {
    cleanup_timer_.expires_after(kCleanupInterval);
    cleanup_timer_.async_wait([this](const boost::system::error_code& ec) {
      if (ec) return;
      cleanup_expired();
      schedule_cleanup();
    });
  }

  bool is_expired(const Registration& reg) const {
    return std::chrono::steady_clock::now() - reg.last_seen > kTtl;
  }

  std::optional<tcp::endpoint> session_remote_endpoint(const std::shared_ptr<ClientSession>& session) {
    boost::system::error_code ec;
    auto ep = session->socket_.remote_endpoint(ec);
    if (ec) return std::nullopt;
    return ep;
  }

  boost::asio::io_context& io_;
  tcp::acceptor acceptor_;
  udp::socket udp_socket_;
  boost::asio::steady_timer cleanup_timer_;
  boost::asio::steady_timer public_ip_timer_;
  std::string public_ip_;
  std::chrono::steady_clock::time_point public_ip_last_{};
  bool public_ip_fetching_ = false;
  std::vector<std::function<void()>> public_ip_waiters_;
  bool public_ip_fetch_enabled_ = true;

  struct UdpSeen {
    std::string ip;
    uint16_t port = 0;
    std::chrono::steady_clock::time_point last_seen{};
  };
  std::unordered_map<std::string, UdpSeen> udp_seen_;

  std::unordered_map<std::string, Registration> regs_;
  std::unordered_map<std::string, std::vector<FriendRequest>> pending_friend_requests_;
  std::unordered_map<std::string, std::vector<std::string>> pending_friend_accepts_;

  void udp_read_loop() {
    auto buf = std::make_shared<std::array<uint8_t, common::kMaxFrameSize + 4>>();
    auto remote = std::make_shared<udp::endpoint>();
    udp_socket_.async_receive_from(
        boost::asio::buffer(*buf),
        *remote,
        [this, buf, remote](const boost::system::error_code& ec, std::size_t n) {
          if (ec) return;
          if (n == 0) return udp_read_loop();

          const auto jopt = common::parse_framed_json_bytes(std::span<const uint8_t>(buf->data(), n));
          if (!jopt) return udp_read_loop();
          const json& j = *jopt;
          if (!j.contains("type") || !j["type"].is_string()) return udp_read_loop();
          const std::string type = j["type"].get<std::string>();

          if (type == "udp_announce") {
            if (!j.contains("id") || !j["id"].is_string()) return udp_read_loop();
            if (!j.contains("ts") || !j["ts"].is_number_integer()) return udp_read_loop();
            if (!j.contains("sig") || !j["sig"].is_string()) return udp_read_loop();
            const std::string id = j["id"].get<std::string>();
            const auto ts = j["ts"].get<long long>();
            if (!common::is_valid_id(id)) return udp_read_loop();

            const std::string msg = "p2p-chat-udp-announce|" + id + "|" + std::to_string(ts);
            const bool ok = common::ed25519_verify_bytes_b64url(
                id,
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()), msg.size()),
                j["sig"].get<std::string>());
            if (!ok) return udp_read_loop();

            UdpSeen seen;
            seen.ip = remote->address().to_string();
            seen.port = remote->port();
            seen.last_seen = std::chrono::steady_clock::now();
            if (common::is_private_ipv4(seen.ip)) ensure_public_ip_fresh();
            {
              const auto it_prev = udp_seen_.find(id);
              const bool first = (it_prev == udp_seen_.end());
              const bool changed = !first && (it_prev->second.ip != seen.ip || it_prev->second.port != seen.port);
              if (first || changed) {
                common::log("udp_announce id=" + id + " from " + seen.ip + ":" + std::to_string(seen.port));
              }
            }
            udp_seen_[id] = seen;
            if (auto it = regs_.find(id); it != regs_.end()) {
              it->second.udp_ip = seen.ip;
              it->second.udp_port = seen.port;
              it->second.last_seen = std::chrono::steady_clock::now();
            }

            // Best-effort ack so clients can warn when UDP to rendezvous is blocked.
            json okj;
            okj["type"] = "udp_announce_ok";
            if (auto framed = common::frame_json_bytes(okj)) {
              auto out = std::make_shared<std::vector<uint8_t>>(std::move(*framed));
              udp_socket_.async_send_to(boost::asio::buffer(*out), *remote,
                                        [out](const boost::system::error_code&, std::size_t) {});
            }
          }

          udp_read_loop();
        });
  }
};

ClientSession::ClientSession(RendezvousServer& server, tcp::socket socket)
    : server_(server), socket_(std::move(socket)) {
  writer_ = std::make_shared<common::JsonWriteQueue<tcp::socket>>(socket_);
}

void ClientSession::start() {
  boost::system::error_code ec;
  const auto ep = socket_.remote_endpoint(ec);
  observed_ip_ = ec ? "unknown" : ep.address().to_string();
  common::log("client connected from " + (ec ? std::string("unknown") : common::endpoint_to_string(ep)));
  do_read();
}

void ClientSession::stop() {
  if (stopped_) return;
  stopped_ = true;
  boost::system::error_code ignored;
  socket_.shutdown(tcp::socket::shutdown_both, ignored);
  socket_.close(ignored);
}

void ClientSession::send_error(std::string_view message) {
  json j;
  j["type"] = "error";
  j["message"] = std::string(message);
  send(std::move(j));
}

void ClientSession::do_read() {
  auto self = shared_from_this();
  common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json msg) {
    if (ec) {
      if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::eof) {
        common::log(std::string("client read error: ") + ec.message());
      }
      self->stop();
      return;
    }
    self->handle_message(msg);
    self->do_read();
  });
}

void ClientSession::handle_message(const json& msg) {
  const auto type_it = msg.find("type");
  if (type_it == msg.end() || !type_it->is_string()) {
    send_error("missing/invalid field: type");
    return;
  }
  const std::string type = *type_it;

  if (type == "register_init") {
    if (!msg.contains("id") || !msg["id"].is_string()) {
      send_error("missing/invalid field: id");
      return;
    }
    const std::string id = msg["id"].get<std::string>();
    if (!common::is_valid_id(id)) {
      send_error("invalid id format");
      return;
    }
    PendingAuth pa;
    pa.id = id;
    pa.challenge_b64url = random_challenge_b64url(32);
    pending_auth_ = pa;

    json resp;
    resp["type"] = "register_challenge";
    resp["id"] = id;
    resp["challenge"] = pa.challenge_b64url;
    send(std::move(resp));
    return;
  }

  if (type == "register_finish") {
    if (!pending_auth_) {
      send_error("no pending register_init");
      return;
    }
    if (!msg.contains("id") || !msg["id"].is_string()) {
      send_error("missing/invalid field: id");
      return;
    }
    if (!msg.contains("signature") || !msg["signature"].is_string()) {
      send_error("missing/invalid field: signature");
      return;
    }
    const std::string id = msg["id"].get<std::string>();
    const std::string sig = msg["signature"].get<std::string>();
    if (id != pending_auth_->id) {
      send_error("id mismatch");
      return;
    }

    const auto ch = common::base64url_decode(pending_auth_->challenge_b64url);
    const bool auth_ok = ch && common::ed25519_verify_bytes_b64url(id, *ch, sig);
    if (!auth_ok) {
      send_error("signature verification failed");
      return;
    }

    // Commit registration after challenge verification.
    auto self = shared_from_this();
    const auto pa = *pending_auth_;
    pending_auth_.reset();

    auto do_register = [self, pa]() mutable {
      std::string final_id;
      std::string observed_ip;
      std::string err;

      const bool ok = self->server_.register_client(self,
                                                    pa.id,
                                                    &final_id,
                                                    &observed_ip,
                                                    &err);
      if (!ok) {
        self->send_error(err);
        return;
      }
      self->id_ = final_id;
      self->send_register_ok();
    };

    if (common::is_private_ipv4(observed_ip_) && self->server_.public_ip().empty()) {
      // Try to learn the server's public IP before finalizing registration so observed_ip can be rewritten.
      self->server_.ensure_public_ip_fresh(std::move(do_register));
    } else {
      do_register();
    }
    return;
  }

  if (type == "heartbeat") {
    if (!msg.contains("id") || !msg["id"].is_string()) {
      send_error("missing/invalid field: id");
      return;
    }
    const std::string id = msg["id"].get<std::string>();
    if (!id_.empty() && id != id_) {
      send_error("id mismatch for this connection");
      return;
    }
    std::string err;
    if (!server_.touch(id, &err)) {
      send_error(err);
      return;
    }
    return;
  }

  if (type == "lookup") {
    if (!msg.contains("target_id") || !msg["target_id"].is_string()) {
      send_error("missing/invalid field: target_id");
      return;
    }
    const std::string target_id = msg["target_id"].get<std::string>();

    const auto reg = server_.get_registration(target_id);
    json resp;
    resp["type"] = "lookup_result";
    resp["target_id"] = target_id;
    if (!reg) {
      resp["ok"] = false;
      resp["ip"] = "";
      resp["udp_port"] = 0;
      resp["udp_ip"] = "";
    } else {
      resp["ok"] = true;
      resp["ip"] = reg->observed_ip;
      resp["udp_port"] = reg->udp_port;
      resp["udp_ip"] = server_.best_udp_ip_for(*reg, observed_ip_);
    }
    common::log("lookup target_id=" + target_id + " ok=" +
                std::string(resp["ok"].get<bool>() ? "true" : "false"));
    send(std::move(resp));
    return;
  }

  if (type == "friend_request") {
    if (!msg.contains("from_id") || !msg["from_id"].is_string() || !msg.contains("to_id") ||
        !msg["to_id"].is_string()) {
      send_error("missing/invalid fields: from_id/to_id");
      return;
    }
    const std::string from_id = msg["from_id"].get<std::string>();
    const std::string to_id = msg["to_id"].get<std::string>();
    if (!id_.empty() && from_id != id_) {
      send_error("from_id mismatch for this connection");
      return;
    }
    std::string err;
    server_.enqueue_friend_request(from_id, to_id, &err);
    if (!err.empty()) {
      send_error(err);
      return;
    }
    common::log("friend_request from_id=" + from_id + " to_id=" + to_id);
    return;
  }

  if (type == "friend_accept") {
    if (!msg.contains("from_id") || !msg["from_id"].is_string() || !msg.contains("to_id") ||
        !msg["to_id"].is_string()) {
      send_error("missing/invalid fields: from_id/to_id");
      return;
    }
    const std::string from_id = msg["from_id"].get<std::string>(); // acceptor
    const std::string to_id = msg["to_id"].get<std::string>();     // original requester
    if (!id_.empty() && from_id != id_) {
      send_error("from_id mismatch for this connection");
      return;
    }
    std::string err;
    server_.accept_friend(from_id, to_id, &err);
    if (!err.empty()) {
      send_error(err);
      return;
    }
    common::log("friend_accept from_id=" + from_id + " to_id=" + to_id);
    return;
  }

  if (type == "poll") {
    if (!msg.contains("id") || !msg["id"].is_string()) {
      send_error("missing/invalid field: id");
      return;
    }
    const std::string id = msg["id"].get<std::string>();
    if (!id_.empty() && id != id_) {
      send_error("id mismatch for this connection");
      return;
    }
    std::string err;
    // Touch for TTL purposes if registered.
    if (!server_.touch(id, &err)) {
      send_error(err);
      return;
    }

    auto friend_reqs = server_.take_pending_friend_requests(id);
    auto friend_accepts = server_.take_pending_friend_accepts(id);
    json resp;
    resp["type"] = "poll_result";
    resp["friend_requests"] = json::array();
    for (const auto& fr : friend_reqs) {
      json jf;
      jf["from_id"] = fr.from_id;
      resp["friend_requests"].push_back(std::move(jf));
    }
    resp["friend_accepts"] = json::array();
    for (const auto& accepter : friend_accepts) {
      json ja;
      ja["from_id"] = accepter;
      resp["friend_accepts"].push_back(std::move(ja));
    }
    send(std::move(resp));
    return;
  }

  send_error("unknown message type");
}

void ClientSession::send_register_ok() {
  const auto reg = server_.get_registration(id_);
  if (!reg) return;
  json resp;
  resp["type"] = "register_ok";
  resp["id"] = reg->id;
  resp["observed_ip"] = reg->observed_ip;
  resp["udp_ip"] = reg->udp_ip;
  resp["udp_port"] = reg->udp_port;
  send(std::move(resp));
}

} // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <bind_ip> <port> [--public-ip <ip>] [--no-public-ip-fetch]\n";
    std::cerr << "Example: " << argv[0] << " 0.0.0.0 5555\n";
    return 2;
  }

  const std::string bind_ip = argv[1];
  const int port_i = std::stoi(argv[2]);
  if (port_i <= 0 || port_i > 65535) {
    std::cerr << "Invalid port\n";
    return 2;
  }

  std::string public_ip_override;
  bool no_public_ip_fetch = false;
  for (int i = 3; i < argc; ++i) {
    const std::string a = argv[i];
    auto need_val = [&](const char* flag) -> std::optional<std::string> {
      if (a != flag) return std::nullopt;
      if (i + 1 >= argc) return std::nullopt;
      return std::string(argv[++i]);
    };
    if (auto v = need_val("--public-ip")) {
      public_ip_override = *v;
      continue;
    }
    if (a == "--no-public-ip-fetch") {
      no_public_ip_fetch = true;
      continue;
    }
    if (a == "--help" || a == "-h") {
      std::cout << "Usage: " << argv[0] << " <bind_ip> <port> [--public-ip <ip>] [--no-public-ip-fetch]\n";
      return 0;
    }
    std::cerr << "Unknown arg: " << a << "\n";
    return 2;
  }

  boost::asio::io_context io;
  RendezvousServer server(io);
  if (no_public_ip_fetch) server.set_public_ip_fetch_enabled(false);
  if (!public_ip_override.empty()) {
    if (!server.set_public_ip(public_ip_override)) {
      std::cerr << "Invalid --public-ip (must be a public IPv4 address)\n";
      return 2;
    }
  }

  boost::asio::signal_set signals(io, SIGINT, SIGTERM);
  signals.async_wait([&](const boost::system::error_code&, int) {
    common::log("signal received, shutting down");
    server.stop();
    io.stop();
  });

  boost::system::error_code ec;
  auto addr = boost::asio::ip::make_address(bind_ip, ec);
  if (ec) {
    std::cerr << "Invalid bind address: " << ec.message() << "\n";
    return 2;
  }

  server.listen(tcp::endpoint(addr, static_cast<uint16_t>(port_i)));
  io.run();
  return 0;
}
