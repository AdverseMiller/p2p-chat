#include "common/framing.hpp"
#include "common/util.hpp"

#include <boost/asio.hpp>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

using boost::asio::ip::tcp;
using common::json;

namespace {

constexpr auto kTtl = std::chrono::seconds(60);
constexpr auto kCleanupInterval = std::chrono::seconds(5);

struct ConnectRequest {
  std::string from_id;
  std::string ip;
  uint16_t port = 0;
  bool reachable = true;
};

struct FriendRequest {
  std::string from_id;
  std::string intro;
  std::chrono::steady_clock::time_point created_at{};
};

struct Registration {
  std::string id;
  std::string observed_ip;
  uint16_t external_port = 0;
  bool reachable = false;
  std::chrono::steady_clock::time_point last_seen{};
  std::weak_ptr<void> owner_tag;
};

bool ed25519_verify_b64url(std::string_view pubkey_b64url,
                           std::string_view msg_b64url,
                           std::string_view sig_b64url) {
  const auto pub = common::base64url_decode(pubkey_b64url);
  const auto msg = common::base64url_decode(msg_b64url);
  const auto sig = common::base64url_decode(sig_b64url);
  if (!pub || !msg || !sig) return false;
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
    const int rc = EVP_DigestVerify(ctx, sig->data(), sig->size(), msg->data(), msg->size());
    ok = (rc == 1);
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

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
    uint16_t listen_port = 0;
    uint16_t external_port_hint = 0;
    std::string challenge_b64url;
  };
  std::optional<PendingAuth> pending_auth_;
  uint16_t listen_port_ = 0;
};

class RendezvousServer {
 public:
  explicit RendezvousServer(boost::asio::io_context& io)
      : io_(io), acceptor_(io), cleanup_timer_(io) {}

  void listen(const tcp::endpoint& ep) {
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
    common::log(std::string("rendezvous_server listening on ") + common::endpoint_to_string(ep));
    do_accept();
    schedule_cleanup();
  }

  void stop() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
    cleanup_timer_.cancel();
  }

  std::optional<Registration> get_registration(std::string_view id) {
    auto it = regs_.find(std::string(id));
    if (it == regs_.end()) return std::nullopt;
    if (is_expired(it->second)) return std::nullopt;
    return it->second;
  }

  bool register_client(const std::shared_ptr<ClientSession>& session,
                       std::string id,
                       uint16_t listen_port,
                       uint16_t external_port,
                       bool reachable,
                       std::string* out_final_id,
                       std::string* out_observed_ip,
                       bool* out_reachable,
                       uint16_t* out_external_port,
                       std::string* out_error) {
    if (listen_port == 0) {
      *out_error = "listen_port must be 1..65535";
      return false;
    }
    if (!common::is_valid_id(id)) {
      *out_error = "invalid id (allowed: [A-Za-z0-9_-], length 10..128)";
      return false;
    }

    const auto remote_ep = session_remote_endpoint(session);
    const std::string observed_ip = remote_ep ? remote_ep->address().to_string() : "unknown";

    const std::string final_id = std::move(id);

    const auto now = std::chrono::steady_clock::now();

    // Cryptographic IDs are authenticated via challenge-response; allow replacing an existing
    // registration for the same ID (e.g., reconnects) even if a previous session is still alive.

    Registration reg;
    reg.id = final_id;
    reg.observed_ip = observed_ip;
    reg.external_port = reachable ? external_port : 0;
    reg.reachable = reachable;
    reg.last_seen = now;
    reg.owner_tag = session->owner_tag();
    regs_[final_id] = reg;

    *out_final_id = final_id;
    *out_observed_ip = observed_ip;
    *out_reachable = reachable;
    *out_external_port = reg.external_port;

    common::log("register id=" + final_id + " observed_ip=" + observed_ip +
                " reachable=" + std::string(reachable ? "true" : "false") +
                " external_port=" + std::to_string(reg.external_port));
    (void)listen_port; // reserved for future (might be useful for diagnostics)
    return true;
  }

  using ProbeCallback = std::function<void(bool reachable)>;

  void probe_reachability(std::string id,
                          std::string observed_ip,
                          uint16_t external_port_hint,
                          ProbeCallback cb) {
    if (external_port_hint == 0) return cb(false);

    auto sock = std::make_shared<tcp::socket>(io_);
    auto timer = std::make_shared<boost::asio::steady_timer>(io_);
    timer->expires_after(std::chrono::seconds(2));

    auto challenge = std::make_shared<std::string>(random_challenge_b64url(32));
    timer->async_wait([sock, cb](const boost::system::error_code& ec) {
      if (ec) return;
      boost::system::error_code ignored;
      sock->close(ignored);
      cb(false);
    });

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(observed_ip, ec);
    if (ec) return cb(false);
    tcp::endpoint ep(addr, external_port_hint);

    sock->async_connect(ep, [sock, timer, id = std::move(id), challenge, cb = std::move(cb)](
                                const boost::system::error_code& ec2) mutable {
      if (ec2) {
        timer->cancel();
        return cb(false);
      }

      json p;
      p["type"] = "probe";
      p["challenge"] = *challenge;

      common::async_write_json(*sock, p, [sock, timer, id, challenge, cb = std::move(cb)](
                                         const boost::system::error_code& ecw) mutable {
        if (ecw) {
          timer->cancel();
          return cb(false);
        }
        common::async_read_json(*sock, common::kMaxFrameSize, [timer, id, challenge, cb = std::move(cb)](
                                                               const boost::system::error_code& ecr,
                                                               json resp) mutable {
          timer->cancel();
          if (ecr) return cb(false);
          if (!resp.contains("type") || !resp["type"].is_string()) return cb(false);
          if (resp["type"].get<std::string>() != "probe_ok") return cb(false);
          if (!resp.contains("id") || !resp["id"].is_string()) return cb(false);
          if (!resp.contains("signature") || !resp["signature"].is_string()) return cb(false);
          const std::string rid = resp["id"].get<std::string>();
          if (rid != id) return cb(false);
          const std::string sig = resp["signature"].get<std::string>();
          const bool ok = ed25519_verify_b64url(id, *challenge, sig);
          cb(ok);
        });
      });
    });
  }

  bool touch(std::string_view id, std::string* out_error) {
    auto it = regs_.find(std::string(id));
    if (it == regs_.end() || is_expired(it->second)) {
      *out_error = "unknown or expired id";
      return false;
    }
    it->second.last_seen = std::chrono::steady_clock::now();
    return true;
  }

  void enqueue_connect_request(std::string from_id, std::string to_id, std::string* out_error) {
    const auto from = get_registration(from_id);
    const auto to = get_registration(to_id);

    if (!from) {
      *out_error = "from_id not registered";
      return;
    }
    if (!from->reachable || from->external_port == 0) {
      *out_error = "from_id must be reachable to request outbound connect";
      return;
    }
    if (!to) {
      *out_error = "to_id not registered";
      return;
    }

    ConnectRequest req;
    req.from_id = std::move(from_id);
    req.ip = from->observed_ip;
    req.port = from->external_port;
    req.reachable = true;
    pending_[std::move(to_id)].push_back(std::move(req));
  }

  void enqueue_friend_request(std::string from_id,
                              std::string to_id,
                              std::string intro,
                              std::string* out_error) {
    if (!get_registration(from_id)) {
      *out_error = "from_id not registered";
      return;
    }
    if (!get_registration(to_id)) {
      *out_error = "to_id not registered";
      return;
    }
    if (intro.size() > 256) {
      *out_error = "intro too long (max 256)";
      return;
    }
    FriendRequest fr;
    fr.from_id = std::move(from_id);
    fr.intro = std::move(intro);
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

  std::vector<ConnectRequest> take_pending_requests(std::string_view id, std::string* out_error) {
    auto it = pending_.find(std::string(id));
    if (it == pending_.end()) return {};

    std::vector<ConnectRequest> out;
    out.reserve(it->second.size());

    for (auto& req : it->second) {
      const auto from = get_registration(req.from_id);
      if (!from || !from->reachable || from->external_port == 0) continue;
      ConnectRequest live;
      live.from_id = from->id;
      live.ip = from->observed_ip;
      live.port = from->external_port;
      live.reachable = true;
      out.push_back(std::move(live));
    }

    pending_.erase(it);
    (void)out_error;
    return out;
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
      pending_.erase(id);
      pending_friend_requests_.erase(id);
      pending_friend_accepts_.erase(id);
      common::log("expired id=" + id);
    }
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
  boost::asio::steady_timer cleanup_timer_;

  std::unordered_map<std::string, Registration> regs_;
  std::unordered_map<std::string, std::vector<ConnectRequest>> pending_;
  std::unordered_map<std::string, std::vector<FriendRequest>> pending_friend_requests_;
  std::unordered_map<std::string, std::vector<std::string>> pending_friend_accepts_;
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
    if (!msg.contains("listen_port") || !msg["listen_port"].is_number_integer()) {
      send_error("missing/invalid field: listen_port");
      return;
    }
    const int lp = msg["listen_port"].get<int>();
    if (lp <= 0 || lp > 65535) {
      send_error("listen_port must be 1..65535");
      return;
    }
    if (!msg.contains("external_port_hint") || !msg["external_port_hint"].is_number_integer()) {
      send_error("missing/invalid field: external_port_hint");
      return;
    }
    const int eph = msg["external_port_hint"].get<int>();
    if (eph <= 0 || eph > 65535) {
      send_error("external_port_hint must be 1..65535");
      return;
    }

    PendingAuth pa;
    pa.id = id;
    pa.listen_port = static_cast<uint16_t>(lp);
    pa.external_port_hint = static_cast<uint16_t>(eph);
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

    const bool auth_ok = ed25519_verify_b64url(id, pending_auth_->challenge_b64url, sig);
    if (!auth_ok) {
      send_error("signature verification failed");
      return;
    }

    // Run reachability probe; only then commit registration and respond register_ok.
    auto self = shared_from_this();
    const auto pa = *pending_auth_;
    pending_auth_.reset();
    server_.probe_reachability(pa.id, observed_ip_, pa.external_port_hint, [self, pa](bool reachable) mutable {
      std::string final_id;
      std::string observed_ip;
      bool out_reachable = false;
      uint16_t out_ext_port = 0;
      std::string err;

      const bool ok = self->server_.register_client(self,
                                                    pa.id,
                                                    pa.listen_port,
                                                    pa.external_port_hint,
                                                    reachable,
                                                    &final_id,
                                                    &observed_ip,
                                                    &out_reachable,
                                                    &out_ext_port,
                                                    &err);
      if (!ok) {
        self->send_error(err);
        return;
      }
      self->id_ = final_id;
      self->listen_port_ = pa.listen_port;
      self->send_register_ok();
    });
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
      resp["port"] = 0;
      resp["reachable"] = false;
    } else {
      resp["ok"] = true;
      resp["ip"] = reg->observed_ip;
      resp["reachable"] = reg->reachable;
      resp["port"] = reg->reachable ? reg->external_port : 0;
    }
    common::log("lookup target_id=" + target_id + " ok=" +
                std::string(resp["ok"].get<bool>() ? "true" : "false"));
    send(std::move(resp));
    return;
  }

  if (type == "connect_request") {
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
    server_.enqueue_connect_request(from_id, to_id, &err);
    if (!err.empty()) {
      send_error(err);
      return;
    }
    common::log("connect_request from_id=" + from_id + " to_id=" + to_id);
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
    std::string intro;
    if (msg.contains("intro") && msg["intro"].is_string()) intro = msg["intro"].get<std::string>();
    std::string err;
    server_.enqueue_friend_request(from_id, to_id, std::move(intro), &err);
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

    auto connect_reqs = server_.take_pending_requests(id, &err);
    auto friend_reqs = server_.take_pending_friend_requests(id);
    auto friend_accepts = server_.take_pending_friend_accepts(id);
    json resp;
    resp["type"] = "poll_result";
    resp["connect_requests"] = json::array();
    for (const auto& r : connect_reqs) {
      json jr;
      jr["from_id"] = r.from_id;
      jr["ip"] = r.ip;
      jr["port"] = r.port;
      jr["reachable"] = r.reachable;
      resp["connect_requests"].push_back(std::move(jr));
    }
    resp["friend_requests"] = json::array();
    for (const auto& fr : friend_reqs) {
      json jf;
      jf["from_id"] = fr.from_id;
      jf["intro"] = fr.intro;
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
  resp["reachable"] = reg->reachable;
  resp["external_port"] = reg->external_port;
  send(std::move(resp));
}

} // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <bind_ip> <port>\n";
    std::cerr << "Example: " << argv[0] << " 0.0.0.0 5555\n";
    return 2;
  }

  const std::string bind_ip = argv[1];
  const int port_i = std::stoi(argv[2]);
  if (port_i <= 0 || port_i > 65535) {
    std::cerr << "Invalid port\n";
    return 2;
  }

  boost::asio::io_context io;
  RendezvousServer server(io);

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
