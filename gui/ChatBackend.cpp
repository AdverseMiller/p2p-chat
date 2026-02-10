#include "gui/ChatBackend.hpp"

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
  using OnChat = std::function<void(const std::string& peer_id, const std::string& peer_name, const std::string& text)>;
  using OnClosed = std::function<void()>;

  PeerSession(tcp::socket socket,
              Role role,
              std::string self_id,
              std::function<std::string()> get_self_name,
              std::function<bool(const std::string&)> allow_peer)
      : socket_(std::move(socket)),
        role_(role),
        self_id_(std::move(self_id)),
        get_self_name_(std::move(get_self_name)),
        allow_peer_(std::move(allow_peer)),
        writer_(std::make_shared<common::JsonWriteQueue<tcp::socket>>(socket_)) {}

  void start(OnReady on_ready, OnChat on_chat, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    if (role_ == Role::Initiator) {
      json hello;
      hello["type"] = "hello";
      hello["id"] = self_id_;
      const auto nm = get_self_name_ ? get_self_name_() : std::string();
      if (!nm.empty()) hello["name"] = nm;
      writer_->send(std::move(hello));
      wait_for_hello_ack();
    } else {
      wait_for_hello();
    }
  }

  void start_accept_with_hello(json hello, OnReady on_ready, OnChat on_chat, OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_chat_ = std::move(on_chat);
    on_closed_ = std::move(on_closed);
    if (!hello.contains("id") || !hello["id"].is_string()) return send_error_and_close("hello missing id");
    peer_id_ = hello["id"].get<std::string>();
    if (!common::is_valid_id(peer_id_)) return send_error_and_close("invalid peer id");
    if (allow_peer_ && !allow_peer_(peer_id_)) return send_error_and_close("not friends");
    if (hello.contains("name") && hello["name"].is_string()) peer_name_ = hello["name"].get<std::string>();
    send_hello_ack_and_ready();
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
  std::string_view peer_name() const { return peer_name_; }

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
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "hello") {
        return self->send_error_and_close("expected hello");
      }
      self->start_accept_with_hello(std::move(j), self->on_ready_, self->on_chat_, self->on_closed_);
    });
  }

  void wait_for_hello_ack() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "hello_ack") {
        return self->send_error_and_close("expected hello_ack");
      }
      if (!j.contains("id") || !j["id"].is_string()) return self->send_error_and_close("hello_ack missing id");
      self->peer_id_ = j["id"].get<std::string>();
      if (!common::is_valid_id(self->peer_id_)) return self->send_error_and_close("invalid peer id");
      if (j.contains("name") && j["name"].is_string()) self->peer_name_ = j["name"].get<std::string>();
      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      self->read_loop();
    });
  }

  void send_hello_ack_and_ready() {
    json ack;
    ack["type"] = "hello_ack";
    ack["id"] = self_id_;
    const auto nm = get_self_name_ ? get_self_name_() : std::string();
    if (!nm.empty()) ack["name"] = nm;
    writer_->send(std::move(ack));
    ready_ = true;
    if (on_ready_) on_ready_(peer_id_, peer_name_);
  }

  void read_loop() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (j.contains("type") && j["type"].is_string() && j["type"].get<std::string>() == "chat") {
        if (j.contains("text") && j["text"].is_string()) {
          const std::string text = j["text"].get<std::string>();
          if (self->on_chat_) self->on_chat_(self->peer_id_, self->peer_name_, text);
        }
      }
      self->read_loop();
    });
  }

  tcp::socket socket_;
  Role role_;
  std::string self_id_;
  std::function<std::string()> get_self_name_;
  std::string peer_id_;
  std::string peer_name_;
  std::function<bool(const std::string&)> allow_peer_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;
  bool ready_ = false;
  bool closed_ = false;
  OnReady on_ready_;
  OnChat on_chat_;
  OnClosed on_closed_;
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
        poll_timer_(io) {}

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
                              if (ec) return self->stop();
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

  std::string_view id() const { return id_; }
  bool reachable() const { return reachable_; }
  uint16_t external_port() const { return external_port_; }
  std::string_view observed_ip() const { return observed_ip_; }

  void enable_polling(bool enabled) {
    polling_enabled_ = enabled;
    if (polling_enabled_) schedule_poll();
  }

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
    j["from_id"] = id_;
    j["to_id"] = requester_id;
    writer_->send(std::move(j));
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
      self->stop();
    });

    boost::asio::async_connect(socket_, results,
                               [self, timer](const boost::system::error_code& ec, const tcp::endpoint&) {
                                 timer->cancel();
                                 if (ec) return self->stop();
                                 self->writer_ = std::make_shared<common::JsonWriteQueue<tcp::socket>>(self->socket_);
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
      if (ec) return self->stop();
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
        startPeerAcceptWithHello(std::move(*sock), std::move(j));
        return;
      }
    });
  }

  void startPeerAcceptWithHello(tcp::socket socket, json hello) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    active_peer = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Acceptor, std::move(selfId),
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); });

    active_peer->start_accept_with_hello(
        std::move(hello),
        [this](const std::string& peer_id, const std::string& peer_name) {
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
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

  void connectToPeer(const std::string& peer_id, const std::string& ip, uint16_t port) {
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

    sock->async_connect(ep, [this, sock, timer, peer_id](const boost::system::error_code& ec2) {
      timer->cancel();
      if (ec2) {
        postToQt([this, peer_id] {
          emit q->deliveryError(QString::fromStdString(peer_id), "connect failed");
        });
        return;
      }
      startPeerInitiator(std::move(*sock));
    });
  }

  void startPeerInitiator(tcp::socket socket) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    active_peer = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Initiator, std::move(selfId),
        [this] { return getSelfName(); }, [this](const std::string& pid) { return isAccepted(pid); });

    active_peer->start(
        [this](const std::string& peer_id, const std::string& peer_name) {
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
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

  void attemptDelivery(const std::string& peer_id) {
    if (!rendezvous) return;
    if (active_peer) return;
    if (!isAccepted(peer_id)) return;

    rendezvous->send_lookup(peer_id, [this](RendezvousClient::LookupResult r) {
      if (!r.ok) {
        postToQt([this, tid = r.target_id] {
          emit q->deliveryError(QString::fromStdString(tid), "lookup failed (offline?)");
        });
        return;
      }
      if (r.reachable && r.port != 0) {
        connectToPeer(r.target_id, r.ip, r.port);
        return;
      }
      if (rendezvous->reachable()) {
        rendezvous->send_connect_request(r.target_id);
        return;
      }
      postToQt([this, tid = r.target_id] {
        emit q->deliveryError(QString::fromStdString(tid), "both unreachable; cannot connect");
      });
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
        impl_->connectToPeer(req.from_id, req.ip, req.port);
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
  std::lock_guard lk(impl_->m);
  impl_->self_name = name.toStdString();
}

void ChatBackend::setFriendAccepted(const QString& peerId, bool accepted) {
  impl_->setAccepted(peerId.toStdString(), accepted);
}

void ChatBackend::sendFriendRequest(const QString& peerId, const QString& intro) {
  if (!impl_->rendezvous) return;
  impl_->rendezvous->send_friend_request(peerId.toStdString(), intro.toStdString());
}

void ChatBackend::acceptFriend(const QString& peerId) {
  if (!impl_->rendezvous) return;
  impl_->setAccepted(peerId.toStdString(), true);
  impl_->rendezvous->send_friend_accept(peerId.toStdString());
}

void ChatBackend::sendMessage(const QString& peerId, const QString& text) {
  const auto pid = peerId.toStdString();
  if (!impl_->rendezvous) return;
  if (!impl_->isAccepted(pid)) {
    emit deliveryError(peerId, "not friends");
    return;
  }

  if (impl_->active_peer && std::string(impl_->active_peer->peer_id()) == pid) {
    impl_->active_peer->send_chat(text.toStdString());
    emit messageReceived(peerId, peerId, text, false);
    return;
  }

  impl_->queueOutgoing(pid, text.toStdString());
  impl_->attemptDelivery(pid);
  emit messageReceived(peerId, peerId, text, false);
}

