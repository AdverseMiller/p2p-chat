#include "gui/ChatBackend.hpp"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QTimer>

#include <atomic>
#include <iostream>

namespace {
struct HostPort {
  QString host;
  quint16 port = 0;
};

std::optional<HostPort> parseHostPort(const QString& s) {
  const auto trimmed = s.trimmed();
  const auto idx = trimmed.lastIndexOf(':');
  if (idx <= 0 || idx + 1 >= trimmed.size()) return std::nullopt;
  bool ok = false;
  const int port_i = trimmed.mid(idx + 1).toInt(&ok);
  if (!ok || port_i <= 0 || port_i > 65535) return std::nullopt;
  return HostPort{trimmed.left(idx), static_cast<quint16>(port_i)};
}

QString mkTempDir(const QString& name) {
  const auto base = QDir::temp().filePath(name);
  QDir().mkpath(base);
  return base;
}
} // namespace

int main(int argc, char** argv) {
  QCoreApplication app(argc, argv);

  QString server = "127.0.0.1:5555";
  int timeoutMs = 20000;
  for (int i = 1; i < argc; ++i) {
    const QString a = argv[i];
    auto needVal = [&](const char* flag) -> std::optional<QString> {
      if (a != flag) return std::nullopt;
      if (i + 1 >= argc) return std::nullopt;
      return QString::fromUtf8(argv[++i]);
    };
    if (auto v = needVal("--server")) {
      server = *v;
      continue;
    }
    if (auto v = needVal("--timeout-ms")) {
      bool ok = false;
      timeoutMs = v->toInt(&ok);
      if (!ok || timeoutMs < 1000) timeoutMs = 20000;
      continue;
    }
    if (a == "--help") {
      std::cout << "Usage: udp_smoke [--server host:port] [--timeout-ms N]\n";
      return 0;
    }
  }

  const auto hp = parseHostPort(server);
  if (!hp) {
    std::cerr << "invalid --server\n";
    return 2;
  }

  const auto dirA = mkTempDir("p2p-chat-smoke-A");
  const auto dirB = mkTempDir("p2p-chat-smoke-B");

  ChatBackend a;
  ChatBackend b;

  ChatBackend::Options oa;
  oa.serverHost = hp->host;
  oa.serverPort = hp->port;
  oa.keyPath = QDir(dirA).filePath("identity.pem");
  oa.selfName = "smokeA";
  oa.listenPort = 41001;
  oa.noUpnp = true;
  oa.externalPort = oa.listenPort;

  ChatBackend::Options ob;
  ob.serverHost = hp->host;
  ob.serverPort = hp->port;
  ob.keyPath = QDir(dirB).filePath("identity.pem");
  ob.selfName = "smokeB";
  ob.listenPort = 41002;
  ob.noUpnp = true;
  ob.externalPort = ob.listenPort;

  QString idA;
  QString idB;
  std::atomic<bool> done{false};

  auto maybeKick = [&] {
    if (idA.isEmpty() || idB.isEmpty()) return;
    a.setFriendAccepted(idB, true);
    b.setFriendAccepted(idA, true);
    a.sendMessage(idB, "hello over udp");
  };

  QObject::connect(&a, &ChatBackend::registered, &app, [&](QString selfId, bool, QString, quint16) {
    idA = selfId;
    maybeKick();
  });
  QObject::connect(&b, &ChatBackend::registered, &app, [&](QString selfId, bool, QString, quint16) {
    idB = selfId;
    maybeKick();
  });

  QObject::connect(&b, &ChatBackend::messageReceived, &app,
                   [&](QString peerId, QString, QString text, bool incoming) {
                     if (!incoming) return;
                     if (done.load()) return;
                     if (peerId != idA) return;
                     if (text != "hello over udp") return;
                     done.store(true);
                     std::cout << "OK: received message over UDP session\n";
                     QTimer::singleShot(0, &app, [&] { app.exit(0); });
                   });

  QObject::connect(&a, &ChatBackend::deliveryError, &app, [&](QString, QString msg) {
    if (done.load()) return;
    std::cerr << "delivery error: " << msg.toStdString() << "\n";
  });
  QObject::connect(&b, &ChatBackend::deliveryError, &app, [&](QString, QString msg) {
    if (done.load()) return;
    std::cerr << "delivery error: " << msg.toStdString() << "\n";
  });

  QTimer::singleShot(timeoutMs, &app, [&] {
    if (done.load()) return;
    std::cerr << "timeout\n";
    app.exit(1);
  });

  a.start(oa);
  b.start(ob);

  const int rc = app.exec();
  a.stop();
  b.stop();
  return rc;
}

