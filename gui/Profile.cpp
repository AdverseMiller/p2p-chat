#include "gui/Profile.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>

QString Profile::defaultPath() {
  const auto dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  return QDir(dir).filePath("profile.json");
}

QString Profile::defaultKeyPath() {
  const auto dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  return QDir(dir).filePath("identity.pem");
}

QString Profile::chatsDir() {
  const auto dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
  return QDir(dir).filePath("chats");
}

QString Profile::chatPathForPeer(const QString& peerId) {
  // Peer IDs are base64url and safe as filenames on Windows/Linux, but keep a stable extension.
  return QDir(chatsDir()).filePath(peerId + ".json");
}

Profile Profile::load(const QString& path, QString* errorOut) {
  Profile p;
  p.path_ = path;

  QFile f(path);
  if (!f.exists()) return p;
  if (!f.open(QIODevice::ReadOnly)) {
    if (errorOut) *errorOut = "Failed to open profile for reading";
    return p;
  }
  const auto bytes = f.readAll();
  f.close();

  QJsonParseError pe;
  const auto doc = QJsonDocument::fromJson(bytes, &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
    if (errorOut) *errorOut = "Failed to parse profile JSON";
    return p;
  }
  const auto root = doc.object();
  p.keyPath = root.value("keyPath").toString();
  p.selfName = root.value("selfName").toString();
  p.serverHost = root.value("serverHost").toString(p.serverHost);
  p.serverPort = static_cast<quint16>(root.value("serverPort").toInt(p.serverPort));
  p.listenPort = static_cast<quint16>(root.value("listenPort").toInt(0));
  p.noUpnp = root.value("noUpnp").toBool(false);
  p.externalPort = static_cast<quint16>(root.value("externalPort").toInt(0));

  const auto arr = root.value("friends").toArray();
  for (const auto& v : arr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    FriendEntry e;
    e.id = o.value("id").toString();
    e.alias = o.value("alias").toString();
    e.name = o.value("name").toString();
    e.status = statusFromString(o.value("status").toString());
    e.lastIntro = o.value("lastIntro").toString();
    if (!e.id.isEmpty()) p.friends.push_back(e);
  }
  return p;
}

bool Profile::save(QString* errorOut) const {
  QFile f(path_);
  QDir().mkpath(QFileInfo(path_).absolutePath());
  if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    if (errorOut) *errorOut = "Failed to open profile for writing";
    return false;
  }

  QJsonObject root;
  root["keyPath"] = keyPath;
  root["selfName"] = selfName;
  root["serverHost"] = serverHost;
  root["serverPort"] = static_cast<int>(serverPort);
  root["listenPort"] = static_cast<int>(listenPort);
  root["noUpnp"] = noUpnp;
  root["externalPort"] = static_cast<int>(externalPort);

  QJsonArray arr;
  for (const auto& e : friends) {
    QJsonObject o;
    o["id"] = e.id;
    o["alias"] = e.alias;
    o["name"] = e.name;
    o["status"] = statusToString(e.status);
    o["lastIntro"] = e.lastIntro;
    arr.push_back(o);
  }
  root["friends"] = arr;

  f.write(QJsonDocument(root).toJson(QJsonDocument::Indented));
  f.close();
  return true;
}

Profile::FriendEntry* Profile::findFriend(const QString& id) {
  for (auto& f : friends) {
    if (f.id == id) return &f;
  }
  return nullptr;
}

const Profile::FriendEntry* Profile::findFriend(const QString& id) const {
  for (const auto& f : friends) {
    if (f.id == id) return &f;
  }
  return nullptr;
}

void Profile::upsertFriend(const FriendEntry& e) {
  for (auto& f : friends) {
    if (f.id == e.id) {
      f = e;
      return;
    }
  }
  friends.push_back(e);
}

QVector<Profile::ChatMessage> Profile::loadChat(const QString& peerId, QString* errorOut) const {
  QVector<ChatMessage> out;
  const auto p = chatPathForPeer(peerId);
  QFile f(p);
  if (!f.exists()) return out;
  if (!f.open(QIODevice::ReadOnly)) {
    if (errorOut) *errorOut = "Failed to open chat history";
    return out;
  }
  const auto bytes = f.readAll();
  f.close();

  QJsonParseError pe;
  const auto doc = QJsonDocument::fromJson(bytes, &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isArray()) {
    if (errorOut) *errorOut = "Failed to parse chat history";
    return out;
  }
  const auto arr = doc.array();
  out.reserve(arr.size());
  for (const auto& v : arr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    ChatMessage m;
    m.tsMs = static_cast<qint64>(o.value("tsMs").toVariant().toLongLong());
    m.incoming = o.value("incoming").toBool(false);
    m.text = o.value("text").toString();
    if (!m.text.isEmpty()) out.push_back(m);
  }
  return out;
}

bool Profile::saveChat(const QString& peerId, const QVector<ChatMessage>& msgs, QString* errorOut) const {
  const auto dir = chatsDir();
  QDir().mkpath(dir);
  QFile f(chatPathForPeer(peerId));
  if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    if (errorOut) *errorOut = "Failed to write chat history";
    return false;
  }

  QJsonArray arr;
  for (const auto& m : msgs) {
    QJsonObject o;
    o["tsMs"] = static_cast<double>(m.tsMs);
    o["incoming"] = m.incoming;
    o["text"] = m.text;
    arr.push_back(o);
  }

  f.write(QJsonDocument(arr).toJson(QJsonDocument::Compact));
  f.close();
  return true;
}

bool Profile::deleteChat(const QString& peerId, QString* errorOut) const {
  QFile f(chatPathForPeer(peerId));
  if (!f.exists()) return true;
  if (!f.remove()) {
    if (errorOut) *errorOut = "Failed to delete chat history";
    return false;
  }
  return true;
}

QString Profile::statusToString(FriendStatus s) {
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
  return "none";
}

Profile::FriendStatus Profile::statusFromString(const QString& s) {
  if (s == "outgoing_pending") return FriendStatus::OutgoingPending;
  if (s == "incoming_pending") return FriendStatus::IncomingPending;
  if (s == "accepted") return FriendStatus::Accepted;
  return FriendStatus::None;
}
