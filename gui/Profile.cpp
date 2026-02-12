#include "gui/Profile.hpp"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>

#include <algorithm>

namespace {
QString configRootDir() {
  // Prefer the standard XDG config root; keep our state in ~/.config/p2p-chat on Linux.
  const auto root = QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
  return QDir(root).filePath("p2p-chat");
}

QString legacyConfigDir() {
  // Legacy location used earlier: ~/.config/p2p-chat/p2p_chat (Qt's AppConfigLocation).
  return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
}

void copyDirBestEffort(const QString& fromDir, const QString& toDir) {
  QDir src(fromDir);
  if (!src.exists()) return;
  QDir().mkpath(toDir);

  const auto entries = src.entryInfoList(QDir::Files | QDir::NoDotAndDotDot);
  for (const auto& fi : entries) {
    const auto dst = QDir(toDir).filePath(fi.fileName());
    if (QFile::exists(dst)) continue;
    QFile::copy(fi.absoluteFilePath(), dst);
  }
}
} // namespace

QString Profile::defaultPath() {
  return QDir(configRootDir()).filePath("profile.json");
}

QString Profile::defaultKeyPath() {
  return QDir(configRootDir()).filePath("identity.pem");
}

QString Profile::avatarsDir() {
  return QDir(configRootDir()).filePath("avatars");
}

QString Profile::selfAvatarFile() {
  return QDir(avatarsDir()).filePath("self.png");
}

QString Profile::peerAvatarFile(const QString& peerId) {
  // Peer IDs are base64url and safe as filenames on Windows/Linux.
  return QDir(avatarsDir()).filePath(peerId + ".png");
}

QString Profile::chatsDir() {
  return QDir(configRootDir()).filePath("chats");
}

QString Profile::chatPathForPeer(const QString& peerId) {
  // Peer IDs are base64url and safe as filenames on Windows/Linux, but keep a stable extension.
  return QDir(chatsDir()).filePath(peerId + ".json");
}

Profile Profile::load(const QString& path, QString* errorOut) {
  Profile p;
  p.path_ = path;

  // Identity migration independent of profile existence:
  // if a legacy identity exists but the canonical one doesn't, copy it over before any key creation.
  const auto canonicalKey = Profile::defaultKeyPath();
  const auto legacy_gui_key = QDir(legacyConfigDir()).filePath("identity.pem");
  const auto legacy_cli_key =
      QDir(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)).filePath("p2p_chat/identity.pem");

  if (!QFile::exists(canonicalKey)) {
    const QString src = QFile::exists(legacy_cli_key) ? legacy_cli_key
                     : QFile::exists(legacy_gui_key) ? legacy_gui_key
                                                     : QString();
    if (!src.isEmpty()) {
      QDir().mkpath(QFileInfo(canonicalKey).absolutePath());
      (void)QFile::copy(src, canonicalKey);
    }
  }

  // If both exist and differ, surface a warning (helps explain mismatched IDs).
  if (QFile::exists(canonicalKey) && QFile::exists(legacy_cli_key)) {
    QFile a(canonicalKey), b(legacy_cli_key);
    if (a.open(QIODevice::ReadOnly) && b.open(QIODevice::ReadOnly)) {
      const auto ha = QCryptographicHash::hash(a.readAll(), QCryptographicHash::Sha256);
      const auto hb = QCryptographicHash::hash(b.readAll(), QCryptographicHash::Sha256);
      if (ha != hb && errorOut) {
        *errorOut =
            "Warning: multiple identity keys found in ~/.config/p2p-chat and ~/.config/p2p_chat; IDs may differ.";
      }
    }
  }

  // Best-effort migration from legacy Qt AppConfigLocation to ~/.config/p2p-chat.
  if (!QFile::exists(path)) {
    const auto legacyDir = legacyConfigDir();
    const auto legacyProfile = QDir(legacyDir).filePath("profile.json");
    if (QFile::exists(legacyProfile)) {
      QDir().mkpath(QFileInfo(path).absolutePath());
      (void)QFile::copy(legacyProfile, path);

      // Migrate identity key if present.
      const auto newKey = Profile::defaultKeyPath();
      const auto legacyKey = QDir(legacyDir).filePath("identity.pem");
      if (!QFile::exists(newKey) && QFile::exists(legacyKey)) {
        QDir().mkpath(QFileInfo(newKey).absolutePath());
        (void)QFile::copy(legacyKey, newKey);
      }

      // Migrate chat logs.
      copyDirBestEffort(QDir(legacyDir).filePath("chats"), Profile::chatsDir());
    }
  }

  QFile f(path);
  if (!f.exists()) {
    // Ensure first run has stable defaults even before the profile is saved.
    p.keyPath = Profile::defaultKeyPath();
    return p;
  }
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
  p.selfAvatarPath = root.value("selfAvatarPath").toString();
  p.serverHost = root.value("serverHost").toString(p.serverHost);
  p.serverPort = static_cast<quint16>(root.value("serverPort").toInt(p.serverPort));
  p.listenPort = static_cast<quint16>(root.value("listenPort").toInt(0));
  p.noUpnp = root.value("noUpnp").toBool(false);
  p.externalPort = static_cast<quint16>(root.value("externalPort").toInt(0));
  p.darkMode = root.value("darkMode").toBool(false);

  if (root.value("audio").isObject()) {
    const auto a = root.value("audio").toObject();
    p.audio.inputDeviceIdHex = a.value("inputDeviceIdHex").toString();
    p.audio.outputDeviceIdHex = a.value("outputDeviceIdHex").toString();
    p.audio.micVolume = a.value("micVolume").toInt(p.audio.micVolume);
    p.audio.speakerVolume = a.value("speakerVolume").toInt(p.audio.speakerVolume);
    p.audio.bitrate = a.value("bitrate").toInt(p.audio.bitrate);
    p.audio.frameMs = a.value("frameMs").toInt(p.audio.frameMs);
    if (p.audio.frameMs != 10 && p.audio.frameMs != 20) p.audio.frameMs = 20;
    p.audio.micVolume = std::clamp(p.audio.micVolume, 0, 100);
    p.audio.speakerVolume = std::clamp(p.audio.speakerVolume, 0, 100);
    if (p.audio.bitrate < 8000) p.audio.bitrate = 8000;
    if (p.audio.bitrate > 128000) p.audio.bitrate = 128000;
  }

  const auto arr = root.value("friends").toArray();
  for (const auto& v : arr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    FriendEntry e;
    e.id = o.value("id").toString();
    e.alias = o.value("alias").toString();
    e.name = o.value("name").toString();
    e.avatarPath = o.value("avatarPath").toString();
    e.status = statusFromString(o.value("status").toString());
    if (!e.id.isEmpty()) p.friends.push_back(e);
  }

  // Normalize/migrate identity key path:
  // - Legacy GUI default:  <AppConfigLocation>/identity.pem  (typically ~/.config/p2p-chat/p2p_chat/identity.pem)
  // - Legacy CLI default:  ~/.config/p2p_chat/identity.pem
  // - New canonical:       ~/.config/p2p-chat/identity.pem
  const auto canonical = Profile::defaultKeyPath();
  const auto legacy_gui = QDir(legacyConfigDir()).filePath("identity.pem");
  const auto legacy_cli = QDir(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation))
                              .filePath("p2p_chat/identity.pem");

  auto is_legacy = [&](const QString& kp) {
    if (kp.isEmpty()) return true;
    if (QFileInfo(kp).absoluteFilePath() == QFileInfo(legacy_gui).absoluteFilePath()) return true;
    if (QFileInfo(kp).absoluteFilePath() == QFileInfo(legacy_cli).absoluteFilePath()) return true;
    if (QFileInfo(kp).absoluteFilePath().startsWith(QFileInfo(legacyConfigDir()).absoluteFilePath())) return true;
    if (kp.contains("/p2p_chat/identity.pem")) return true;   // old CLI underscore dir
    if (kp.contains("/p2p_chat/")) return true;
    return false;
  };

  if (p.keyPath.isEmpty()) {
    p.keyPath = canonical;
  } else if (is_legacy(p.keyPath)) {
    // Prefer canonical if it exists; otherwise copy legacy into canonical.
    if (QFile::exists(canonical)) {
      p.keyPath = canonical;
    } else if (QFile::exists(p.keyPath)) {
      QDir().mkpath(QFileInfo(canonical).absolutePath());
      (void)QFile::copy(p.keyPath, canonical);
      p.keyPath = canonical;
    } else if (QFile::exists(legacy_gui)) {
      QDir().mkpath(QFileInfo(canonical).absolutePath());
      (void)QFile::copy(legacy_gui, canonical);
      p.keyPath = canonical;
    }
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
  root["selfAvatarPath"] = selfAvatarPath;
  root["serverHost"] = serverHost;
  root["serverPort"] = static_cast<int>(serverPort);
  root["listenPort"] = static_cast<int>(listenPort);
  root["noUpnp"] = noUpnp;
  root["externalPort"] = static_cast<int>(externalPort);
  root["darkMode"] = darkMode;

  {
    QJsonObject a;
    a["inputDeviceIdHex"] = audio.inputDeviceIdHex;
    a["outputDeviceIdHex"] = audio.outputDeviceIdHex;
    a["micVolume"] = audio.micVolume;
    a["speakerVolume"] = audio.speakerVolume;
    a["bitrate"] = audio.bitrate;
    a["frameMs"] = audio.frameMs;
    root["audio"] = a;
  }

  QJsonArray arr;
  for (const auto& e : friends) {
    QJsonObject o;
    o["id"] = e.id;
    o["alias"] = e.alias;
    o["name"] = e.name;
    o["avatarPath"] = e.avatarPath;
    o["status"] = statusToString(e.status);
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
    // Sanitize timestamps: corrupted chat logs should not crash rendering.
    constexpr qint64 kMin = 946684800000LL;   // 2000-01-01
    constexpr qint64 kMax = 4102444800000LL;  // 2100-01-01
    if (m.tsMs < kMin || m.tsMs > kMax) m.tsMs = 0;
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
