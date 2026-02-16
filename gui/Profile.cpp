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
  const auto overrideDir = qEnvironmentVariable("P2P_CHAT_CONFIG_DIR");
  if (!overrideDir.trimmed().isEmpty()) {
    QFileInfo fi(overrideDir);
    if (fi.isAbsolute()) return fi.absoluteFilePath();
    return QDir::current().absoluteFilePath(overrideDir);
  }
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
  const bool usingProfileStore = !qEnvironmentVariable("P2P_CHAT_PROFILE_NAME").trimmed().isEmpty();

  // Identity migration independent of profile existence:
  // if a legacy identity exists but the canonical one doesn't, copy it over before any key creation.
  const auto canonicalKey = Profile::defaultKeyPath();
  const auto legacy_gui_key = QDir(legacyConfigDir()).filePath("identity.pem");
  const auto legacy_cli_key =
      QDir(QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation)).filePath("p2p_chat/identity.pem");

  if (!usingProfileStore && !QFile::exists(canonicalKey)) {
    const QString src = QFile::exists(legacy_cli_key) ? legacy_cli_key
                     : QFile::exists(legacy_gui_key) ? legacy_gui_key
                                                     : QString();
    if (!src.isEmpty()) {
      QDir().mkpath(QFileInfo(canonicalKey).absolutePath());
      (void)QFile::copy(src, canonicalKey);
    }
  }

  // If both exist and differ, surface a warning (helps explain mismatched IDs).
  if (!usingProfileStore && QFile::exists(canonicalKey) && QFile::exists(legacy_cli_key)) {
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
  if (!usingProfileStore && !QFile::exists(path)) {
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
  p.shareIdentityWithNonFriendsInServers = root.value("shareIdentityWithNonFriendsInServers").toBool(false);
  p.signedOnlyServerMessages = root.value("signedOnlyServerMessages").toBool(false);
  p.hideLocalStreamPreviewInServerByDefault = root.value("hideLocalStreamPreviewInServerByDefault").toBool(false);
  if (root.value("mutedVoicePeerIds").isArray()) {
    const auto muted = root.value("mutedVoicePeerIds").toArray();
    for (const auto& v : muted) {
      if (!v.isString()) continue;
      const auto id = v.toString();
      if (id.isEmpty()) continue;
      p.mutedVoicePeerIds.push_back(id);
    }
  }

  if (root.value("audio").isObject()) {
    const auto a = root.value("audio").toObject();
    p.audio.inputDeviceIdHex = a.value("inputDeviceIdHex").toString();
    p.audio.outputDeviceIdHex = a.value("outputDeviceIdHex").toString();
    p.audio.micVolume = a.value("micVolume").toInt(p.audio.micVolume);
    p.audio.speakerVolume = a.value("speakerVolume").toInt(p.audio.speakerVolume);
    p.audio.bitrate = a.value("bitrate").toInt(p.audio.bitrate);
    p.audio.frameMs = a.value("frameMs").toInt(p.audio.frameMs);
    p.audio.channels = a.value("channels").toInt(p.audio.channels);
    if (p.audio.frameMs != 10 && p.audio.frameMs != 20) p.audio.frameMs = 20;
    if (p.audio.channels != 1 && p.audio.channels != 2) p.audio.channels = 1;
    p.audio.micVolume = std::clamp(p.audio.micVolume, 0, 100);
    p.audio.speakerVolume = std::clamp(p.audio.speakerVolume, 0, 100);
    if (p.audio.bitrate < 8000) p.audio.bitrate = 8000;
    if (p.audio.bitrate > 128000) p.audio.bitrate = 128000;
  }

  if (root.value("video").isObject()) {
    const auto v = root.value("video").toObject();
    p.video.devicePath = v.value("devicePath").toString();
    p.video.cameraFourcc = v.value("cameraFourcc").toString();
    p.video.width = v.value("width").toInt(p.video.width);
    p.video.height = v.value("height").toInt(p.video.height);
    p.video.fpsNum = v.value("fpsNum").toInt(p.video.fpsNum);
    p.video.fpsDen = v.value("fpsDen").toInt(p.video.fpsDen);
    p.video.codec = v.value("codec").toString(p.video.codec);
    p.video.bitrateKbps = v.value("bitrateKbps").toInt(p.video.bitrateKbps);
    if (p.video.width < 16) p.video.width = 16;
    if (p.video.height < 16) p.video.height = 16;
    if (p.video.fpsNum <= 0) p.video.fpsNum = 1;
    if (p.video.fpsDen <= 0) p.video.fpsDen = 30;
    if (p.video.bitrateKbps < 100) p.video.bitrateKbps = 100;
    if (p.video.bitrateKbps > 20000) p.video.bitrateKbps = 20000;
    p.video.codec = p.video.codec.trimmed().toLower();
    if (p.video.codec == "h265") p.video.codec = "hevc";
    if (p.video.codec == "av01") p.video.codec = "av1";
    if (p.video.codec != "h264" && p.video.codec != "hevc" && p.video.codec != "av1") p.video.codec = "h264";
  }

  if (root.value("screen").isObject()) {
    const auto s = root.value("screen").toObject();
    p.screen.width = s.value("width").toInt(p.screen.width);
    p.screen.height = s.value("height").toInt(p.screen.height);
    p.screen.fpsNum = s.value("fpsNum").toInt(p.screen.fpsNum);
    p.screen.fpsDen = s.value("fpsDen").toInt(p.screen.fpsDen);
    p.screen.bitrateKbps = s.value("bitrateKbps").toInt(p.screen.bitrateKbps);
    p.screen.codec = s.value("codec").toString(p.screen.codec);
    p.screen.provider = s.value("provider").toString(p.screen.provider);
    p.screen.lastDisplayName = s.value("lastDisplayName").toString(p.screen.lastDisplayName);
    if (p.screen.width < 0) p.screen.width = 0;
    if (p.screen.height < 0) p.screen.height = 0;
    if (p.screen.width == 0 || p.screen.height == 0) {
      p.screen.width = 0;
      p.screen.height = 0;
    }
    if (p.screen.fpsNum <= 0) p.screen.fpsNum = 1;
    if (p.screen.fpsDen <= 0) p.screen.fpsDen = 15;
    if (p.screen.bitrateKbps < 100) p.screen.bitrateKbps = 100;
    if (p.screen.bitrateKbps > 20000) p.screen.bitrateKbps = 20000;
    p.screen.codec = p.screen.codec.trimmed().toLower();
    if (p.screen.codec == "h265") p.screen.codec = "hevc";
    if (p.screen.codec == "av01") p.screen.codec = "av1";
    if (p.screen.codec != "h264" && p.screen.codec != "hevc" && p.screen.codec != "av1") p.screen.codec = "h264";
    p.screen.provider = p.screen.provider.trimmed().toLower();
    if (p.screen.provider.isEmpty()) p.screen.provider = "auto";
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

  const auto srvArr = root.value("servers").toArray();
  for (const auto& v : srvArr) {
    if (!v.isObject()) continue;
    const auto so = v.toObject();
    ServerEntry s;
    s.id = so.value("id").toString();
    s.name = so.value("name").toString();
    s.ownerId = so.value("ownerId").toString();
    s.membershipCertPayload = so.value("membershipCertPayload").toString();
    s.membershipCertSignature = so.value("membershipCertSignature").toString();
    s.expanded = so.value("expanded").toBool(true);
    const auto chArr = so.value("channels").toArray();
    for (const auto& cv : chArr) {
      if (!cv.isObject()) continue;
      const auto co = cv.toObject();
      ServerChannel c;
      c.id = co.value("id").toString();
      c.name = co.value("name").toString();
      c.voice = co.value("voice").toBool(false);
      if (!c.id.isEmpty()) s.channels.push_back(c);
    }
    const auto memArr = so.value("members").toArray();
    for (const auto& mv : memArr) {
      if (!mv.isObject()) continue;
      const auto mo = mv.toObject();
      ServerMember m;
      m.id = mo.value("id").toString();
      m.name = mo.value("name").toString();
      if (!m.id.isEmpty()) s.members.push_back(m);
    }
    const auto revokedArr = so.value("revokedMemberIds").toArray();
    for (const auto& rv : revokedArr) {
      if (!rv.isString()) continue;
      const auto id = rv.toString();
      if (!id.isEmpty()) s.revokedMemberIds.push_back(id);
    }
    if (!s.id.isEmpty()) p.servers.push_back(s);
  }

  const auto invArr = root.value("pendingServerInvites").toArray();
  for (const auto& v : invArr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    PendingServerInvite pi;
    pi.serverId = o.value("serverId").toString();
    pi.ownerId = o.value("ownerId").toString();
    pi.payloadJson = o.value("payloadJson").toString();
    pi.signature = o.value("signature").toString();
    if (!pi.serverId.isEmpty() && !pi.ownerId.isEmpty()) p.pendingServerInvites.push_back(pi);
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
  } else if (!usingProfileStore && is_legacy(p.keyPath)) {
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
  if (usingProfileStore) {
    const auto canonicalAbs = QFileInfo(canonical).absoluteFilePath();
    const auto currentAbs = QFileInfo(p.keyPath).absoluteFilePath();
    if (p.keyPath.isEmpty() || currentAbs != canonicalAbs) {
      if (!QFile::exists(canonical) && QFile::exists(p.keyPath)) {
        QDir().mkpath(QFileInfo(canonical).absolutePath());
        (void)QFile::copy(p.keyPath, canonical);
      }
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
  root["shareIdentityWithNonFriendsInServers"] = shareIdentityWithNonFriendsInServers;
  root["signedOnlyServerMessages"] = signedOnlyServerMessages;
  root["hideLocalStreamPreviewInServerByDefault"] = hideLocalStreamPreviewInServerByDefault;
  {
    QJsonArray muted;
    for (const auto& id : mutedVoicePeerIds) {
      if (id.isEmpty()) continue;
      muted.push_back(id);
    }
    root["mutedVoicePeerIds"] = muted;
  }

  {
    QJsonObject a;
    a["inputDeviceIdHex"] = audio.inputDeviceIdHex;
    a["outputDeviceIdHex"] = audio.outputDeviceIdHex;
    a["micVolume"] = audio.micVolume;
    a["speakerVolume"] = audio.speakerVolume;
    a["bitrate"] = audio.bitrate;
    a["frameMs"] = audio.frameMs;
    a["channels"] = (audio.channels == 2) ? 2 : 1;
    root["audio"] = a;
  }

  {
    QJsonObject v;
    v["devicePath"] = video.devicePath;
    v["cameraFourcc"] = video.cameraFourcc;
    v["width"] = video.width;
    v["height"] = video.height;
    v["fpsNum"] = video.fpsNum;
    v["fpsDen"] = video.fpsDen;
    v["codec"] = video.codec;
    v["bitrateKbps"] = video.bitrateKbps;
    root["video"] = v;
  }

  {
    QJsonObject s;
    s["width"] = screen.width;
    s["height"] = screen.height;
    s["fpsNum"] = screen.fpsNum;
    s["fpsDen"] = screen.fpsDen;
    s["bitrateKbps"] = screen.bitrateKbps;
    s["codec"] = screen.codec;
    s["provider"] = screen.provider;
    s["lastDisplayName"] = screen.lastDisplayName;
    root["screen"] = s;
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

  QJsonArray srvArr;
  for (const auto& s : servers) {
    QJsonObject so;
    so["id"] = s.id;
    so["name"] = s.name;
    so["ownerId"] = s.ownerId;
    so["membershipCertPayload"] = s.membershipCertPayload;
    so["membershipCertSignature"] = s.membershipCertSignature;
    so["expanded"] = s.expanded;
    QJsonArray chArr;
    for (const auto& c : s.channels) {
      QJsonObject co;
      co["id"] = c.id;
      co["name"] = c.name;
      co["voice"] = c.voice;
      chArr.push_back(co);
    }
    so["channels"] = chArr;
    QJsonArray memArr;
    for (const auto& m : s.members) {
      QJsonObject mo;
      mo["id"] = m.id;
      mo["name"] = m.name;
      memArr.push_back(mo);
    }
    so["members"] = memArr;
    QJsonArray revokedArr;
    for (const auto& id : s.revokedMemberIds) {
      revokedArr.push_back(id);
    }
    so["revokedMemberIds"] = revokedArr;
    srvArr.push_back(so);
  }
  root["servers"] = srvArr;

  QJsonArray invArr;
  for (const auto& pi : pendingServerInvites) {
    QJsonObject o;
    o["serverId"] = pi.serverId;
    o["ownerId"] = pi.ownerId;
    o["payloadJson"] = pi.payloadJson;
    o["signature"] = pi.signature;
    invArr.push_back(o);
  }
  root["pendingServerInvites"] = invArr;

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

Profile::ServerEntry* Profile::findServer(const QString& id) {
  for (auto& s : servers) {
    if (s.id == id) return &s;
  }
  return nullptr;
}

const Profile::ServerEntry* Profile::findServer(const QString& id) const {
  for (const auto& s : servers) {
    if (s.id == id) return &s;
  }
  return nullptr;
}

Profile::PendingServerInvite* Profile::findPendingServerInvite(const QString& serverId, const QString& ownerId) {
  for (auto& p : pendingServerInvites) {
    if (p.serverId == serverId && p.ownerId == ownerId) return &p;
  }
  return nullptr;
}

const Profile::PendingServerInvite* Profile::findPendingServerInvite(const QString& serverId,
                                                                     const QString& ownerId) const {
  for (const auto& p : pendingServerInvites) {
    if (p.serverId == serverId && p.ownerId == ownerId) return &p;
  }
  return nullptr;
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
    m.senderId = o.value("senderId").toString();
    m.senderName = o.value("senderName").toString();
    m.senderUnknown = o.value("senderUnknown").toBool(false);
    m.verified = o.value("verified").toBool(false);
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
    if (!m.senderId.isEmpty()) o["senderId"] = m.senderId;
    if (!m.senderName.isEmpty()) o["senderName"] = m.senderName;
    if (m.senderUnknown) o["senderUnknown"] = true;
    if (m.verified) o["verified"] = true;
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
