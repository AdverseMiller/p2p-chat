#pragma once

#include <QJsonObject>
#include <QString>
#include <QVector>

class Profile {
public:
  enum class FriendStatus {
    None,
    OutgoingPending,
    IncomingPending,
    Accepted,
  };

  struct FriendEntry {
    QString id;
    QString alias;   // local nickname
    QString name;    // learned from peer after handshake
    QString avatarPath; // local cached avatar image path (png)
    FriendStatus status = FriendStatus::None;
  };

  struct ServerChannel {
    QString id;
    QString name;
    bool voice = false;
  };

  struct ServerMember {
    QString id;
    QString name;
  };

  struct ServerEntry {
    QString id;
    QString name;
    QString ownerId;
    QString membershipCertPayload;   // compact JSON payload signed by owner
    QString membershipCertSignature; // base64url Ed25519 over payload
    bool expanded = true;
    QVector<ServerChannel> channels;
    QVector<ServerMember> members;
    QVector<QString> revokedMemberIds;
  };

  struct PendingServerInvite {
    QString serverId;
    QString ownerId;
    QString payloadJson; // compact JSON payload signed by owner
    QString signature;   // owner signature over payloadJson
  };

  struct ChatMessage {
    qint64 tsMs = 0;   // UTC ms since epoch
    bool incoming = false;
    QString senderId;   // optional; used for multi-sender chats (server channels)
    QString senderName; // optional display hint for multi-sender chats
    bool senderUnknown = false; // true when sender identity/name should not be disclosed
    bool verified = false;      // true when message came from a verified signed control envelope
    QString text;
  };

  static QString defaultPath();
  static QString defaultKeyPath();
  static QString avatarsDir();
  static QString selfAvatarFile();
  static QString peerAvatarFile(const QString& peerId);
  static Profile load(const QString& path, QString* errorOut = nullptr);
  bool save(QString* errorOut = nullptr) const;

  const QString& path() const { return path_; }

  struct AudioSettings {
    QString inputDeviceIdHex;
    QString outputDeviceIdHex;
    int micVolume = 100;      // 0..100
    int speakerVolume = 100;  // 0..100
    int bitrate = 32000;      // bps (Opus target)
    int frameMs = 20;         // 10 or 20
    int channels = 1;         // 1 (mono) or 2 (stereo)
  };

  struct VideoSettings {
    QString devicePath;
    QString cameraFourcc; // e.g. "MJPG"
    int width = 640;
    int height = 480;
    int fpsNum = 1;
    int fpsDen = 30;
    QString codec = "h264";
    int bitrateKbps = 1500;
  };

  struct ScreenSettings {
    int width = 0;     // 0 => native display resolution
    int height = 0;    // 0 => native display resolution
    int fpsNum = 1;    // denominator-style (fps = den / num)
    int fpsDen = 15;
    int bitrateKbps = 2500;
    QString codec = "h264";
    QString lastDisplayName;
  };

  QString keyPath;          // identity pem path
  QString selfName;         // last used name
  QString selfAvatarPath;   // local avatar path (png)
  QString serverHost = "learn.fairuse.org";
  quint16 serverPort = 5555;
  quint16 listenPort = 0;
  bool noUpnp = false;
  quint16 externalPort = 0;
  bool darkMode = false;
  bool shareIdentityWithNonFriendsInServers = false;
  bool signedOnlyServerMessages = false;
  bool hideLocalStreamPreviewInServerByDefault = false;
  QVector<QString> mutedVoicePeerIds;
  AudioSettings audio;
  VideoSettings video;
  ScreenSettings screen;

  QVector<FriendEntry> friends;
  QVector<ServerEntry> servers;
  QVector<PendingServerInvite> pendingServerInvites;

  FriendEntry* findFriend(const QString& id);
  const FriendEntry* findFriend(const QString& id) const;
  void upsertFriend(const FriendEntry& e);

  ServerEntry* findServer(const QString& id);
  const ServerEntry* findServer(const QString& id) const;
  PendingServerInvite* findPendingServerInvite(const QString& serverId, const QString& ownerId);
  const PendingServerInvite* findPendingServerInvite(const QString& serverId, const QString& ownerId) const;

  QVector<ChatMessage> loadChat(const QString& peerId, QString* errorOut = nullptr) const;
  bool saveChat(const QString& peerId, const QVector<ChatMessage>& msgs, QString* errorOut = nullptr) const;
  bool deleteChat(const QString& peerId, QString* errorOut = nullptr) const;

  static QString statusToString(FriendStatus s);
  static FriendStatus statusFromString(const QString& s);

private:
  static QString chatsDir();
  static QString chatPathForPeer(const QString& peerId);
  QString path_;
};
