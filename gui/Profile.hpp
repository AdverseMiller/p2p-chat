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
    FriendStatus status = FriendStatus::None;
    QString lastIntro;
  };

  struct ChatMessage {
    qint64 tsMs = 0;   // UTC ms since epoch
    bool incoming = false;
    QString text;
  };

  static QString defaultPath();
  static QString defaultKeyPath();
  static Profile load(const QString& path, QString* errorOut = nullptr);
  bool save(QString* errorOut = nullptr) const;

  const QString& path() const { return path_; }

  QString keyPath;          // identity pem path
  QString selfName;         // last used name
  QString serverHost = "learn.fairuse.org";
  quint16 serverPort = 5555;
  quint16 listenPort = 0;
  bool noUpnp = false;
  quint16 externalPort = 0;
  bool darkMode = false;

  QVector<FriendEntry> friends;

  FriendEntry* findFriend(const QString& id);
  const FriendEntry* findFriend(const QString& id) const;
  void upsertFriend(const FriendEntry& e);

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
