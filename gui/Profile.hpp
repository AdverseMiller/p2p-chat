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

  QVector<FriendEntry> friends;

  FriendEntry* findFriend(const QString& id);
  const FriendEntry* findFriend(const QString& id) const;
  void upsertFriend(const FriendEntry& e);

  static QString statusToString(FriendStatus s);
  static FriendStatus statusFromString(const QString& s);

private:
  QString path_;
};
