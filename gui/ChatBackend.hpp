#pragma once

#include <QObject>
#include <QString>

// Thin Qt wrapper around the existing CLI networking logic (Boost.Asio).
// Runs the network stack on a background thread and emits Qt signals.
class ChatBackend : public QObject {
  Q_OBJECT
public:
  struct Options {
    QString serverHost = "learn.fairuse.org";
    quint16 serverPort = 5555;
    QString keyPath;
    QString selfName;
    quint16 listenPort = 0;
    bool noUpnp = false;
    quint16 externalPort = 0;
  };

  explicit ChatBackend(QObject* parent = nullptr);
  ~ChatBackend() override;

  void start(const Options& opt);
  void stop();

  void setSelfName(const QString& name);

  void sendFriendRequest(const QString& peerId, const QString& intro);
  void acceptFriend(const QString& peerId);
  void sendMessage(const QString& peerId, const QString& text);
  void disconnectPeer(const QString& peerId);
  void warmConnect(const QString& peerId);

  void setFriendAccepted(const QString& peerId, bool accepted);

signals:
  void registered(QString selfId, bool reachable, QString observedIp, quint16 externalPort);
  void logLine(QString line);
  void friendRequestReceived(QString fromId, QString intro);
  void friendAccepted(QString peerId);
  void peerNameUpdated(QString peerId, QString name);
  void messageReceived(QString peerId, QString displayName, QString text, bool incoming);
  void deliveryError(QString peerId, QString message);

private:
  struct Impl;
  Impl* impl_;
};
