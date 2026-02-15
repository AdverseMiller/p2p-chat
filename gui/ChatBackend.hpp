#pragma once

#include <QObject>
#include <QByteArray>
#include <QImage>
#include <QString>
#include <QStringList>

// Thin Qt wrapper around the existing CLI networking logic (Boost.Asio).
// Runs the network stack on a background thread and emits Qt signals.
class ChatBackend : public QObject {
  Q_OBJECT
public:
  struct Options {
    QString serverHost = "learn.fairuse.org";
    quint16 serverPort = 5555;
    QString keyPath;
    QString keyPassword;
    QString selfName;
    quint16 listenPort = 0;
  };

  struct VoiceSettings {
    QString inputDeviceIdHex;
    QString outputDeviceIdHex;
    int micVolume = 100;      // 0..100
    int speakerVolume = 100;  // 0..100
    int bitrate = 32000;      // bps
    int frameMs = 20;         // 10 or 20
    int channels = 1;         // 1 (mono) or 2 (stereo)
    QString videoDevicePath;
    QString videoFourcc;      // "MJPG"/"YUYV"/...
    int videoWidth = 640;
    int videoHeight = 480;
    int videoFpsNum = 1;
    int videoFpsDen = 30;
    QString videoCodec = "h264";
    int videoBitrateKbps = 1500;
    bool videoEnabled = true;
  };

  explicit ChatBackend(QObject* parent = nullptr);
  ~ChatBackend() override;

  void start(const Options& opt);
  void stop();

  void setSelfName(const QString& name);
  void setSelfAvatarPng(const QByteArray& pngBytes);

  void sendFriendRequest(const QString& peerId);
  void acceptFriend(const QString& peerId);
  // Send an end-to-end encrypted signed control envelope to an accepted friend.
  // `payloadJsonCompact` must be valid JSON object text.
  void sendSignedControl(const QString& peerId, const QString& kind, const QString& payloadJsonCompact);
  void sendUnsignedControl(const QString& peerId, const QString& kind, const QString& payloadJsonCompact);
  void sendMessage(const QString& peerId, const QString& text);
  void disconnectPeer(const QString& peerId);
  void warmConnect(const QString& peerId);

  void setFriendAccepted(const QString& peerId, bool accepted);
  void setServerMembers(const QStringList& peerIds);
  void setPeerMuted(const QString& peerId, bool muted);
  void setPeerVideoWatch(const QString& peerId, bool watching);

  // Voice calls (Opus over UDP hole-punching). Only one active call at a time.
  void startCall(const QString& peerId, const VoiceSettings& settings);
  void answerCall(const QString& peerId, bool accept, const VoiceSettings& settings);
  void endCall(const QString& peerId);
  // Update voice settings; applies live when in a call (where possible).
  void updateVoiceSettings(const VoiceSettings& settings);

signals:
  void registered(QString selfId, QString observedIp, quint16 udpPort);
  void logLine(QString line);
  void friendRequestReceived(QString fromId);
  void friendAccepted(QString peerId);
  void presenceUpdated(QString peerId, bool online);
  void directPeerConnectionChanged(QString peerId, bool connected);
  void peerAvatarUpdated(QString peerId, QByteArray pngBytes);
  void peerNameUpdated(QString peerId, QString name);
  void messageReceived(QString peerId, QString displayName, QString text, bool incoming);
  void signedControlReceived(QString peerId, QString kind, QString payloadJsonCompact, QString signature, QString fromId);
  void unsignedControlReceived(QString peerId, QString kind, QString payloadJsonCompact, QString fromId);
  void deliveryError(QString peerId, QString message);

  void incomingCall(QString peerId);
  void callStateChanged(QString peerId, QString state);
  void callEnded(QString peerId, QString reason);
  void localVideoFrame(QImage frame);
  void remoteVideoFrame(QString peerId, QImage frame);
  void remoteVideoAvailabilityChanged(QString peerId, bool available);

private:
  struct Impl;
  Impl* impl_;
};
