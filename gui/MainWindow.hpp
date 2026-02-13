#pragma once

#include "gui/ChatBackend.hpp"
#include "gui/Profile.hpp"

#include <QMainWindow>
#include <QMap>
#include <QPointer>
#include <QSet>

class QListWidget;
class QTextBrowser;
class QLineEdit;
class QLabel;
class QTabWidget;
class QPushButton;
class QPoint;
class QAction;
class QJsonObject;
class QStackedWidget;
class QTimer;
class QWidget;

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

private:
  void buildUi();
  void loadProfile();
  void saveProfile();
  void applyTheme(bool dark);
  void rebuildFriendList();
  void rebuildFriendsTab();
  void rebuildServerList();
  void selectFriend(const QString& id);
  void selectServerChannel(const QString& serverId, const QString& channelId, bool voice);
  QString currentPeerId() const;
  QString currentChatKey() const;
  QString serverChannelChatKey(const QString& serverId, const QString& channelId) const;
  void showServerContextMenu(const QPoint& pos);
  void addServerDialog();
  void addChannelToServer(const QString& serverId, bool voice);
  void renameServerChannel(const QString& serverId, const QString& channelId);
  void inviteFriendToServer(const QString& serverId);
  void removeServer(const QString& serverId);
  void removeServerChannel(const QString& serverId, const QString& channelId);
  void reviewPendingServerInvites();
  void handleSignedControl(const QString& peerId,
                           const QString& kind,
                           const QString& payloadJsonCompact,
                           const QString& signature,
                           const QString& fromId);
  void handleUnsignedControl(const QString& peerId,
                             const QString& kind,
                             const QString& payloadJsonCompact,
                             const QString& fromId);
  void handleServerInvite(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerJoinRequest(const QString& peerId, const QJsonObject& payload);
  void handleServerMembershipCert(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerMemberSync(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerLeave(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerRevocation(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerChannelText(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerVoicePresence(const QString& peerId, const QJsonObject& payload, const QString& signature);
  void handleServerGlobalSay(const QString& peerId, const QJsonObject& payload);
  void broadcastServerMemberSync(const Profile::ServerEntry& server);
  void broadcastServerText(const QString& serverId, const QString& channelId, const QString& text);
  void broadcastServerGlobalSay(const QString& serverId, const QString& text);
  void broadcastVoicePresence(const QString& serverId, const QString& channelId, bool joined);
  void appendServerChannelMessage(const QString& serverId,
                                  const QString& channelId,
                                  const QString& senderId,
                                  const QString& senderName,
                                  const QString& text,
                                  bool incoming,
                                  bool verified);
  void maybeSyncVoiceCallForJoinedChannel();
  void announceJoinedVoicePresence();
  QString joinedVoiceServerId() const;
  QString joinedVoiceChannelId() const;
  void sanitizeVoiceOccupantsForServer(const QString& serverId);
  void syncBackendServerMembers();
  bool isFriendAccepted(const QString& peerId) const;
  bool canShowNonFriendIdentity(const QString& peerId, const QString& hintedName = QString()) const;
  bool shouldShowNonFriendAvatar(const QString& peerId, const QString& hintedName = QString()) const;
  QString serverMemberHintName(const QString& peerId) const;
  int presenceStateFor(const QString& peerId) const;
  QString serverPeerDisplayName(const QString& peerId, const QString& hintedName = QString()) const;
  void refreshFriendPresenceRow(const QString& peerId);
  void refreshServerMembersPane();
  void refreshVoiceGallery();
  void leaveSelectedServer();

  void addFriendDialog();
  void sendFriendRequestToId(const QString& id);
  void showChatContextMenu(const QPoint& pos);
  void showServerMemberContextMenu(const QPoint& pos);
  void showProfilePopup(const QString& peerId);
  void clearChatFor(const QString& peerId);
  void removeFriend(const QString& peerId);
  void kickServerMember(const QString& serverId, const QString& memberId);

  void appendMessage(const QString& peerId, const QString& label, const QString& text, bool incoming);
  void refreshHeader();
  void refreshSelfProfileWidget();
  void refreshCallButton();
  void refreshVideoPanel();

  Profile profile_;
  ChatBackend backend_;

  QTabWidget* leftTabs_ = nullptr;
  QListWidget* friendList_ = nullptr;
  QListWidget* serverList_ = nullptr;
  QPushButton* serverInvitesBtn_ = nullptr;

  // Friends tab widgets
  QLineEdit* myIdEdit_ = nullptr;
  QPushButton* copyIdBtn_ = nullptr;
  QLineEdit* addIdEdit_ = nullptr;
  QPushButton* sendReqBtn_ = nullptr;
  QListWidget* requestsList_ = nullptr;
  QPushButton* acceptBtn_ = nullptr;
  QPushButton* rejectBtn_ = nullptr;

  QLabel* headerLabel_ = nullptr;
  QPushButton* callBtn_ = nullptr;
  QPushButton* webcamBtn_ = nullptr;
  QStackedWidget* chatStack_ = nullptr;
  QTextBrowser* chatView_ = nullptr;
  QListWidget* voiceGallery_ = nullptr;
  QWidget* videoPanel_ = nullptr;
  QLabel* remoteVideoLabel_ = nullptr;
  QLabel* localVideoLabel_ = nullptr;
  QString remoteVideoPeerId_;
  bool remoteVideoActive_ = false;
  bool localVideoActive_ = false;
  QLineEdit* input_ = nullptr;
  QListWidget* serverMembersList_ = nullptr;

  // Self profile widget (Chats tab bottom)
  QLabel* myAvatarLabel_ = nullptr;
  QLabel* myNameLabel_ = nullptr;

  QString selectedPeerId_;
  QString selectedServerId_;
  QString selectedServerChannelId_;
  bool selectedServerChannelVoice_ = false;
  QString joinedServerVoiceKey_;
  QMap<QString, QSet<QString>> voiceOccupantsByChannel_; // key: serverChannelChatKey(server, channel)
  QString selfId_;
  QMap<QString, QVector<Profile::ChatMessage>> chatCache_;
  QMap<QString, bool> rendezvousOnline_;
  QMap<QString, bool> directOnline_;
  QSet<QString> pendingJoinOwners_;

  QAction* darkModeAction_ = nullptr;
  QTimer* voicePresenceTimer_ = nullptr;

  QString activeCallPeer_;
  QString activeCallState_;
  bool webcamEnabled_ = false;
};
