#pragma once

#include "gui/ChatBackend.hpp"
#include "gui/Profile.hpp"

#include <QMainWindow>
#include <QMap>
#include <QPointer>

class QListWidget;
class QTextBrowser;
class QLineEdit;
class QLabel;
class QTabWidget;
class QPushButton;
class QPoint;
class QAction;

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
  void selectFriend(const QString& id);
  QString currentPeerId() const;

  void addFriendDialog();
  void showChatContextMenu(const QPoint& pos);
  void showProfilePopup(const QString& peerId);
  void clearChatFor(const QString& peerId);
  void removeFriend(const QString& peerId);

  void appendMessage(const QString& peerId, const QString& label, const QString& text, bool incoming);
  void refreshHeader();
  void refreshSelfProfileWidget();
  void refreshCallButton();

  Profile profile_;
  ChatBackend backend_;

  QTabWidget* leftTabs_ = nullptr;
  QListWidget* friendList_ = nullptr;

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
  QTextBrowser* chatView_ = nullptr;
  QLineEdit* input_ = nullptr;

  // Self profile widget (Chats tab bottom)
  QLabel* myAvatarLabel_ = nullptr;
  QLabel* myNameLabel_ = nullptr;

  QString selectedPeerId_;
  QString selfId_;
  QMap<QString, QVector<Profile::ChatMessage>> chatCache_;
  QMap<QString, bool> online_;

  QAction* darkModeAction_ = nullptr;

  QString activeCallPeer_;
  QString activeCallState_;
};
