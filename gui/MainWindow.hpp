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

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  explicit MainWindow(QWidget* parent = nullptr);
  ~MainWindow() override;

private:
  void buildUi();
  void loadProfile();
  void saveProfile();
  void rebuildFriendList();
  void selectFriend(const QString& id);
  QString currentPeerId() const;

  void addFriendDialog();

  void appendMessage(const QString& peerId, const QString& label, const QString& text, bool incoming);
  void refreshHeader();

  Profile profile_;
  ChatBackend backend_;

  QListWidget* friendList_ = nullptr;
  QLabel* headerLabel_ = nullptr;
  QTextBrowser* chatView_ = nullptr;
  QLineEdit* input_ = nullptr;

  QString selectedPeerId_;
  QMap<QString, QStringList> chatCache_;
};

