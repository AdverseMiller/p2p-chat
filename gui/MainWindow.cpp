#include "gui/MainWindow.hpp"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPalette>
#include <QColor>
#include <QPushButton>
#include <QStatusBar>
#include <QStyleFactory>
#include <QSplitter>
#include <QTabWidget>
#include <QTextBrowser>
#include <QTimeZone>
#include <QVBoxLayout>

namespace {
QString renderLine(const QString& stamp, const QString& who, const QString& text) {
  return QString("[%1] <b>%2</b>: %3").arg(stamp, who.toHtmlEscaped(), text.toHtmlEscaped());
}

QString nowStamp() {
  return QDateTime::currentDateTime().toString("HH:mm");
}

QString stampFromUtcMs(qint64 tsMs) {
  if (tsMs <= 0) return nowStamp();
  return QDateTime::fromMSecsSinceEpoch(tsMs, QTimeZone::utc()).toLocalTime().toString("HH:mm");
}

QString friendDisplay(const Profile::FriendEntry& e) {
  if (!e.alias.isEmpty()) return e.alias;
  if (!e.name.isEmpty()) return e.name;
  return e.id.left(14) + "...";
}

QString statusTag(Profile::FriendStatus s) {
  switch (s) {
    case Profile::FriendStatus::OutgoingPending:
      return " (pending)";
    case Profile::FriendStatus::IncomingPending:
      return " (request)";
    default:
      return "";
  }
}
} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
  buildUi();
  loadProfile();
  applyTheme(profile_.darkMode);

  connect(&backend_, &ChatBackend::registered, this,
          [this](QString selfId, bool reachable, QString observedIp, quint16 externalPort) {
            selfId_ = selfId;
            if (myIdEdit_) myIdEdit_->setText(selfId_);
            setWindowTitle(QString("p2p_chat_gui - %1").arg(selfId.left(12)));
            statusBar()->showMessage(QString("Reachable: %1  Observed: %2  External port: %3")
                                         .arg(reachable ? "true" : "false")
                                         .arg(observedIp)
                                         .arg(externalPort),
                                     10000);
          });

  connect(&backend_, &ChatBackend::friendRequestReceived, this,
          [this](QString fromId, QString intro) {
            auto* fe = profile_.findFriend(fromId);
            Profile::FriendEntry e;
            if (fe) e = *fe;
            e.id = fromId;
            e.status = Profile::FriendStatus::IncomingPending;
            e.lastIntro = intro;
            profile_.upsertFriend(e);
            saveProfile();
            rebuildFriendList();
            rebuildFriendsTab();

            statusBar()->showMessage(QString("Friend request from %1").arg(fromId.left(12)), 8000);
          });

  connect(&backend_, &ChatBackend::friendAccepted, this, [this](QString peerId) {
    auto* f = profile_.findFriend(peerId);
    if (!f) {
      Profile::FriendEntry e;
      e.id = peerId;
      e.status = Profile::FriendStatus::Accepted;
      profile_.upsertFriend(e);
    } else {
      f->status = Profile::FriendStatus::Accepted;
    }
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    backend_.setFriendAccepted(peerId, true);
  });

  connect(&backend_, &ChatBackend::messageReceived, this,
          [this](QString peerId, QString displayName, QString text, bool incoming) {
            appendMessage(peerId, displayName, text, incoming);
          });

  connect(&backend_, &ChatBackend::peerNameUpdated, this, [this](QString peerId, QString name) {
    if (name.isEmpty()) return;
    auto* f = profile_.findFriend(peerId);
    if (!f || f->status != Profile::FriendStatus::Accepted) return;
    if (f->name == name) return;
    f->name = name;
    saveProfile();
    rebuildFriendList();
    refreshHeader();
  });

  connect(&backend_, &ChatBackend::deliveryError, this, [this](QString peerId, QString msg) {
    statusBar()->showMessage(QString("Delivery to %1 failed: %2").arg(peerId.left(12), msg), 8000);
  });

  // Start backend.
  ChatBackend::Options opt;
  opt.serverHost = profile_.serverHost;
  opt.serverPort = profile_.serverPort;
  opt.keyPath = profile_.keyPath;
  opt.selfName = profile_.selfName;
  opt.listenPort = profile_.listenPort;
  opt.noUpnp = profile_.noUpnp;
  opt.externalPort = profile_.externalPort;
  backend_.start(opt);

  // Push accepted friends to backend gate.
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::Accepted) backend_.setFriendAccepted(f.id, true);
  }

  rebuildFriendList();
  rebuildFriendsTab();
  refreshHeader();
}

MainWindow::~MainWindow() {
  saveProfile();
  backend_.stop();
}

void MainWindow::buildUi() {
  auto* addFriend = new QAction("Add Friend...", this);
  connect(addFriend, &QAction::triggered, this, [this] { addFriendDialog(); });
  menuBar()->addAction(addFriend);

  auto* darkMode = new QAction("Dark Mode", this);
  darkMode->setCheckable(true);
  menuBar()->addAction(darkMode);

  auto* setName = new QAction("Set Name...", this);
  connect(setName, &QAction::triggered, this, [this] {
    bool ok = false;
    const auto name = QInputDialog::getText(this, "Set name", "Name:", QLineEdit::Normal, profile_.selfName, &ok)
                          .trimmed();
    if (!ok) return;
    if (name.size() > 32) {
      QMessageBox::warning(this, "Invalid name", "Name must be at most 32 characters.");
      return;
    }
    profile_.selfName = name;
    backend_.setSelfName(name);
    saveProfile();
    statusBar()->showMessage("Name updated (takes effect on next connection)", 6000);
  });
  menuBar()->addAction(setName);

  auto* quit = new QAction("Quit", this);
  connect(quit, &QAction::triggered, qApp, &QApplication::quit);
  menuBar()->addAction(quit);

  auto* splitter = new QSplitter(this);

  leftTabs_ = new QTabWidget(splitter);
  leftTabs_->setMinimumWidth(260);

  friendList_ = new QListWidget(leftTabs_);
  leftTabs_->addTab(friendList_, "Chats");

  // Friends tab
  auto* friendsTab = new QWidget(leftTabs_);
  auto* friendsLayout = new QVBoxLayout(friendsTab);
  friendsLayout->setContentsMargins(8, 8, 8, 8);

  auto* idLabel = new QLabel("Your ID (share this):", friendsTab);
  friendsLayout->addWidget(idLabel);

  auto* idRow = new QWidget(friendsTab);
  auto* idRowLayout = new QHBoxLayout(idRow);
  idRowLayout->setContentsMargins(0, 0, 0, 0);
  myIdEdit_ = new QLineEdit(idRow);
  myIdEdit_->setReadOnly(true);
  myIdEdit_->setPlaceholderText("Connecting…");
  copyIdBtn_ = new QPushButton("Copy", idRow);
  idRowLayout->addWidget(myIdEdit_, 1);
  idRowLayout->addWidget(copyIdBtn_);
  friendsLayout->addWidget(idRow);

  connect(copyIdBtn_, &QPushButton::clicked, this, [this] {
    if (!myIdEdit_) return;
    QGuiApplication::clipboard()->setText(myIdEdit_->text());
    statusBar()->showMessage("Copied ID to clipboard", 3000);
  });

  friendsLayout->addSpacing(10);

  auto* addLabel = new QLabel("Send friend request:", friendsTab);
  friendsLayout->addWidget(addLabel);

  addIdEdit_ = new QLineEdit(friendsTab);
  addIdEdit_->setPlaceholderText("Friend ID");
  friendsLayout->addWidget(addIdEdit_);

  addIntroEdit_ = new QLineEdit(friendsTab);
  addIntroEdit_->setPlaceholderText("Intro (optional)");
  friendsLayout->addWidget(addIntroEdit_);

  sendReqBtn_ = new QPushButton("Send Request", friendsTab);
  friendsLayout->addWidget(sendReqBtn_);
  connect(sendReqBtn_, &QPushButton::clicked, this, [this] {
    const auto id = addIdEdit_->text().trimmed();
    if (id.isEmpty()) return;
    Profile::FriendEntry e;
    auto* ex = profile_.findFriend(id);
    if (ex) e = *ex;
    e.id = id;
    if (e.status == Profile::FriendStatus::None) e.status = Profile::FriendStatus::OutgoingPending;
    profile_.upsertFriend(e);
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    backend_.sendFriendRequest(id, addIntroEdit_->text().trimmed());
    statusBar()->showMessage("Friend request sent", 5000);
  });

  friendsLayout->addSpacing(10);

  auto* reqLabel = new QLabel("Incoming requests:", friendsTab);
  friendsLayout->addWidget(reqLabel);
  requestsList_ = new QListWidget(friendsTab);
  friendsLayout->addWidget(requestsList_, 1);

  auto* reqBtns = new QWidget(friendsTab);
  auto* reqBtnsLayout = new QHBoxLayout(reqBtns);
  reqBtnsLayout->setContentsMargins(0, 0, 0, 0);
  acceptBtn_ = new QPushButton("Accept", reqBtns);
  rejectBtn_ = new QPushButton("Reject", reqBtns);
  reqBtnsLayout->addWidget(acceptBtn_);
  reqBtnsLayout->addWidget(rejectBtn_);
  friendsLayout->addWidget(reqBtns);

  connect(acceptBtn_, &QPushButton::clicked, this, [this] {
    if (!requestsList_ || !requestsList_->currentItem()) return;
    const auto id = requestsList_->currentItem()->data(Qt::UserRole).toString();
    auto* f = profile_.findFriend(id);
    if (!f) return;
    f->status = Profile::FriendStatus::Accepted;
    saveProfile();
    backend_.acceptFriend(id);
    backend_.setFriendAccepted(id, true);
    rebuildFriendList();
    rebuildFriendsTab();
    statusBar()->showMessage("Friend accepted", 5000);
  });
  connect(rejectBtn_, &QPushButton::clicked, this, [this] {
    if (!requestsList_ || !requestsList_->currentItem()) return;
    const auto id = requestsList_->currentItem()->data(Qt::UserRole).toString();
    for (int i = 0; i < profile_.friends.size(); ++i) {
      if (profile_.friends[i].id == id) {
        profile_.friends.removeAt(i);
        break;
      }
    }
    backend_.setFriendAccepted(id, false);
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    statusBar()->showMessage("Request rejected", 5000);
  });

  leftTabs_->addTab(friendsTab, "Friends");

  auto* right = new QWidget(splitter);
  auto* rightLayout = new QVBoxLayout(right);
  rightLayout->setContentsMargins(8, 8, 8, 8);

  headerLabel_ = new QLabel("No chat selected", right);
  headerLabel_->setStyleSheet("font-weight:600; font-size:14px;");
  rightLayout->addWidget(headerLabel_);

  chatView_ = new QTextBrowser(right);
  chatView_->setOpenExternalLinks(false);
  rightLayout->addWidget(chatView_, /*stretch*/ 1);

  auto* bottom = new QWidget(right);
  auto* bottomLayout = new QHBoxLayout(bottom);
  bottomLayout->setContentsMargins(0, 0, 0, 0);
  input_ = new QLineEdit(bottom);
  input_->setPlaceholderText("Type a message…");
  auto* sendBtn = new QPushButton("Send", bottom);
  bottomLayout->addWidget(input_, 1);
  bottomLayout->addWidget(sendBtn);
  rightLayout->addWidget(bottom);

  splitter->setStretchFactor(0, 1);
  splitter->setStretchFactor(1, 4);

  setCentralWidget(splitter);
  resize(1000, 650);

  connect(friendList_, &QListWidget::currentRowChanged, this, [this](int row) {
    if (row < 0 || row >= friendList_->count()) return;
    const auto id = friendList_->item(row)->data(Qt::UserRole).toString();
    selectFriend(id);
  });

  friendList_->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(friendList_, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
    showChatContextMenu(pos);
  });

  auto sendNow = [this] {
    const auto pid = currentPeerId();
    if (pid.isEmpty()) return;
    const auto msg = input_->text().trimmed();
    if (msg.isEmpty()) return;
    input_->clear();
    backend_.sendMessage(pid, msg);
  };
  connect(sendBtn, &QPushButton::clicked, this, sendNow);
  connect(input_, &QLineEdit::returnPressed, this, sendNow);

  // Dark mode toggle (profile loads after UI is built, so we set checked state later in loadProfile()).
  connect(darkMode, &QAction::toggled, this, [this](bool on) {
    profile_.darkMode = on;
    saveProfile();
    applyTheme(on);
  });
  darkModeAction_ = darkMode;
}

void MainWindow::loadProfile() {
  QString err;
  profile_ = Profile::load(Profile::defaultPath(), &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  if (profile_.keyPath.isEmpty()) profile_.keyPath = Profile::defaultKeyPath();
  if (darkModeAction_) darkModeAction_->setChecked(profile_.darkMode);
}

void MainWindow::saveProfile() {
  QString err;
  profile_.save(&err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
}

void MainWindow::applyTheme(bool dark) {
  // Use Fusion for more consistent palettes across platforms.
  QApplication::setStyle(QStyleFactory::create("Fusion"));

  if (!dark) {
    qApp->setPalette(QApplication::style()->standardPalette());
    qApp->setStyleSheet({});
    return;
  }

  QPalette p;
  p.setColor(QPalette::Window, QColor(30, 30, 30));
  p.setColor(QPalette::WindowText, QColor(220, 220, 220));
  p.setColor(QPalette::Base, QColor(20, 20, 20));
  p.setColor(QPalette::AlternateBase, QColor(35, 35, 35));
  p.setColor(QPalette::ToolTipBase, QColor(255, 255, 255));
  p.setColor(QPalette::ToolTipText, QColor(0, 0, 0));
  p.setColor(QPalette::Text, QColor(220, 220, 220));
  p.setColor(QPalette::Button, QColor(45, 45, 45));
  p.setColor(QPalette::ButtonText, QColor(220, 220, 220));
  p.setColor(QPalette::BrightText, Qt::red);
  p.setColor(QPalette::Link, QColor(42, 130, 218));
  p.setColor(QPalette::Highlight, QColor(42, 130, 218));
  p.setColor(QPalette::HighlightedText, QColor(0, 0, 0));

  qApp->setPalette(p);
  // Improve readability for some controls that ignore palette colors (e.g., tooltips).
  qApp->setStyleSheet(
      "QToolTip { color: #000; background-color: #fff; border: 1px solid #aaa; }");
}

void MainWindow::rebuildFriendList() {
  friendList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::None) continue;
    auto* item = new QListWidgetItem(friendDisplay(f) + statusTag(f.status));
    item->setData(Qt::UserRole, f.id);
    if (!f.lastIntro.isEmpty()) item->setToolTip(f.lastIntro);
    friendList_->addItem(item);
  }
  // Restore selection if possible.
  if (!selectedPeerId_.isEmpty()) {
    for (int i = 0; i < friendList_->count(); ++i) {
      if (friendList_->item(i)->data(Qt::UserRole).toString() == selectedPeerId_) {
        friendList_->setCurrentRow(i);
        break;
      }
    }
  }
}

void MainWindow::rebuildFriendsTab() {
  if (!requestsList_) return;
  requestsList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status != Profile::FriendStatus::IncomingPending) continue;
    auto* item = new QListWidgetItem(f.id.left(14) + "…");
    item->setData(Qt::UserRole, f.id);
    if (!f.lastIntro.isEmpty()) item->setToolTip(f.lastIntro);
    requestsList_->addItem(item);
  }
  if (myIdEdit_ && !selfId_.isEmpty()) myIdEdit_->setText(selfId_);
}

void MainWindow::selectFriend(const QString& id) {
  selectedPeerId_ = id;
  refreshHeader();
  chatView_->clear();

  if (!chatCache_.contains(id)) {
    QString err;
    chatCache_[id] = profile_.loadChat(id, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  const auto msgs = chatCache_.value(id);
  const auto* fe = profile_.findFriend(id);
  const auto peerLabel = fe ? friendDisplay(*fe) : id.left(14) + "...";
  for (const auto& m : msgs) {
    const auto who = m.incoming ? peerLabel : "You";
    chatView_->append(renderLine(stampFromUtcMs(m.tsMs), who, m.text));
  }
}

void MainWindow::showChatContextMenu(const QPoint& pos) {
  if (!friendList_) return;
  auto* item = friendList_->itemAt(pos);
  if (!item) return;
  const auto peerId = item->data(Qt::UserRole).toString();
  if (peerId.isEmpty()) return;

  QMenu menu(this);
  auto* profile = menu.addAction("View profile…");
  menu.addSeparator();
  auto* clearChat = menu.addAction("Clear chat history");
  auto* unfriend = menu.addAction("Unfriend / Remove");

  const auto* f = profile_.findFriend(peerId);
  if (f && f->status == Profile::FriendStatus::IncomingPending) {
    unfriend->setText("Reject request");
  } else if (f && f->status == Profile::FriendStatus::OutgoingPending) {
    unfriend->setText("Cancel request");
  }

  auto* chosen = menu.exec(friendList_->viewport()->mapToGlobal(pos));
  if (!chosen) return;
  if (chosen == profile) {
    showProfilePopup(peerId);
    return;
  }
  if (chosen == clearChat) {
    clearChatFor(peerId);
    return;
  }
  if (chosen == unfriend) {
    removeFriend(peerId);
    return;
  }
}

void MainWindow::showProfilePopup(const QString& peerId) {
  const auto* f = profile_.findFriend(peerId);
  const auto display = f ? friendDisplay(*f) : (peerId.left(14) + "...");

  QDialog dlg(this);
  dlg.setWindowTitle("Profile");
  auto* root = new QVBoxLayout(&dlg);
  root->setContentsMargins(10, 10, 10, 10);

  auto* title = new QLabel(display, &dlg);
  title->setStyleSheet("font-weight:600; font-size:15px;");
  root->addWidget(title);

  auto* form = new QFormLayout();

  auto* nameLabel = new QLabel(f ? f->name : QString(), &dlg);
  form->addRow("Name:", nameLabel);

  auto* aliasLabel = new QLabel(f ? f->alias : QString(), &dlg);
  form->addRow("Alias:", aliasLabel);

  auto* statusLabel = new QLabel(f ? Profile::statusToString(f->status) : QString("unknown"), &dlg);
  form->addRow("Status:", statusLabel);

  auto* idRow = new QWidget(&dlg);
  auto* idRowLayout = new QHBoxLayout(idRow);
  idRowLayout->setContentsMargins(0, 0, 0, 0);
  auto* idEdit = new QLineEdit(idRow);
  idEdit->setReadOnly(true);
  idEdit->setText(peerId);
  auto* copyBtn = new QPushButton("Copy", idRow);
  idRowLayout->addWidget(idEdit, 1);
  idRowLayout->addWidget(copyBtn);
  form->addRow("Public key:", idRow);

  if (f && !f->lastIntro.isEmpty()) {
    auto* introLabel = new QLabel(f->lastIntro, &dlg);
    introLabel->setWordWrap(true);
    form->addRow("Intro:", introLabel);
  }

  root->addLayout(form);

  connect(copyBtn, &QPushButton::clicked, this, [peerId] {
    QGuiApplication::clipboard()->setText(peerId);
  });

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
  connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  root->addWidget(buttons);

  dlg.exec();
}

void MainWindow::clearChatFor(const QString& peerId) {
  chatCache_.remove(peerId);
  if (selectedPeerId_ == peerId) chatView_->clear();
  QString err;
  profile_.deleteChat(peerId, &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  statusBar()->showMessage("Chat cleared", 4000);
}

void MainWindow::removeFriend(const QString& peerId) {
  backend_.disconnectPeer(peerId);
  backend_.setFriendAccepted(peerId, false);

  for (int i = 0; i < profile_.friends.size(); ++i) {
    if (profile_.friends[i].id == peerId) {
      profile_.friends.removeAt(i);
      break;
    }
  }
  saveProfile();

  // Keep chat history unless user explicitly clears it.
  chatCache_.remove(peerId);
  if (selectedPeerId_ == peerId) {
    selectedPeerId_.clear();
    chatView_->clear();
    refreshHeader();
  }
  rebuildFriendList();
  rebuildFriendsTab();
  statusBar()->showMessage("Removed", 4000);
}

QString MainWindow::currentPeerId() const {
  return selectedPeerId_;
}

void MainWindow::appendMessage(const QString& peerId, const QString& label, const QString& text, bool incoming) {
  // Best-effort: if we learned a peer name, store it in the profile.
  if (incoming) {
    auto* f = profile_.findFriend(peerId);
    if (f && f->status == Profile::FriendStatus::Accepted) {
      if (!label.isEmpty() && label != peerId && f->name != label) {
        f->name = label;
        saveProfile();
        rebuildFriendList();
        refreshHeader();
      }
    }
  }

  if (!chatCache_.contains(peerId)) {
    QString err;
    chatCache_[peerId] = profile_.loadChat(peerId, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  auto& msgs = chatCache_[peerId];
  Profile::ChatMessage m;
  m.tsMs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
  m.incoming = incoming;
  m.text = text;
  msgs.push_back(m);
  while (msgs.size() > 500) msgs.removeFirst();

  QString err;
  profile_.saveChat(peerId, msgs, &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);

  const auto who = incoming ? label : "You";
  const auto line = renderLine(stampFromUtcMs(m.tsMs), who, text);
  if (peerId == selectedPeerId_) chatView_->append(line);
}

void MainWindow::refreshHeader() {
  if (selectedPeerId_.isEmpty()) {
    headerLabel_->setText("No chat selected");
    return;
  }
  const auto* f = profile_.findFriend(selectedPeerId_);
  const auto title = f ? friendDisplay(*f) : selectedPeerId_.left(14) + "...";
  headerLabel_->setText(title);
}

void MainWindow::addFriendDialog() {
  QDialog dlg(this);
  dlg.setWindowTitle("Add Friend");
  QFormLayout form(&dlg);

  QLineEdit idEdit;
  idEdit.setPlaceholderText("Friend ID (base64url public key)");
  QLineEdit introEdit;
  introEdit.setPlaceholderText("Optional intro");
  form.addRow("ID:", &idEdit);
  form.addRow("Intro:", &introEdit);

  QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  form.addRow(&buttons);
  connect(&buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(&buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

  if (dlg.exec() != QDialog::Accepted) return;
  const auto id = idEdit.text().trimmed();
  if (id.isEmpty()) return;

  Profile::FriendEntry e;
  auto* ex = profile_.findFriend(id);
  if (ex) e = *ex;
  e.id = id;
  if (e.status == Profile::FriendStatus::None) e.status = Profile::FriendStatus::OutgoingPending;
  profile_.upsertFriend(e);
  saveProfile();
  rebuildFriendList();

  backend_.sendFriendRequest(id, introEdit.text().trimmed());
  statusBar()->showMessage("Friend request sent", 5000);
}
