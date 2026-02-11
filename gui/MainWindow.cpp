#include "gui/MainWindow.hpp"

#include <QAction>
#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPainter>
#include <QStyledItemDelegate>
#include <QStyle>
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

#include <functional>

namespace {
constexpr int kRolePeerId = Qt::UserRole;
constexpr int kRoleOnline = Qt::UserRole + 1;

class ClickableLabel final : public QLabel {
public:
  using QLabel::QLabel;
  std::function<void()> onClick;

protected:
  void mousePressEvent(QMouseEvent* ev) override {
    if (onClick) onClick();
    QLabel::mousePressEvent(ev);
  }
};

class PresenceDotDelegate final : public QStyledItemDelegate {
public:
  explicit PresenceDotDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

  void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override {
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);

    const bool selected = (opt.state & QStyle::State_Selected);
    const bool online = index.data(kRoleOnline).toBool();

    const int dot = 10;
    const int margin = 8;

    const int icon = opt.decorationSize.isValid() ? std::min(opt.decorationSize.width(), opt.decorationSize.height()) : 24;
    QRect iconRect = opt.rect;
    iconRect.setLeft(opt.rect.left() + margin);
    iconRect.setRight(iconRect.left() + icon);
    iconRect.setTop(opt.rect.center().y() - icon / 2);
    iconRect.setBottom(iconRect.top() + icon);

    QRect dotRect = opt.rect;
    dotRect.setLeft(dotRect.right() - margin - dot);
    dotRect.setRight(dotRect.left() + dot);
    dotRect.setTop(opt.rect.center().y() - dot / 2);
    dotRect.setBottom(dotRect.top() + dot);

    QRect textRect = opt.rect.adjusted(margin + icon + margin, 0, -(margin + dot + margin), 0);

    // Draw background/selection without text.
    QStyleOptionViewItem bg(opt);
    bg.text.clear();
    bg.icon = QIcon();
    const auto* w = opt.widget;
    QStyle* style = w ? w->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &bg, painter, w);

    painter->save();
    if (!opt.icon.isNull()) {
      opt.icon.paint(painter, iconRect, Qt::AlignCenter, selected ? QIcon::Selected : QIcon::Normal);
    }

    painter->setFont(opt.font);
    painter->setPen(opt.palette.color(selected ? QPalette::HighlightedText : QPalette::Text));
    const QFontMetrics fm(opt.font);
    const auto elided = fm.elidedText(opt.text, Qt::ElideRight, textRect.width());
    painter->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft, elided);

    painter->setRenderHint(QPainter::Antialiasing, true);
    const QColor c = online ? QColor(0, 200, 80) : QColor(120, 120, 120);
    painter->setBrush(c);
    painter->setPen(Qt::NoPen);
    painter->drawEllipse(dotRect);
    painter->restore();
  }
};

QColor colorFromId(const QString& id) {
  // Deterministic color from the peer id.
  uint32_t h = 2166136261u;
  for (const auto ch : id) {
    h ^= static_cast<uint32_t>(ch.unicode());
    h *= 16777619u;
  }
  const int r = 40 + static_cast<int>(h & 0x7F);
  const int g = 40 + static_cast<int>((h >> 8) & 0x7F);
  const int b = 40 + static_cast<int>((h >> 16) & 0x7F);
  return QColor(r, g, b);
}

QPixmap placeholderAvatar(const QString& seed, int size) {
  QPixmap pm(size, size);
  pm.fill(Qt::transparent);
  QPainter p(&pm);
  p.setRenderHint(QPainter::Antialiasing, true);
  p.setPen(Qt::NoPen);
  p.setBrush(colorFromId(seed));
  p.drawEllipse(QRectF(0, 0, size, size));

  QFont f = p.font();
  f.setBold(true);
  f.setPointSize(std::max(10, size / 3));
  p.setFont(f);
  p.setPen(Qt::white);
  const QString letter = seed.isEmpty() ? "?" : seed.left(1).toUpper();
  p.drawText(QRect(0, 0, size, size), Qt::AlignCenter, letter);
  return pm;
}

QPixmap loadAvatarOrPlaceholder(const QString& seed, const QString& path, int size) {
  if (!path.isEmpty() && QFileInfo::exists(path)) {
    QPixmap pm(path);
    if (!pm.isNull()) return pm.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  }
  return placeholderAvatar(seed, size);
}

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
  refreshSelfProfileWidget();

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
            refreshSelfProfileWidget();
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
    // Best-effort: now that both sides are "friends", establish a P2P session to learn the peer name.
    backend_.warmConnect(peerId);
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

  connect(&backend_, &ChatBackend::peerAvatarUpdated, this, [this](QString peerId, QByteArray pngBytes) {
    if (pngBytes.isEmpty()) return;
    QImage img;
    if (!img.loadFromData(pngBytes, "PNG")) return;
    const auto path = Profile::peerAvatarFile(peerId);
    QDir().mkpath(QFileInfo(path).absolutePath());
    (void)img.save(path, "PNG");

    auto* f = profile_.findFriend(peerId);
    if (f && f->avatarPath != path) {
      f->avatarPath = path;
      saveProfile();
    }
    rebuildFriendList();
    refreshHeader();
  });

  connect(&backend_, &ChatBackend::presenceUpdated, this, [this](QString peerId, bool online) {
    online_[peerId] = online;
    for (int i = 0; i < friendList_->count(); ++i) {
      auto* item = friendList_->item(i);
      if (!item) continue;
      if (item->data(kRolePeerId).toString() != peerId) continue;
      item->setData(kRoleOnline, online);
      friendList_->viewport()->update();
      break;
    }
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

  // Load and announce our avatar to peers (P2P only; not via rendezvous).
  if (!profile_.selfAvatarPath.isEmpty() && QFileInfo::exists(profile_.selfAvatarPath)) {
    QImage img(profile_.selfAvatarPath);
    if (!img.isNull()) {
      const QImage wire = img.scaled(96, 96, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QByteArray out;
      QBuffer buf(&out);
      buf.open(QIODevice::WriteOnly);
      (void)wire.save(&buf, "PNG");
      backend_.setSelfAvatarPng(out);
    }
  }

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
  auto* optionsMenu = menuBar()->addMenu("Options");

  auto* addFriend = new QAction("Add Friend...", this);
  connect(addFriend, &QAction::triggered, this, [this] { addFriendDialog(); });
  optionsMenu->addAction(addFriend);

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
    refreshSelfProfileWidget();
    statusBar()->showMessage("Name updated", 6000);
  });
  optionsMenu->addAction(setName);

  auto* darkMode = new QAction("Dark Mode", this);
  darkMode->setCheckable(true);
  optionsMenu->addAction(darkMode);
  optionsMenu->addSeparator();

  auto* quit = new QAction("Quit", this);
  connect(quit, &QAction::triggered, qApp, &QApplication::quit);
  optionsMenu->addAction(quit);

  auto* splitter = new QSplitter(this);

  leftTabs_ = new QTabWidget(splitter);
  leftTabs_->setMinimumWidth(260);

  // Chats tab (list + self profile widget)
  auto* chatsTab = new QWidget(leftTabs_);
  auto* chatsLayout = new QVBoxLayout(chatsTab);
  chatsLayout->setContentsMargins(0, 0, 0, 0);
  chatsLayout->setSpacing(0);

  friendList_ = new QListWidget(chatsTab);
  friendList_->setItemDelegate(new PresenceDotDelegate(friendList_));
  friendList_->setIconSize(QSize(28, 28));
  friendList_->setSpacing(2);
  chatsLayout->addWidget(friendList_, 1);

  auto* selfPanel = new QWidget(chatsTab);
  auto* selfLayout = new QHBoxLayout(selfPanel);
  selfLayout->setContentsMargins(10, 8, 10, 8);
  selfLayout->setSpacing(10);

  myAvatarLabel_ = new ClickableLabel(selfPanel);
  myAvatarLabel_->setFixedSize(48, 48);
  myAvatarLabel_->setCursor(Qt::PointingHandCursor);
  myAvatarLabel_->setToolTip("Click to change profile picture");
  myAvatarLabel_->setScaledContents(true);

  myNameLabel_ = new QLabel(selfPanel);
  myNameLabel_->setStyleSheet("font-weight:600;");

  selfLayout->addWidget(myAvatarLabel_, 0);
  selfLayout->addWidget(myNameLabel_, 1);
  chatsLayout->addWidget(selfPanel, 0);

  leftTabs_->addTab(chatsTab, "Chats");

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
    const auto id = friendList_->item(row)->data(kRolePeerId).toString();
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

  if (auto* clickable = dynamic_cast<ClickableLabel*>(myAvatarLabel_)) {
    clickable->onClick = [this] {
      const auto file = QFileDialog::getOpenFileName(
          this, "Choose profile picture", QDir::homePath(), "Images (*.png *.jpg *.jpeg *.bmp *.gif)");
      if (file.isEmpty()) return;
      QImage img(file);
      if (img.isNull()) {
        QMessageBox::warning(this, "Invalid image", "Could not load the selected image.");
        return;
      }
      // Save a reasonably sized local copy.
      const QImage saved = img.scaled(256, 256, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QDir().mkpath(QFileInfo(Profile::selfAvatarFile()).absolutePath());
      if (!saved.save(Profile::selfAvatarFile(), "PNG")) {
        QMessageBox::warning(this, "Save failed", "Failed to save profile picture.");
        return;
      }
      profile_.selfAvatarPath = Profile::selfAvatarFile();
      saveProfile();
      refreshSelfProfileWidget();

      // Send a smaller version to peers over the encrypted P2P channel.
      const QImage wire = img.scaled(96, 96, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QByteArray out;
      QBuffer buf(&out);
      buf.open(QIODevice::WriteOnly);
      (void)wire.save(&buf, "PNG");
      backend_.setSelfAvatarPng(out);
      statusBar()->showMessage("Profile picture updated", 4000);
    };
  }
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

void MainWindow::refreshSelfProfileWidget() {
  if (myNameLabel_) {
    myNameLabel_->setText(profile_.selfName.isEmpty() ? QString("(no name)") : profile_.selfName);
  }
  if (myAvatarLabel_) {
    const auto seed = selfId_.isEmpty() ? QString("me") : selfId_;
    myAvatarLabel_->setPixmap(loadAvatarOrPlaceholder(seed, profile_.selfAvatarPath, 48));
  }
}

void MainWindow::rebuildFriendList() {
  friendList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::None) continue;
    auto* item = new QListWidgetItem(friendDisplay(f) + statusTag(f.status));
    item->setData(kRolePeerId, f.id);
    item->setData(kRoleOnline, online_.value(f.id, false));
    item->setIcon(QIcon(loadAvatarOrPlaceholder(f.id, f.avatarPath, 28)));
    item->setSizeHint(QSize(0, 46));
    if (!f.lastIntro.isEmpty()) item->setToolTip(f.lastIntro);
    friendList_->addItem(item);
  }
  // Restore selection if possible.
  if (!selectedPeerId_.isEmpty()) {
    for (int i = 0; i < friendList_->count(); ++i) {
      if (friendList_->item(i)->data(kRolePeerId).toString() == selectedPeerId_) {
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
  const auto peerId = item->data(kRolePeerId).toString();
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
  dlg.setMinimumSize(520, 360);
  auto* root = new QVBoxLayout(&dlg);
  root->setContentsMargins(10, 10, 10, 10);

  auto* header = new QWidget(&dlg);
  auto* headerLayout = new QHBoxLayout(header);
  headerLayout->setContentsMargins(0, 0, 0, 0);
  headerLayout->setSpacing(12);

  auto* avatar = new QLabel(header);
  avatar->setFixedSize(96, 96);
  avatar->setScaledContents(true);
  avatar->setPixmap(loadAvatarOrPlaceholder(peerId, f ? f->avatarPath : QString(), 96));
  headerLayout->addWidget(avatar, 0);

  auto* title = new QLabel(display, header);
  title->setStyleSheet("font-weight:600; font-size:16px;");
  title->setWordWrap(true);
  headerLayout->addWidget(title, 1);
  root->addWidget(header);

  auto* form = new QFormLayout();

  auto* nameLabel = new QLabel(f ? f->name : QString(), &dlg);
  form->addRow("Name:", nameLabel);

  auto* aliasLabel = new QLabel(f ? f->alias : QString(), &dlg);
  form->addRow("Alias:", aliasLabel);

  auto* statusLabel = new QLabel(f ? Profile::statusToString(f->status) : QString("unknown"), &dlg);
  form->addRow("Status:", statusLabel);

  auto* keyRow = new QWidget(&dlg);
  auto* keyRowLayout = new QHBoxLayout(keyRow);
  keyRowLayout->setContentsMargins(0, 0, 0, 0);
  auto* keyEdit = new QLineEdit(keyRow);
  keyEdit->setReadOnly(true);
  keyEdit->setText(peerId);
  keyEdit->setCursorPosition(0);
  auto* copyBtn = new QPushButton("Copy", keyRow);
  keyRowLayout->addWidget(keyEdit, 1);
  keyRowLayout->addWidget(copyBtn, 0);
  form->addRow("Public key:", keyRow);

  if (f && !f->lastIntro.isEmpty()) {
    auto* introLabel = new QLabel(f->lastIntro, &dlg);
    introLabel->setWordWrap(true);
    form->addRow("Intro:", introLabel);
  }

  root->addLayout(form);

  connect(copyBtn, &QPushButton::clicked, this, [peerId] { QGuiApplication::clipboard()->setText(peerId); });

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

  QString who = "You";
  if (incoming) {
    const auto* f = profile_.findFriend(peerId);
    who = f ? friendDisplay(*f) : label;
  }
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
