#include "gui/MainWindow.hpp"

#include <QAction>
#include <QApplication>
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
#include <QMessageBox>
#include <QPushButton>
#include <QStatusBar>
#include <QSplitter>
#include <QTextBrowser>
#include <QVBoxLayout>

namespace {
QString nowStamp() {
  return QDateTime::currentDateTime().toString("HH:mm");
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

  connect(&backend_, &ChatBackend::registered, this,
          [this](QString selfId, bool reachable, QString observedIp, quint16 externalPort) {
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

            const auto text = intro.isEmpty() ? QString("Friend request from %1").arg(fromId)
                                              : QString("Friend request from %1:\n%2").arg(fromId, intro);
            const auto r = QMessageBox::question(this, "Friend request", text, QMessageBox::Yes | QMessageBox::No);
            if (r == QMessageBox::Yes) {
              backend_.acceptFriend(fromId);
              auto* f2 = profile_.findFriend(fromId);
              if (f2) f2->status = Profile::FriendStatus::Accepted;
              saveProfile();
              rebuildFriendList();
              backend_.setFriendAccepted(fromId, true);
            }
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
    backend_.setFriendAccepted(peerId, true);
  });

  connect(&backend_, &ChatBackend::messageReceived, this,
          [this](QString peerId, QString displayName, QString text, bool incoming) {
            appendMessage(peerId, displayName, text, incoming);
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

  friendList_ = new QListWidget(splitter);
  friendList_->setMinimumWidth(200);

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
}

void MainWindow::loadProfile() {
  QString err;
  profile_ = Profile::load(Profile::defaultPath(), &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  if (profile_.keyPath.isEmpty()) profile_.keyPath = Profile::defaultKeyPath();
}

void MainWindow::saveProfile() {
  QString err;
  profile_.save(&err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
}

void MainWindow::rebuildFriendList() {
  friendList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::None) continue;
    auto* item = new QListWidgetItem(friendDisplay(f) + statusTag(f.status));
    item->setData(Qt::UserRole, f.id);
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

void MainWindow::selectFriend(const QString& id) {
  selectedPeerId_ = id;
  refreshHeader();
  chatView_->clear();
  const auto msgs = chatCache_.value(id);
  for (const auto& m : msgs) chatView_->append(m);
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
  const auto prefix = incoming ? label : "You";
  const auto line = QString("[%1] <b>%2</b>: %3").arg(nowStamp(), prefix.toHtmlEscaped(), text.toHtmlEscaped());
  chatCache_[peerId].push_back(line);
  if (chatCache_[peerId].size() > 500) chatCache_[peerId].removeFirst();
  if (peerId == selectedPeerId_) chatView_->append(line);
}

void MainWindow::refreshHeader() {
  if (selectedPeerId_.isEmpty()) {
    headerLabel_->setText("No chat selected");
    return;
  }
  const auto* f = profile_.findFriend(selectedPeerId_);
  const auto title = f ? friendDisplay(*f) : selectedPeerId_.left(14) + "...";
  headerLabel_->setText(title + "  (" + selectedPeerId_.left(10) + "…)");
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
