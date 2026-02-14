#include "gui/ProfileLoginDialog.hpp"

#include "common/identity.hpp"
#include "common/profile_store.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTabWidget>
#include <QVBoxLayout>

#include <filesystem>

namespace {
QString to_qs(const std::string& v) { return QString::fromStdString(v); }
std::string to_std(const QString& v) { return v.toStdString(); }

} // namespace

ProfileLoginDialog::ProfileLoginDialog(QString rootDir, QWidget* parent)
    : QDialog(parent), rootDir_(std::move(rootDir)) {
  setWindowTitle("Select Profile");
  setModal(true);
  resize(440, 280);

  auto* outer = new QVBoxLayout(this);
  auto* tabs = new QTabWidget(this);
  outer->addWidget(tabs, 1);

  auto* loginTab = new QWidget(tabs);
  auto* loginForm = new QFormLayout(loginTab);
  profileCombo_ = new QComboBox(loginTab);
  passwordEdit_ = new QLineEdit(loginTab);
  passwordEdit_->setEchoMode(QLineEdit::Password);
  passwordEdit_->setPlaceholderText("Password (if encrypted)");
  loginForm->addRow("Profile:", profileCombo_);
  loginForm->addRow("Password:", passwordEdit_);
  tabs->addTab(loginTab, "Login");

  auto* createTab = new QWidget(tabs);
  auto* createForm = new QFormLayout(createTab);
  createNameEdit_ = new QLineEdit(createTab);
  createNameEdit_->setPlaceholderText("Profile name");
  createEncryptedCheck_ = new QCheckBox("Encrypt profile key with password", createTab);
  createPasswordEdit_ = new QLineEdit(createTab);
  createPasswordEdit_->setEchoMode(QLineEdit::Password);
  createPasswordConfirmEdit_ = new QLineEdit(createTab);
  createPasswordConfirmEdit_->setEchoMode(QLineEdit::Password);
  createForm->addRow("Name:", createNameEdit_);
  createForm->addRow("", createEncryptedCheck_);
  createForm->addRow("Password:", createPasswordEdit_);
  createForm->addRow("Confirm:", createPasswordConfirmEdit_);
  tabs->addTab(createTab, "Create");

  auto* buttons = new QDialogButtonBox(this);
  auto* loginBtn = buttons->addButton("Login", QDialogButtonBox::AcceptRole);
  auto* createBtn = buttons->addButton("Create", QDialogButtonBox::ActionRole);
  auto* cancelBtn = buttons->addButton(QDialogButtonBox::Cancel);
  outer->addWidget(buttons);

  connect(cancelBtn, &QPushButton::clicked, this, &QDialog::reject);
  connect(loginBtn, &QPushButton::clicked, this, &ProfileLoginDialog::onLogin);
  connect(createBtn, &QPushButton::clicked, this, &ProfileLoginDialog::onCreateProfile);
  connect(profileCombo_, &QComboBox::currentIndexChanged, this, [this] { updateLoginUi(); });
  connect(createEncryptedCheck_, &QCheckBox::toggled, this, [this](bool on) {
    createPasswordEdit_->setEnabled(on);
    createPasswordConfirmEdit_->setEnabled(on);
    if (!on) {
      createPasswordEdit_->clear();
      createPasswordConfirmEdit_->clear();
    }
  });

  createPasswordEdit_->setEnabled(false);
  createPasswordConfirmEdit_->setEnabled(false);

  loadProfiles();
}

void ProfileLoginDialog::loadProfiles() {
  profileCombo_->clear();

  std::string err;
  const auto root = std::filesystem::path(rootDir_.toStdString());
  if (!common::profile_store::ensure_store(root, &err)) {
    QMessageBox::critical(this, "Profile error", QString::fromStdString(err));
    return;
  }

  common::profile_store::Index idx;
  if (!common::profile_store::load_index(root, &idx, &err)) {
    QMessageBox::critical(this, "Profile error", QString::fromStdString(err));
    return;
  }

  int selected = -1;
  for (std::size_t i = 0; i < idx.profiles.size(); ++i) {
    const auto& p = idx.profiles[i];
    const QString label = p.encrypted ? QString("%1 🔒").arg(to_qs(p.name)) : to_qs(p.name);
    profileCombo_->addItem(label);
    profileCombo_->setItemData(static_cast<int>(i), to_qs(p.name), Qt::UserRole);
    profileCombo_->setItemData(static_cast<int>(i), to_qs(p.rel_dir), Qt::UserRole + 1);
    profileCombo_->setItemData(static_cast<int>(i), p.encrypted, Qt::UserRole + 2);
    if (!idx.current.empty() && p.name == idx.current) {
      selected = static_cast<int>(i);
    }
  }
  if (selected >= 0) profileCombo_->setCurrentIndex(selected);
  updateLoginUi();
}

void ProfileLoginDialog::updateLoginUi() {
  const bool ok = profileCombo_->count() > 0 && profileCombo_->currentIndex() >= 0;
  passwordEdit_->setEnabled(ok);
  if (!ok) {
    passwordEdit_->setPlaceholderText("No profiles yet. Create one.");
    return;
  }
  const bool encrypted = profileCombo_->currentData(Qt::UserRole + 2).toBool();
  passwordEdit_->setPlaceholderText(encrypted ? "Password required" : "Password (not required)");
}

void ProfileLoginDialog::onLogin() {
  if (profileCombo_->count() == 0 || profileCombo_->currentIndex() < 0) {
    QMessageBox::warning(this, "No profile", "Create a profile first.");
    return;
  }

  const QString name = profileCombo_->currentData(Qt::UserRole).toString();
  const QString rel = profileCombo_->currentData(Qt::UserRole + 1).toString();
  const bool encrypted = profileCombo_->currentData(Qt::UserRole + 2).toBool();
  const QString password = passwordEdit_->text();
  if (encrypted && password.isEmpty()) {
    QMessageBox::warning(this, "Password required", "This profile is encrypted. Enter its password.");
    return;
  }

  const auto profileDir = std::filesystem::path(rootDir_.toStdString()) / rel.toStdString();
  const auto keyPath = profileDir / "identity.pem";
  try {
    (void)common::Identity::load_or_create(keyPath.string(), password.toStdString());
  } catch (const std::exception& e) {
    QMessageBox::critical(this, "Login failed", QString("Failed to load identity: %1").arg(e.what()));
    return;
  }

  std::string err;
  (void)common::profile_store::set_current(std::filesystem::path(rootDir_.toStdString()),
                                           name.toStdString(),
                                           &err);

  selected_ = ProfileSelection{name, QString::fromStdString(profileDir.string()), password, encrypted};
  accept();
}

void ProfileLoginDialog::onCreateProfile() {
  const QString name = createNameEdit_->text().trimmed();
  if (name.isEmpty()) {
    QMessageBox::warning(this, "Invalid name", "Profile name cannot be empty.");
    return;
  }
  if (name.size() > 64) {
    QMessageBox::warning(this, "Invalid name", "Profile name must be at most 64 characters.");
    return;
  }

  const bool encrypted = createEncryptedCheck_->isChecked();
  const QString password = createPasswordEdit_->text();
  const QString confirm = createPasswordConfirmEdit_->text();
  if (encrypted) {
    if (password.size() < 6) {
      QMessageBox::warning(this, "Weak password", "Use at least 6 characters.");
      return;
    }
    if (password != confirm) {
      QMessageBox::warning(this, "Mismatch", "Passwords do not match.");
      return;
    }
  }

  common::profile_store::Entry created;
  std::string err;
  const auto root = std::filesystem::path(rootDir_.toStdString());
  if (!common::profile_store::create_profile(root,
                                             name.toStdString(),
                                             encrypted,
                                             &created,
                                             &err)) {
    QMessageBox::critical(this, "Create failed", QString::fromStdString(err));
    return;
  }

  const auto profileDir = common::profile_store::profile_dir(root, created);
  const auto keyPath = profileDir / "identity.pem";
  try {
    (void)common::Identity::load_or_create(keyPath.string(), password.toStdString());
  } catch (const std::exception& e) {
    QMessageBox::critical(this, "Create failed", QString("Failed to create identity: %1").arg(e.what()));
    return;
  }

  selected_ = ProfileSelection{QString::fromStdString(created.name),
                               QString::fromStdString(profileDir.string()),
                               password,
                               created.encrypted};
  accept();
}
