#pragma once

#include <QDialog>
#include <QString>

#include <optional>

class QCheckBox;
class QComboBox;
class QLineEdit;

struct ProfileSelection {
  QString name;
  QString profileDir;
  QString password;
  bool encrypted = false;
};

class ProfileLoginDialog final : public QDialog {
  Q_OBJECT
public:
  explicit ProfileLoginDialog(QString rootDir, QWidget* parent = nullptr);

  std::optional<ProfileSelection> selection() const { return selected_; }

private:
  void loadProfiles();
  void updateLoginUi();
  void onLogin();
  void onCreateProfile();

  QString rootDir_;

  QComboBox* profileCombo_ = nullptr;
  QLineEdit* passwordEdit_ = nullptr;

  QLineEdit* createNameEdit_ = nullptr;
  QCheckBox* createEncryptedCheck_ = nullptr;
  QLineEdit* createPasswordEdit_ = nullptr;
  QLineEdit* createPasswordConfirmEdit_ = nullptr;

  std::optional<ProfileSelection> selected_;
};

