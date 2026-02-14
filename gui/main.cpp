#include "gui/MainWindow.hpp"
#include "gui/ProfileLoginDialog.hpp"
#include "common/identity.hpp"
#include "common/profile_store.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QString>
#include <iostream>
#include <filesystem>

int main(int argc, char** argv) {
  QString configDirArg;
  QString profileArg;
  QString profilePasswordArg;
  bool migrateOnly = false;
  for (int i = 1; i < argc; ++i) {
    const QString arg = QString::fromLocal8Bit(argv[i]);
    if (arg == "--debug") {
      qputenv("P2PCHAT_DEBUG", "1");
    } else if (arg == "--no-debug") {
      qputenv("P2PCHAT_DEBUG", "0");
    } else if (arg == "--config-dir" && i + 1 < argc) {
      configDirArg = QString::fromLocal8Bit(argv[++i]);
    } else if (arg.startsWith("--config-dir=")) {
      configDirArg = arg.mid(QString("--config-dir=").size());
    } else if (arg == "--profile" && i + 1 < argc) {
      profileArg = QString::fromLocal8Bit(argv[++i]).trimmed();
    } else if (arg.startsWith("--profile=")) {
      profileArg = arg.mid(QString("--profile=").size()).trimmed();
    } else if (arg == "--profile-password" && i + 1 < argc) {
      profilePasswordArg = QString::fromLocal8Bit(argv[++i]);
    } else if (arg.startsWith("--profile-password=")) {
      profilePasswordArg = arg.mid(QString("--profile-password=").size());
    } else if (arg == "--migrate-profiles") {
      migrateOnly = true;
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: " << argv[0]
                << " [--debug|--no-debug] [--config-dir <path>] [--profile <name>] [--profile-password <password>] [--migrate-profiles]\n";
      return 0;
    }
  }
  if (!configDirArg.trimmed().isEmpty()) {
    qputenv("P2P_CHAT_CONFIG_DIR", configDirArg.toLocal8Bit());
  }

  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("p2p-chat");
  QCoreApplication::setApplicationName("p2p_chat");

  const auto root = common::profile_store::resolve_root();
  std::string err;
  if (!common::profile_store::ensure_store(root, &err)) {
    QMessageBox::critical(nullptr, "Profile error", QString::fromStdString(err));
    return 1;
  }
  if (migrateOnly) {
    std::cout << "Profile migration complete at " << root.string() << "\n";
    return 0;
  }

  common::profile_store::Index idx;
  if (!common::profile_store::load_index(root, &idx, &err)) {
    QMessageBox::critical(nullptr, "Profile error", QString::fromStdString(err));
    return 1;
  }

  // Always show profile selector on startup.
  if (!profileArg.isEmpty()) {
    const auto found = common::profile_store::find_profile(idx, profileArg.toStdString());
    if (!found.has_value()) {
      QMessageBox::critical(nullptr, "Profile error", "Requested profile was not found.");
      return 1;
    }
    common::profile_store::set_current(root, profileArg.toStdString(), nullptr);
  }

  ProfileLoginDialog dlg(QString::fromStdString(root.string()));
  if (dlg.exec() != QDialog::Accepted || !dlg.selection().has_value()) {
    return 0;
  }
  auto selected = dlg.selection();
  if (selected->encrypted && selected->password.isEmpty() && !profilePasswordArg.isEmpty()) {
    selected->password = profilePasswordArg;
  }
  if (!selected.has_value()) return 0;

  try {
    const auto keyPath =
        (std::filesystem::path(selected->profileDir.toStdString()) / "identity.pem").string();
    (void)common::Identity::load_or_create(keyPath, selected->password.toStdString());
  } catch (const std::exception& e) {
    QMessageBox::critical(nullptr, "Profile error", QString("Failed to load identity: %1").arg(e.what()));
    return 1;
  }

  qputenv("P2P_CHAT_CONFIG_DIR", selected->profileDir.toLocal8Bit());
  qputenv("P2P_CHAT_PROFILE_NAME", selected->name.toLocal8Bit());

  MainWindow w(selected->password);
  w.show();
  return app.exec();
}
