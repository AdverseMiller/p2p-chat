#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QString>
#include <iostream>

int main(int argc, char** argv) {
  QString configDirArg;
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
    } else if (arg == "--help" || arg == "-h") {
      std::cout << "Usage: " << argv[0]
                << " [--debug|--no-debug] [--config-dir <path>]\n";
      return 0;
    }
  }
  if (!configDirArg.trimmed().isEmpty()) {
    qputenv("P2P_CHAT_CONFIG_DIR", configDirArg.toLocal8Bit());
  }

  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("p2p-chat");
  QCoreApplication::setApplicationName("p2p_chat");
  MainWindow w;
  w.show();
  return app.exec();
}
