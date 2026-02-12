#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QString>

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const QString arg = QString::fromLocal8Bit(argv[i]);
    if (arg == "--debug") {
      qputenv("P2PCHAT_DEBUG", "1");
    } else if (arg == "--no-debug") {
      qputenv("P2PCHAT_DEBUG", "0");
    }
  }

  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("p2p-chat");
  QCoreApplication::setApplicationName("p2p_chat");
  MainWindow w;
  w.show();
  return app.exec();
}
