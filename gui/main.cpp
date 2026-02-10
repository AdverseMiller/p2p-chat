#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QCoreApplication>

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  QCoreApplication::setOrganizationName("p2p-chat");
  QCoreApplication::setApplicationName("p2p_chat");
  MainWindow w;
  w.show();
  return app.exec();
}
