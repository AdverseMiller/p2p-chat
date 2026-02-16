#pragma once

#include <QImage>
#include <QString>

#include <cstdint>

namespace video {

class X11ShmCapture {
public:
  X11ShmCapture() = default;
  ~X11ShmCapture();

  X11ShmCapture(const X11ShmCapture&) = delete;
  X11ShmCapture& operator=(const X11ShmCapture&) = delete;

  bool open(int x, int y, int width, int height, QString* err = nullptr);
  bool grab(QImage* out, QString* err = nullptr);
  void close();
  bool isOpen() const { return open_; }

private:
  struct Impl;
  Impl* impl_ = nullptr;
  bool open_ = false;
};

} // namespace video
