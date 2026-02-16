#include "src/video/x11_shm_capture.h"

#if defined(__linux__)
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XShm.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include <cstring>
#endif

namespace video {

#if defined(__linux__)
struct X11ShmCapture::Impl {
  Display* display = nullptr;
  Window root = 0;
  XImage* image = nullptr;
  XShmSegmentInfo shm {};
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;
  bool shmAttached = false;
};
#endif

X11ShmCapture::~X11ShmCapture() { close(); }

bool X11ShmCapture::open(int x, int y, int width, int height, QString* err) {
  close();
#if !defined(__linux__)
  if (err) *err = "X11 SHM capture is only supported on Linux";
  return false;
#else
  if (width <= 0 || height <= 0) {
    if (err) *err = "invalid capture size";
    return false;
  }

  impl_ = new Impl();
  impl_->display = XOpenDisplay(nullptr);
  if (!impl_->display) {
    if (err) *err = "XOpenDisplay failed";
    close();
    return false;
  }
  if (!XShmQueryExtension(impl_->display)) {
    if (err) *err = "XShm extension unavailable";
    close();
    return false;
  }

  const int screen = DefaultScreen(impl_->display);
  impl_->root = RootWindow(impl_->display, screen);
  XWindowAttributes wa {};
  if (!XGetWindowAttributes(impl_->display, impl_->root, &wa)) {
    if (err) *err = "XGetWindowAttributes failed";
    close();
    return false;
  }

  impl_->x = std::max(0, x);
  impl_->y = std::max(0, y);
  impl_->width = std::min(width, std::max(1, wa.width - impl_->x));
  impl_->height = std::min(height, std::max(1, wa.height - impl_->y));

  impl_->image = XShmCreateImage(impl_->display,
                                 DefaultVisual(impl_->display, screen),
                                 static_cast<unsigned>(DefaultDepth(impl_->display, screen)),
                                 ZPixmap,
                                 nullptr,
                                 &impl_->shm,
                                 static_cast<unsigned>(impl_->width),
                                 static_cast<unsigned>(impl_->height));
  if (!impl_->image) {
    if (err) *err = "XShmCreateImage failed";
    close();
    return false;
  }

  const std::size_t bytes = static_cast<std::size_t>(impl_->image->bytes_per_line) *
                            static_cast<std::size_t>(impl_->image->height);
  impl_->shm.shmid = shmget(IPC_PRIVATE, bytes, IPC_CREAT | 0600);
  if (impl_->shm.shmid < 0) {
    if (err) *err = "shmget failed";
    close();
    return false;
  }
  impl_->shm.shmaddr = static_cast<char*>(shmat(impl_->shm.shmid, nullptr, 0));
  if (impl_->shm.shmaddr == reinterpret_cast<char*>(-1)) {
    impl_->shm.shmaddr = nullptr;
    if (err) *err = "shmat failed";
    close();
    return false;
  }
  impl_->shm.readOnly = False;
  impl_->image->data = impl_->shm.shmaddr;
  if (!XShmAttach(impl_->display, &impl_->shm)) {
    if (err) *err = "XShmAttach failed";
    close();
    return false;
  }
  impl_->shmAttached = true;
  XSync(impl_->display, False);
  // Mark for deletion once detached.
  shmctl(impl_->shm.shmid, IPC_RMID, nullptr);

  open_ = true;
  return true;
#endif
}

bool X11ShmCapture::grab(QImage* out, QString* err) {
  if (!out) return false;
#if !defined(__linux__)
  if (err) *err = "unsupported platform";
  return false;
#else
  if (!open_ || !impl_ || !impl_->display || !impl_->image) {
    if (err) *err = "capture not open";
    return false;
  }
  if (!XShmGetImage(impl_->display, impl_->root, impl_->image, impl_->x, impl_->y, AllPlanes)) {
    if (err) *err = "XShmGetImage failed";
    return false;
  }
  QImage view(reinterpret_cast<const uchar*>(impl_->image->data),
              impl_->image->width,
              impl_->image->height,
              impl_->image->bytes_per_line,
              QImage::Format_RGB32);
  *out = view.copy();
  return !out->isNull();
#endif
}

void X11ShmCapture::close() {
#if defined(__linux__)
  if (!impl_) {
    open_ = false;
    return;
  }
  if (impl_->display && impl_->shmAttached) {
    XShmDetach(impl_->display, &impl_->shm);
    XSync(impl_->display, False);
    impl_->shmAttached = false;
  }
  if (impl_->image) {
    // Prevent XDestroyImage from attempting free() on shared memory.
    impl_->image->data = nullptr;
    XDestroyImage(impl_->image);
    impl_->image = nullptr;
  }
  if (impl_->shm.shmaddr) {
    shmdt(impl_->shm.shmaddr);
    impl_->shm.shmaddr = nullptr;
  }
  if (impl_->display) {
    XCloseDisplay(impl_->display);
    impl_->display = nullptr;
  }
  delete impl_;
  impl_ = nullptr;
#endif
  open_ = false;
}

} // namespace video
