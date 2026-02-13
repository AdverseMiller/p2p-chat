#include "src/video/v4l2_capture.h"

#include "common/util.hpp"

#if defined(__linux__)
#include <linux/videodev2.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#endif

namespace video {

#if !defined(__linux__)
V4L2Capture::V4L2Capture() = default;
V4L2Capture::~V4L2Capture() { stop(); }
bool V4L2Capture::start(const CaptureConfig&, FrameCallback, ErrorCallback onError) {
  if (onError) onError("V4L2 capture is only available on Linux");
  return false;
}
void V4L2Capture::stop() {}
void V4L2Capture::runLoop(CaptureConfig, FrameCallback, ErrorCallback) {}

#else
namespace {

struct MmapBuf {
  void* ptr = MAP_FAILED;
  size_t len = 0;
};

bool xioctl(int fd, unsigned long req, void* arg) {
  for (;;) {
    const int rc = ::ioctl(fd, req, arg);
    if (rc == 0) return true;
    if (errno == EINTR) continue;
    return false;
  }
}

uint64_t monotonic_us() {
  timespec ts {};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000ull + static_cast<uint64_t>(ts.tv_nsec / 1000ull);
}

} // namespace

V4L2Capture::V4L2Capture() = default;

V4L2Capture::~V4L2Capture() { stop(); }

bool V4L2Capture::start(const CaptureConfig& cfg, FrameCallback onFrame, ErrorCallback onError) {
  stop();
  running_ = true;
  thread_ = std::thread([this, cfg, onFrame = std::move(onFrame), onError = std::move(onError)]() mutable {
    runLoop(cfg, std::move(onFrame), std::move(onError));
  });
  return true;
}

void V4L2Capture::stop() {
  running_ = false;
  if (thread_.joinable()) thread_.join();
}

void V4L2Capture::runLoop(CaptureConfig cfg, FrameCallback onFrame, ErrorCallback onError) {
  auto emitError = [&](const QString& msg) {
    if (onError) onError(msg);
    common::log("video: capture error: " + msg.toStdString());
  };

  int fd = ::open(cfg.devicePath.toLocal8Bit().constData(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    emitError(QString("Failed to open %1: %2").arg(cfg.devicePath, QString::fromLocal8Bit(std::strerror(errno))));
    running_ = false;
    return;
  }

  std::vector<MmapBuf> mmaps;
  auto cleanup = [&] {
    if (fd >= 0) {
      v4l2_buf_type t = V4L2_BUF_TYPE_VIDEO_CAPTURE;
      (void)::ioctl(fd, VIDIOC_STREAMOFF, &t);
      t = V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE;
      (void)::ioctl(fd, VIDIOC_STREAMOFF, &t);
    }
    for (auto& mb : mmaps) {
      if (mb.ptr != MAP_FAILED && mb.len > 0) {
        ::munmap(mb.ptr, mb.len);
      }
    }
    mmaps.clear();
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
  };

  v4l2_format fmt {};
  fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  fmt.fmt.pix.width = cfg.width;
  fmt.fmt.pix.height = cfg.height;
  fmt.fmt.pix.pixelformat = cfg.fourcc;
  fmt.fmt.pix.field = V4L2_FIELD_ANY;
  if (!xioctl(fd, VIDIOC_S_FMT, &fmt)) {
    cleanup();
    emitError("VIDIOC_S_FMT failed");
    running_ = false;
    return;
  }
  const uint32_t outW = fmt.fmt.pix.width;
  const uint32_t outH = fmt.fmt.pix.height;
  const uint32_t outFourcc = fmt.fmt.pix.pixelformat;

  v4l2_streamparm parm {};
  parm.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  parm.parm.capture.timeperframe.numerator = cfg.fpsNum ? cfg.fpsNum : 1;
  parm.parm.capture.timeperframe.denominator = cfg.fpsDen ? cfg.fpsDen : 30;
  (void)xioctl(fd, VIDIOC_S_PARM, &parm);

  v4l2_requestbuffers req {};
  req.count = 4;
  req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  req.memory = V4L2_MEMORY_MMAP;
  if (!xioctl(fd, VIDIOC_REQBUFS, &req) || req.count == 0) {
    cleanup();
    emitError("VIDIOC_REQBUFS failed");
    running_ = false;
    return;
  }
  mmaps.resize(req.count);

  for (uint32_t i = 0; i < req.count; ++i) {
    v4l2_buffer b {};
    b.type = req.type;
    b.memory = V4L2_MEMORY_MMAP;
    b.index = i;
    if (!xioctl(fd, VIDIOC_QUERYBUF, &b)) {
      cleanup();
      emitError("VIDIOC_QUERYBUF failed");
      running_ = false;
      return;
    }
    void* p = ::mmap(nullptr, b.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, b.m.offset);
    if (p == MAP_FAILED) {
      cleanup();
      emitError("mmap failed");
      running_ = false;
      return;
    }
    mmaps[i] = MmapBuf{p, b.length};
  }

  for (uint32_t i = 0; i < req.count; ++i) {
    v4l2_buffer b {};
    b.type = req.type;
    b.memory = V4L2_MEMORY_MMAP;
    b.index = i;
    if (!xioctl(fd, VIDIOC_QBUF, &b)) {
      cleanup();
      emitError("VIDIOC_QBUF failed");
      running_ = false;
      return;
    }
  }

  v4l2_buf_type t = static_cast<v4l2_buf_type>(req.type);
  if (!xioctl(fd, VIDIOC_STREAMON, &t)) {
    cleanup();
    emitError("VIDIOC_STREAMON failed");
    running_ = false;
    return;
  }

  uint64_t seq = 0;
  while (running_.load()) {
    pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int prc = ::poll(&pfd, 1, 200);
    if (prc < 0) {
      if (errno == EINTR) continue;
      emitError(QString("poll failed: %1").arg(QString::fromLocal8Bit(std::strerror(errno))));
      break;
    }
    if (prc == 0) continue;
    if ((pfd.revents & POLLIN) == 0) continue;

    v4l2_buffer b {};
    b.type = req.type;
    b.memory = V4L2_MEMORY_MMAP;
    if (!xioctl(fd, VIDIOC_DQBUF, &b)) {
      if (errno == EAGAIN) continue;
      emitError(QString("VIDIOC_DQBUF failed: %1").arg(QString::fromLocal8Bit(std::strerror(errno))));
      break;
    }
    if (b.index < mmaps.size() && b.bytesused > 0 && mmaps[b.index].ptr != MAP_FAILED) {
      RawFrame rf;
      rf.seq = seq++;
      rf.monotonicUs = monotonic_us();
      rf.fourcc = outFourcc;
      rf.width = outW;
      rf.height = outH;
      rf.bytes.resize(static_cast<size_t>(b.bytesused));
      std::memcpy(rf.bytes.data(), mmaps[b.index].ptr, rf.bytes.size());
      if (onFrame) onFrame(rf);
    }

    if (!xioctl(fd, VIDIOC_QBUF, &b)) {
      emitError("VIDIOC_QBUF failed in capture loop");
      break;
    }
  }

  cleanup();
  running_ = false;
}
#endif

} // namespace video
