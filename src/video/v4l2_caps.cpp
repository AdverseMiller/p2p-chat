#include "src/video/v4l2_caps.h"

#include "common/util.hpp"

#if defined(__linux__)
#include <linux/videodev2.h>

#include <QDir>
#include <QFileInfo>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <set>
#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace video {

double Fps::value() const {
  if (num == 0) return 0.0;
  return static_cast<double>(den) / static_cast<double>(num);
}

QString fourccToString(uint32_t fourcc) {
  std::array<char, 5> s{};
  s[0] = static_cast<char>(fourcc & 0xFF);
  s[1] = static_cast<char>((fourcc >> 8) & 0xFF);
  s[2] = static_cast<char>((fourcc >> 16) & 0xFF);
  s[3] = static_cast<char>((fourcc >> 24) & 0xFF);
  s[4] = '\0';
  for (int i = 0; i < 4; ++i) {
    if (static_cast<unsigned char>(s[i]) < 32 || static_cast<unsigned char>(s[i]) > 126) s[i] = '?';
  }
  return QString::fromLatin1(s.data(), 4);
}

#if !defined(__linux__)
std::vector<DeviceInfo> listVideoDevices() { return {}; }
DeviceCaps queryDeviceCaps(const QString& devPath) {
  DeviceCaps out;
  out.path = devPath;
  return out;
}
#else
namespace {

class Fd {
public:
  explicit Fd(int fd = -1) : fd_(fd) {}
  ~Fd() {
    if (fd_ >= 0) ::close(fd_);
  }
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
  Fd& operator=(Fd&& other) noexcept {
    if (this == &other) return *this;
    if (fd_ >= 0) ::close(fd_);
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }
  int get() const { return fd_; }
  explicit operator bool() const { return fd_ >= 0; }

private:
  int fd_;
};

bool xioctl(int fd, unsigned long req, void* arg) {
  for (;;) {
    const int rc = ::ioctl(fd, req, arg);
    if (rc == 0) return true;
    if (errno == EINTR) continue;
    return false;
  }
}

std::vector<std::pair<uint32_t, uint32_t>> sample_stepwise_sizes(const v4l2_frmsize_stepwise& s) {
  std::vector<std::pair<uint32_t, uint32_t>> out;
  if (s.min_width == 0 || s.min_height == 0) return out;
  if (s.max_width < s.min_width || s.max_height < s.min_height) return out;

  const uint32_t step_w = s.step_width ? s.step_width : 1;
  const uint32_t step_h = s.step_height ? s.step_height : 1;

  const uint32_t count_w = ((s.max_width - s.min_width) / step_w) + 1;
  const uint32_t count_h = ((s.max_height - s.min_height) / step_h) + 1;
  const uint32_t target = 15;
  const uint32_t n = std::min<uint32_t>(target, std::max<uint32_t>(1, std::max(count_w, count_h)));

  for (uint32_t i = 0; i < n; ++i) {
    const double t = (n == 1) ? 0.0 : static_cast<double>(i) / static_cast<double>(n - 1);
    auto round_to_step = [](uint32_t min_v, uint32_t max_v, uint32_t step_v, double ratio) {
      const double raw = static_cast<double>(min_v) + static_cast<double>(max_v - min_v) * ratio;
      uint32_t v = static_cast<uint32_t>(std::llround(raw));
      if (v < min_v) v = min_v;
      if (v > max_v) v = max_v;
      const uint32_t off = (v - min_v) / step_v;
      v = min_v + off * step_v;
      if (v > max_v) v = max_v;
      return v;
    };
    const uint32_t w = round_to_step(s.min_width, s.max_width, step_w, t);
    const uint32_t h = round_to_step(s.min_height, s.max_height, step_h, t);
    out.emplace_back(w, h);
  }

  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}

std::vector<Fps> sample_stepwise_fps(const v4l2_frmival_stepwise& s) {
  std::vector<Fps> out;
  if (s.min.numerator == 0 || s.min.denominator == 0 || s.max.numerator == 0 || s.max.denominator == 0) return out;

  const double min_s = static_cast<double>(s.min.numerator) / static_cast<double>(s.min.denominator);
  const double max_s = static_cast<double>(s.max.numerator) / static_cast<double>(s.max.denominator);
  if (!(min_s > 0.0) || !(max_s > 0.0)) return out;

  const int n = 10;
  for (int i = 0; i < n; ++i) {
    const double t = (n == 1) ? 0.0 : static_cast<double>(i) / static_cast<double>(n - 1);
    const double sec = min_s + (max_s - min_s) * t;
    if (sec <= 0.0) continue;
    const double fps = 1.0 / sec;
    if (fps <= 0.0) continue;
    Fps f;
    f.den = static_cast<uint32_t>(std::llround(fps * 1000.0));
    f.num = 1000;
    out.push_back(f);
  }
  std::sort(out.begin(), out.end(), [](const Fps& a, const Fps& b) { return a.value() < b.value(); });
  out.erase(std::unique(out.begin(),
                        out.end(),
                        [](const Fps& a, const Fps& b) {
                          return std::abs(a.value() - b.value()) < 0.25;
                        }),
            out.end());
  return out;
}

std::vector<Fps> enumerate_fps(int fd, uint32_t fourcc, uint32_t width, uint32_t height) {
  std::vector<Fps> out;
  std::set<std::pair<uint32_t, uint32_t>> seen;
  for (uint32_t idx = 0;; ++idx) {
    v4l2_frmivalenum fi {};
    fi.index = idx;
    fi.pixel_format = fourcc;
    fi.width = width;
    fi.height = height;
    if (!xioctl(fd, VIDIOC_ENUM_FRAMEINTERVALS, &fi)) break;

    if (fi.type == V4L2_FRMIVAL_TYPE_DISCRETE) {
      const auto key = std::make_pair(fi.discrete.numerator, fi.discrete.denominator);
      if (!seen.insert(key).second) continue;
      out.push_back(Fps{fi.discrete.numerator, fi.discrete.denominator});
      continue;
    }
    if (fi.type == V4L2_FRMIVAL_TYPE_STEPWISE || fi.type == V4L2_FRMIVAL_TYPE_CONTINUOUS) {
      for (const auto& fps : sample_stepwise_fps(fi.stepwise)) {
        const auto key = std::make_pair(fps.num, fps.den);
        if (!seen.insert(key).second) continue;
        out.push_back(fps);
      }
    }
  }

  if (out.empty()) out.push_back(Fps{1, 30});
  std::sort(out.begin(), out.end(), [](const Fps& a, const Fps& b) { return a.value() < b.value(); });
  return out;
}

std::vector<FrameSizeCaps> enumerate_sizes(int fd, uint32_t fourcc) {
  std::vector<FrameSizeCaps> out;
  std::set<std::pair<uint32_t, uint32_t>> seen;
  for (uint32_t idx = 0;; ++idx) {
    v4l2_frmsizeenum fs {};
    fs.index = idx;
    fs.pixel_format = fourcc;
    if (!xioctl(fd, VIDIOC_ENUM_FRAMESIZES, &fs)) break;

    if (fs.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
      const uint32_t w = fs.discrete.width;
      const uint32_t h = fs.discrete.height;
      if (w == 0 || h == 0) continue;
      if (!seen.insert({w, h}).second) continue;
      FrameSizeCaps caps;
      caps.width = w;
      caps.height = h;
      caps.fps = enumerate_fps(fd, fourcc, w, h);
      out.push_back(std::move(caps));
      continue;
    }
    if (fs.type == V4L2_FRMSIZE_TYPE_STEPWISE || fs.type == V4L2_FRMSIZE_TYPE_CONTINUOUS) {
      for (const auto& [w, h] : sample_stepwise_sizes(fs.stepwise)) {
        if (w == 0 || h == 0) continue;
        if (!seen.insert({w, h}).second) continue;
        FrameSizeCaps caps;
        caps.width = w;
        caps.height = h;
        caps.fps = enumerate_fps(fd, fourcc, w, h);
        out.push_back(std::move(caps));
      }
    }
  }

  std::sort(out.begin(), out.end(), [](const FrameSizeCaps& a, const FrameSizeCaps& b) {
    if (a.width != b.width) return a.width < b.width;
    return a.height < b.height;
  });
  return out;
}

void enumerate_formats_for_type(int fd, uint32_t type, std::vector<FormatCaps>* out) {
  std::set<uint32_t> seen_fmt;
  for (uint32_t idx = 0;; ++idx) {
    v4l2_fmtdesc d {};
    d.index = idx;
    d.type = type;
    if (!xioctl(fd, VIDIOC_ENUM_FMT, &d)) break;
    if (!seen_fmt.insert(d.pixelformat).second) continue;

    FormatCaps fc;
    fc.fourcc = d.pixelformat;
    fc.fourccStr = fourccToString(d.pixelformat);
    fc.description = QString::fromLocal8Bit(reinterpret_cast<const char*>(d.description));
    fc.sizes = enumerate_sizes(fd, d.pixelformat);
    out->push_back(std::move(fc));
  }
}

} // namespace

std::vector<DeviceInfo> listVideoDevices() {
  std::vector<DeviceInfo> out;
  const QDir devDir("/dev");
  const auto entries = devDir.entryInfoList(QStringList() << "video*", QDir::System | QDir::Readable | QDir::Files, QDir::Name);
  for (const auto& fi : entries) {
    const auto path = fi.absoluteFilePath();
    Fd fd(::open(path.toLocal8Bit().constData(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (!fd) continue;

    v4l2_capability cap {};
    if (!xioctl(fd.get(), VIDIOC_QUERYCAP, &cap)) continue;
    const bool is_capture =
        (cap.device_caps & (V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE)) != 0 ||
        ((cap.capabilities & V4L2_CAP_DEVICE_CAPS) == 0 &&
         (cap.capabilities & (V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE)) != 0);
    if (!is_capture) continue;

    DeviceInfo info;
    info.path = path;
    info.name = QString::fromLocal8Bit(reinterpret_cast<const char*>(cap.card));
    out.push_back(std::move(info));
  }
  std::sort(out.begin(), out.end(), [](const DeviceInfo& a, const DeviceInfo& b) { return a.path < b.path; });
  return out;
}

DeviceCaps queryDeviceCaps(const QString& devPath) {
  DeviceCaps out;
  out.path = devPath;
  Fd fd(::open(devPath.toLocal8Bit().constData(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
  if (!fd) {
    common::log("video: failed to open " + devPath.toStdString() + ": " + std::strerror(errno));
    return out;
  }

  v4l2_capability cap {};
  if (!xioctl(fd.get(), VIDIOC_QUERYCAP, &cap)) {
    common::log("video: VIDIOC_QUERYCAP failed for " + devPath.toStdString());
    return out;
  }
  out.name = QString::fromLocal8Bit(reinterpret_cast<const char*>(cap.card));

  const uint32_t caps = (cap.capabilities & V4L2_CAP_DEVICE_CAPS) ? cap.device_caps : cap.capabilities;
  out.capture = (caps & (V4L2_CAP_VIDEO_CAPTURE | V4L2_CAP_VIDEO_CAPTURE_MPLANE)) != 0;
  if (!out.capture) return out;

  enumerate_formats_for_type(fd.get(), V4L2_BUF_TYPE_VIDEO_CAPTURE, &out.formats);
  enumerate_formats_for_type(fd.get(), V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, &out.formats);

  std::sort(out.formats.begin(), out.formats.end(), [](const FormatCaps& a, const FormatCaps& b) {
    if (a.description != b.description) return a.description < b.description;
    return a.fourcc < b.fourcc;
  });
  out.formats.erase(std::unique(out.formats.begin(),
                                out.formats.end(),
                                [](const FormatCaps& a, const FormatCaps& b) { return a.fourcc == b.fourcc; }),
                    out.formats.end());
  return out;
}
#endif

} // namespace video

