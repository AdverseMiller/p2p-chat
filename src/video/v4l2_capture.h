#pragma once

#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace video {

struct RawFrame {
  uint64_t seq = 0;
  uint64_t monotonicUs = 0;
  uint32_t fourcc = 0;
  uint32_t width = 0;
  uint32_t height = 0;
  std::vector<uint8_t> bytes;
};

struct CaptureConfig {
  QString devicePath;
  uint32_t fourcc = 0;
  uint32_t width = 640;
  uint32_t height = 480;
  uint32_t fpsNum = 1;
  uint32_t fpsDen = 30;
};

class V4L2Capture {
public:
  using FrameCallback = std::function<void(const RawFrame&)>;
  using ErrorCallback = std::function<void(const QString&)>;

  V4L2Capture();
  ~V4L2Capture();

  V4L2Capture(const V4L2Capture&) = delete;
  V4L2Capture& operator=(const V4L2Capture&) = delete;

  bool start(const CaptureConfig& cfg, FrameCallback onFrame, ErrorCallback onError = {});
  void stop();
  bool isRunning() const { return running_.load(); }

private:
  void runLoop(CaptureConfig cfg, FrameCallback onFrame, ErrorCallback onError);

  std::atomic<bool> running_{false};
  std::thread thread_;
};

} // namespace video

