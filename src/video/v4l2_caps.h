#pragma once

#include <QString>

#include <cstdint>
#include <vector>

namespace video {

struct Fps {
  uint32_t num = 0;
  uint32_t den = 0;
  double value() const;
};

struct FrameSizeCaps {
  uint32_t width = 0;
  uint32_t height = 0;
  std::vector<Fps> fps;
};

struct FormatCaps {
  uint32_t fourcc = 0;
  QString fourccStr;
  QString description;
  std::vector<FrameSizeCaps> sizes;
};

struct DeviceCaps {
  QString path;
  QString name;
  bool capture = false;
  std::vector<FormatCaps> formats;
};

struct DeviceInfo {
  QString path;
  QString name;
};

std::vector<DeviceInfo> listVideoDevices();
DeviceCaps queryDeviceCaps(const QString& devPath);
QString fourccToString(uint32_t fourcc);

} // namespace video

