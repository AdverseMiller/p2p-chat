#include "src/video/v4l2_caps.h"

#include <iostream>

int main() {
  const auto devs = video::listVideoDevices();
  if (devs.empty()) {
    std::cout << "No V4L2 capture devices found.\n";
    return 0;
  }

  for (const auto& d : devs) {
    const auto caps = video::queryDeviceCaps(d.path);
    std::cout << d.path.toStdString() << " (" << caps.name.toStdString() << ")\n";
    std::cout << "  capture: " << (caps.capture ? "yes" : "no") << "\n";
    for (const auto& fmt : caps.formats) {
      std::cout << "  format: " << fmt.fourccStr.toStdString() << " [" << fmt.description.toStdString() << "]\n";
      for (const auto& sz : fmt.sizes) {
        std::cout << "    size: " << sz.width << "x" << sz.height << " fps:";
        for (const auto& fps : sz.fps) {
          std::cout << " " << fps.value() << "(" << fps.den << "/" << fps.num << ")";
        }
        std::cout << "\n";
      }
    }
    std::cout << "\n";
  }
  return 0;
}

