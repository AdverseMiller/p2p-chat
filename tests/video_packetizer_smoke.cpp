#include "src/video/video_packetizer.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <random>
#include <vector>

int main() {
  std::vector<uint8_t> payload(5000);
  for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i & 0xFF);

  video::VideoPktHdr h {};
  h.flags = video::kVideoFlagKeyframe;
  h.streamId = 7;
  h.frameId = 42;
  h.ptsMs = 12345;

  auto packets = video::packetizeFrame(h, payload.data(), payload.size(), 1200);
  assert(!packets.empty());

  std::mt19937 rng(1234);
  std::shuffle(packets.begin(), packets.end(), rng);

  video::Reassembler re;
  std::optional<video::CompleteFrame> complete;
  for (const auto& p : packets) {
    video::ParsedPacket parsed;
    assert(video::parsePacket(p.data(), p.size(), &parsed));
    complete = re.add(parsed, 0);
  }

  assert(complete.has_value());
  assert(complete->frameId == 42);
  assert(complete->streamId == 7);
  assert(complete->keyframe);
  assert(complete->bytes == payload);

  video::JitterBuffer jb;
  jb.push(*complete, 0);
  auto out = jb.pop(10);
  assert(out.has_value());
  assert(out->bytes == payload);
  return 0;
}

