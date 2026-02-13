#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace video {

#pragma pack(push, 1)
struct VideoPktHdr {
  uint32_t magic;       // 'VPKT'
  uint8_t version;      // 1
  uint8_t flags;        // bit0=keyframe, bit1=config
  uint16_t headerBytes; // sizeof(VideoPktHdr)
  uint32_t streamId;    // per session
  uint32_t frameId;     // increment per encoded frame
  uint16_t fragIndex;   // 0..fragCount-1
  uint16_t fragCount;   // total frags
  uint32_t ptsMs;       // sender monotonic-ish ms
};
#pragma pack(pop)

constexpr uint32_t kVideoPktMagic = 0x56504B54u; // "VPKT"
constexpr uint8_t kVideoPktVersion = 1;
constexpr uint8_t kVideoFlagKeyframe = 1u << 0;
constexpr uint8_t kVideoFlagConfig = 1u << 1;

struct ParsedPacket {
  VideoPktHdr hdr {};
  std::vector<uint8_t> payload;
};

struct CompleteFrame {
  uint32_t streamId = 0;
  uint32_t frameId = 0;
  uint32_t ptsMs = 0;
  bool keyframe = false;
  std::vector<uint8_t> bytes;
};

bool parsePacket(const uint8_t* data, size_t len, ParsedPacket* out);
std::vector<std::vector<uint8_t>> packetizeFrame(const VideoPktHdr& hdrTemplate,
                                                 const uint8_t* payload,
                                                 size_t payloadLen,
                                                 size_t maxPacketBytes = 1200);

class Reassembler {
public:
  struct Partial {
    uint32_t streamId = 0;
    uint32_t frameId = 0;
    uint32_t ptsMs = 0;
    bool keyframe = false;
    uint16_t fragCount = 0;
    uint64_t firstSeenMs = 0;
    uint64_t lastSeenMs = 0;
    std::vector<std::vector<uint8_t>> frags;
    std::vector<bool> have;
    uint16_t haveCount = 0;
  };

  std::optional<CompleteFrame> add(const ParsedPacket& packet, uint64_t nowMs);
  void expire(uint64_t nowMs, uint64_t timeoutMs);

private:
  std::unordered_map<uint32_t, Partial> partialByFrame_;
};

class JitterBuffer {
public:
  void push(CompleteFrame frame, uint64_t nowMs);
  std::optional<CompleteFrame> pop(uint64_t nowMs, uint64_t maxWaitMs = 200);
  void clear();

private:
  uint32_t expectedFrameId_ = 0;
  bool initialized_ = false;
  std::unordered_map<uint32_t, std::pair<CompleteFrame, uint64_t>> frames_;
};

} // namespace video

