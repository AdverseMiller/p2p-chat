#include "src/video/video_packetizer.h"

#include <algorithm>
#include <cstring>

namespace video {

namespace {
inline void write_u16be(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}
inline void write_u32be(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[3] = static_cast<uint8_t>(v & 0xFF);
}
inline uint16_t read_u16be(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}
inline uint32_t read_u32be(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
} // namespace

bool parsePacket(const uint8_t* data, size_t len, ParsedPacket* out) {
  if (!data || !out) return false;
  if (len < sizeof(VideoPktHdr)) return false;

  VideoPktHdr h {};
  h.magic = read_u32be(data + 0);
  h.version = data[4];
  h.flags = data[5];
  h.headerBytes = read_u16be(data + 6);
  h.streamId = read_u32be(data + 8);
  h.frameId = read_u32be(data + 12);
  h.fragIndex = read_u16be(data + 16);
  h.fragCount = read_u16be(data + 18);
  h.ptsMs = read_u32be(data + 20);

  if (h.magic != kVideoPktMagic || h.version != kVideoPktVersion) return false;
  if (h.headerBytes < sizeof(VideoPktHdr) || h.headerBytes > len) return false;
  if (h.fragCount == 0 || h.fragIndex >= h.fragCount) return false;

  out->hdr = h;
  out->payload.assign(data + h.headerBytes, data + len);
  return true;
}

std::vector<std::vector<uint8_t>> packetizeFrame(const VideoPktHdr& hdrTemplate,
                                                 const uint8_t* payload,
                                                 size_t payloadLen,
                                                 size_t maxPacketBytes) {
  std::vector<std::vector<uint8_t>> out;
  if (!payload || payloadLen == 0) return out;
  const size_t hdrBytes = sizeof(VideoPktHdr);
  if (maxPacketBytes <= hdrBytes + 1) return out;
  const size_t chunk = maxPacketBytes - hdrBytes;
  const uint16_t fragCount = static_cast<uint16_t>((payloadLen + chunk - 1) / chunk);
  if (fragCount == 0) return out;

  out.reserve(fragCount);
  size_t off = 0;
  for (uint16_t i = 0; i < fragCount; ++i) {
    const size_t take = std::min(chunk, payloadLen - off);
    std::vector<uint8_t> pkt(hdrBytes + take);

    write_u32be(pkt.data() + 0, kVideoPktMagic);
    pkt[4] = kVideoPktVersion;
    pkt[5] = hdrTemplate.flags;
    write_u16be(pkt.data() + 6, static_cast<uint16_t>(hdrBytes));
    write_u32be(pkt.data() + 8, hdrTemplate.streamId);
    write_u32be(pkt.data() + 12, hdrTemplate.frameId);
    write_u16be(pkt.data() + 16, i);
    write_u16be(pkt.data() + 18, fragCount);
    write_u32be(pkt.data() + 20, hdrTemplate.ptsMs);
    std::memcpy(pkt.data() + hdrBytes, payload + off, take);
    off += take;
    out.push_back(std::move(pkt));
  }
  return out;
}

std::optional<CompleteFrame> Reassembler::add(const ParsedPacket& packet, uint64_t nowMs) {
  auto& partial = partialByFrame_[packet.hdr.frameId];
  if (partial.fragCount == 0) {
    partial.streamId = packet.hdr.streamId;
    partial.frameId = packet.hdr.frameId;
    partial.ptsMs = packet.hdr.ptsMs;
    partial.keyframe = (packet.hdr.flags & kVideoFlagKeyframe) != 0;
    partial.fragCount = packet.hdr.fragCount;
    partial.firstSeenMs = nowMs;
    partial.lastSeenMs = nowMs;
    partial.frags.resize(packet.hdr.fragCount);
    partial.have.assign(packet.hdr.fragCount, false);
  }

  if (partial.fragCount != packet.hdr.fragCount || packet.hdr.fragIndex >= partial.fragCount) return std::nullopt;
  partial.lastSeenMs = nowMs;
  if (!partial.have[packet.hdr.fragIndex]) {
    partial.have[packet.hdr.fragIndex] = true;
    partial.frags[packet.hdr.fragIndex] = packet.payload;
    partial.haveCount++;
  }
  if (partial.haveCount < partial.fragCount) return std::nullopt;

  CompleteFrame frame;
  frame.streamId = partial.streamId;
  frame.frameId = partial.frameId;
  frame.ptsMs = partial.ptsMs;
  frame.keyframe = partial.keyframe;
  size_t total = 0;
  for (const auto& f : partial.frags) total += f.size();
  frame.bytes.reserve(total);
  for (const auto& f : partial.frags) {
    frame.bytes.insert(frame.bytes.end(), f.begin(), f.end());
  }
  partialByFrame_.erase(packet.hdr.frameId);
  return frame;
}

void Reassembler::expire(uint64_t nowMs, uint64_t timeoutMs) {
  std::vector<uint32_t> drop;
  drop.reserve(partialByFrame_.size());
  for (const auto& [id, p] : partialByFrame_) {
    if (nowMs > p.firstSeenMs && nowMs - p.firstSeenMs > timeoutMs) drop.push_back(id);
  }
  for (uint32_t id : drop) partialByFrame_.erase(id);
}

void JitterBuffer::push(CompleteFrame frame, uint64_t nowMs) {
  if (!initialized_) {
    expectedFrameId_ = frame.frameId;
    initialized_ = true;
  }
  frames_[frame.frameId] = std::make_pair(std::move(frame), nowMs);
}

std::optional<CompleteFrame> JitterBuffer::pop(uint64_t nowMs, uint64_t maxWaitMs) {
  if (!initialized_) return std::nullopt;
  if (frames_.empty()) return std::nullopt;

  auto it = frames_.find(expectedFrameId_);
  if (it != frames_.end()) {
    CompleteFrame out = std::move(it->second.first);
    frames_.erase(it);
    expectedFrameId_++;
    return out;
  }

  uint32_t minId = expectedFrameId_;
  uint64_t minSeen = UINT64_MAX;
  bool haveMin = false;
  for (const auto& [id, v] : frames_) {
    if (!haveMin || id < minId) {
      minId = id;
      minSeen = v.second;
      haveMin = true;
    }
  }
  if (!haveMin) return std::nullopt;
  if (minSeen <= nowMs && (nowMs - minSeen) >= maxWaitMs) {
    expectedFrameId_ = minId;
    auto it2 = frames_.find(minId);
    if (it2 == frames_.end()) return std::nullopt;
    CompleteFrame out = std::move(it2->second.first);
    frames_.erase(it2);
    expectedFrameId_++;
    return out;
  }
  return std::nullopt;
}

void JitterBuffer::clear() {
  frames_.clear();
  initialized_ = false;
  expectedFrameId_ = 0;
}

} // namespace video

