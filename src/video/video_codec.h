#pragma once

#include "src/video/v4l2_capture.h"

#include <QImage>
#include <QString>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace video {

enum class Codec {
  H264,
};

struct EncodedFrame;

QString codecToString(Codec c);
Codec codecFromString(const QString& s);
bool isInputFourccSupported(uint32_t fourcc);
std::optional<Codec> codecFromInputFourcc(uint32_t fourcc);
bool isPassthroughCompatible(uint32_t fourcc, Codec networkCodec);
bool passthroughFrame(const RawFrame& in, Codec networkCodec, EncodedFrame* out, QString* err = nullptr);

struct I420Frame {
  int width = 0;
  int height = 0;
  std::vector<uint8_t> y;
  std::vector<uint8_t> u;
  std::vector<uint8_t> v;
  int yStride = 0;
  int uStride = 0;
  int vStride = 0;
  uint64_t ptsMs = 0;
};

struct EncodedFrame {
  std::vector<uint8_t> bytes;
  bool keyframe = false;
  uint64_t ptsMs = 0;
};

struct EncodeParams {
  Codec codec = Codec::H264;
  int width = 640;
  int height = 480;
  int fpsNum = 30;
  int fpsDen = 1;
  int bitrateKbps = 1500;
};

bool convertRawFrameToI420(const RawFrame& in, I420Frame* out, QString* err = nullptr);
bool qimageToI420(const QImage& in, I420Frame* out, QString* err = nullptr);
QImage i420ToQImage(const I420Frame& in);

class Encoder {
public:
  Encoder();
  ~Encoder();
  Encoder(const Encoder&) = delete;
  Encoder& operator=(const Encoder&) = delete;

  bool open(const EncodeParams& p, QString* err = nullptr);
  void close();
  void requestKeyframe();
  bool encode(const I420Frame& frame, std::vector<EncodedFrame>* out, QString* err = nullptr);
  Codec codec() const { return codec_; }
  bool isOpen() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
  Codec codec_ = Codec::H264;
  bool forceKeyframe_ = false;
};

class Decoder {
public:
  Decoder();
  ~Decoder();
  Decoder(const Decoder&) = delete;
  Decoder& operator=(const Decoder&) = delete;

  bool open(Codec codec, QString* err = nullptr);
  void close();
  bool decode(const uint8_t* data, size_t len, QImage* out, QString* err = nullptr);
  bool isOpen() const;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace video
