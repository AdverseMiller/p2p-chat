#include "src/video/video_codec.h"

#include "common/util.hpp"

#if defined(P2PCHAT_VIDEO)
#if defined(__linux__)
#include <linux/videodev2.h>
#endif
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#include <libavutil/hwcontext.h>
#include <libavutil/opt.h>
#include <libavutil/pixdesc.h>
#include <libavutil/error.h>
#include <libswscale/swscale.h>
}
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>
#include <QStringList>

namespace video {

QString codecToString(Codec c) {
  switch (c) {
    case Codec::H264:
      return "h264";
    case Codec::HEVC:
      return "hevc";
  }
  return "h264";
}

Codec codecFromString(const QString& s) {
  const auto v = s.trimmed().toLower();
  if (v == "hevc" || v == "h265") return Codec::HEVC;
  return Codec::H264;
}

#if !defined(P2PCHAT_VIDEO)
struct Encoder::Impl {};
struct Decoder::Impl {};

bool isInputFourccSupported(uint32_t) { return false; }
std::optional<Codec> codecFromInputFourcc(uint32_t) { return std::nullopt; }
bool isPassthroughCompatible(uint32_t, Codec) { return false; }
bool passthroughFrame(const RawFrame&, Codec, EncodedFrame*, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
bool convertRawFrameToI420(const RawFrame&, I420Frame*, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
bool qimageToI420(const QImage&, I420Frame*, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
QImage i420ToQImage(const I420Frame&) { return {}; }
Encoder::Encoder() = default;
Encoder::~Encoder() = default;
bool Encoder::open(const EncodeParams&, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
void Encoder::close() {}
void Encoder::requestKeyframe() { forceKeyframe_ = true; }
bool Encoder::encode(const I420Frame&, std::vector<EncodedFrame>*, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
bool Encoder::isOpen() const { return false; }
Decoder::Decoder() = default;
Decoder::~Decoder() = default;
bool Decoder::open(Codec, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
void Decoder::close() {}
bool Decoder::decode(const uint8_t*, size_t, QImage*, QString* err) {
  if (err) *err = "video codec unavailable on this build";
  return false;
}
bool Decoder::isOpen() const { return false; }
#else
namespace {

bool codec_trace_enabled() {
  static const bool enabled = [] {
    const char* raw = std::getenv("P2PCHAT_CODEC_TRACE");
    if (!raw || !*raw) return false;
    std::string v(raw);
    std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return v == "1" || v == "true" || v == "yes" || v == "on";
  }();
  return enabled;
}

constexpr uint32_t make_fourcc(char a, char b, char c, char d) {
  return (static_cast<uint32_t>(static_cast<unsigned char>(a)) << 0) |
         (static_cast<uint32_t>(static_cast<unsigned char>(b)) << 8) |
         (static_cast<uint32_t>(static_cast<unsigned char>(c)) << 16) |
         (static_cast<uint32_t>(static_cast<unsigned char>(d)) << 24);
}

class ScopedPacket {
public:
  ScopedPacket() : p(av_packet_alloc()) {}
  ~ScopedPacket() { av_packet_free(&p); }
  AVPacket* get() const { return p; }

private:
  AVPacket* p = nullptr;
};

class ScopedFrame {
public:
  ScopedFrame() : f(av_frame_alloc()) {}
  ~ScopedFrame() { av_frame_free(&f); }
  AVFrame* get() const { return f; }

private:
  AVFrame* f = nullptr;
};

AVPixelFormat fourcc_to_pixfmt(uint32_t fourcc) {
  if (fourcc == make_fourcc('Y', 'U', 'Y', 'V')) return AV_PIX_FMT_YUYV422;
  if (fourcc == make_fourcc('Y', 'V', 'Y', 'U')) return AV_PIX_FMT_YVYU422;
  if (fourcc == make_fourcc('U', 'Y', 'V', 'Y')) return AV_PIX_FMT_UYVY422;
  if (fourcc == make_fourcc('N', 'V', '1', '2')) return AV_PIX_FMT_NV12;
  if (fourcc == make_fourcc('N', 'V', '2', '1')) return AV_PIX_FMT_NV21;
  if (fourcc == make_fourcc('Y', 'U', '1', '2')) return AV_PIX_FMT_YUV420P;
  if (fourcc == make_fourcc('Y', 'V', '1', '2')) return AV_PIX_FMT_YUV420P;
  if (fourcc == make_fourcc('R', 'G', 'B', '3')) return AV_PIX_FMT_RGB24;
  if (fourcc == make_fourcc('B', 'G', 'R', '3')) return AV_PIX_FMT_BGR24;
  if (fourcc == make_fourcc('G', 'R', 'E', 'Y')) return AV_PIX_FMT_GRAY8;
  return AV_PIX_FMT_NONE;
}

std::optional<AVCodecID> fourcc_to_compressed_codec(uint32_t fourcc) {
  if (fourcc == make_fourcc('M', 'J', 'P', 'G') ||
      fourcc == make_fourcc('J', 'P', 'E', 'G')) {
    return AV_CODEC_ID_MJPEG;
  }
  if (fourcc == make_fourcc('H', '2', '6', '4')) return AV_CODEC_ID_H264;
  if (fourcc == make_fourcc('H', 'E', 'V', 'C')) return AV_CODEC_ID_HEVC;
  return std::nullopt;
}

bool scale_to_i420(const AVFrame* src, I420Frame* out, QString* err) {
  if (!src || !out) return false;
  const int w = src->width;
  const int h = src->height;
  if (w <= 0 || h <= 0) {
    if (err) *err = "invalid frame geometry";
    return false;
  }

  SwsContext* sws = sws_getContext(w, h, static_cast<AVPixelFormat>(src->format),
                                   w, h, AV_PIX_FMT_YUV420P, SWS_BILINEAR, nullptr, nullptr, nullptr);
  if (!sws) {
    if (err) *err = "sws_getContext failed";
    return false;
  }

  out->width = w;
  out->height = h;
  out->yStride = w;
  out->uStride = w / 2;
  out->vStride = w / 2;
  out->y.resize(static_cast<size_t>(out->yStride) * static_cast<size_t>(h));
  out->u.resize(static_cast<size_t>(out->uStride) * static_cast<size_t>(h / 2));
  out->v.resize(static_cast<size_t>(out->vStride) * static_cast<size_t>(h / 2));

  uint8_t* dst_data[4] = {out->y.data(), out->u.data(), out->v.data(), nullptr};
  int dst_linesize[4] = {out->yStride, out->uStride, out->vStride, 0};
  sws_scale(sws, src->data, src->linesize, 0, h, dst_data, dst_linesize);
  sws_freeContext(sws);
  return true;
}

bool raw_to_i420_sws(const RawFrame& in, I420Frame* out, QString* err) {
  const AVPixelFormat srcFmt = fourcc_to_pixfmt(in.fourcc);
  if (srcFmt == AV_PIX_FMT_NONE) {
    if (err) *err = "unsupported raw fourcc";
    return false;
  }

  AVFrame* src = av_frame_alloc();
  if (!src) {
    if (err) *err = "av_frame_alloc failed";
    return false;
  }
  src->format = srcFmt;
  src->width = static_cast<int>(in.width);
  src->height = static_cast<int>(in.height);
  if (in.bytes.empty()) {
    av_frame_free(&src);
    if (err) *err = "empty raw frame";
    return false;
  }
  const int need = av_image_fill_arrays(src->data,
                                        src->linesize,
                                        reinterpret_cast<const uint8_t*>(in.bytes.data()),
                                        srcFmt,
                                        src->width,
                                        src->height,
                                        1);
  if (need < 0) {
    av_frame_free(&src);
    if (err) *err = "av_image_fill_arrays failed";
    return false;
  }
  if (static_cast<size_t>(need) > in.bytes.size()) {
    av_frame_free(&src);
    if (err) *err = "short raw frame";
    return false;
  }
  if (in.fourcc == make_fourcc('Y', 'V', '1', '2')) {
    std::swap(src->data[1], src->data[2]);
    std::swap(src->linesize[1], src->linesize[2]);
  }

  const bool ok = scale_to_i420(src, out, err);
  av_frame_free(&src);
  return ok;
}

bool compressed_to_i420(const RawFrame& in, AVCodecID codecId, I420Frame* out, QString* err) {
  static thread_local AVCodecID openedCodecId = AV_CODEC_ID_NONE;
  static thread_local const AVCodec* decCodec = nullptr;
  static thread_local AVCodecContext* decCtx = nullptr;
  static thread_local AVPacket* pkt = av_packet_alloc();
  static thread_local AVFrame* frame = av_frame_alloc();

  if (!pkt || !frame) {
    if (err) *err = "decoder buffers unavailable";
    return false;
  }
  if (!decCtx || openedCodecId != codecId) {
    if (decCtx) {
      avcodec_free_context(&decCtx);
      decCtx = nullptr;
    }
    decCodec = avcodec_find_decoder(codecId);
    if (!decCodec) {
      if (err) *err = "decoder not found";
      return false;
    }
    decCtx = avcodec_alloc_context3(decCodec);
    if (!decCtx || avcodec_open2(decCtx, decCodec, nullptr) < 0) {
      if (err) *err = "failed to open decoder";
      return false;
    }
    openedCodecId = codecId;
  }

  av_packet_unref(pkt);
  pkt->data = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(in.bytes.data()));
  pkt->size = static_cast<int>(in.bytes.size());
  if (avcodec_send_packet(decCtx, pkt) < 0) {
    if (err) *err = "decoder send packet failed";
    return false;
  }
  for (;;) {
    const int rc = avcodec_receive_frame(decCtx, frame);
    if (rc == AVERROR(EAGAIN) || rc == AVERROR_EOF) break;
    if (rc < 0) {
      if (err) *err = "decoder receive frame failed";
      return false;
    }
    if (scale_to_i420(frame, out, err)) {
      out->ptsMs = in.monotonicUs / 1000ull;
      av_frame_unref(frame);
      return true;
    }
    av_frame_unref(frame);
  }
  if (err) *err = "compressed frame not produced";
  return false;
}

std::vector<const AVCodec*> encoder_candidates(Codec want) {
  std::vector<const AVCodec*> out;
  auto add = [&out](const AVCodec* codec) {
    if (!codec) return;
    for (const auto* existing : out) {
      if (existing == codec) return;
    }
    out.push_back(codec);
  };
  auto add_name = [&add](const char* name) { add(avcodec_find_encoder_by_name(name)); };
  auto add_id = [&add](AVCodecID id) { add(avcodec_find_encoder(id)); };

  if (want == Codec::HEVC) {
    // Prefer NVENC first when available, then software, then V4L2 wrappers.
    add_name("hevc_nvenc");
    add_name("libx265");
    add_name("hevc_v4l2m2m");
    add_id(AV_CODEC_ID_HEVC);
  } else {
    add_name("h264_nvenc");
    add_name("libx264");
    add_name("h264_v4l2m2m");
    add_id(AV_CODEC_ID_H264);
  }
  return out;
}

QString ffmpeg_err_string(int rc) {
  char buf[AV_ERROR_MAX_STRING_SIZE] = {0};
  av_strerror(rc, buf, sizeof(buf));
  return QString::fromUtf8(buf);
}

void codec_trace_log(const std::string& msg) {
  if (!codec_trace_enabled()) return;
  common::log("video[trace]: " + msg);
}

std::vector<const AVCodec*> decoder_candidates(Codec codec) {
  std::vector<const AVCodec*> out;
  auto add = [&out](const AVCodec* dec) {
    if (!dec) return;
    for (const auto* existing : out) {
      if (existing == dec) return;
    }
    out.push_back(dec);
  };
  auto add_name = [&add](const char* name) { add(avcodec_find_decoder_by_name(name)); };
  auto add_id = [&add](AVCodecID id) { add(avcodec_find_decoder(id)); };

  if (codec == Codec::HEVC) {
    add_name("hevc_cuvid");
    add_id(AV_CODEC_ID_HEVC);
  } else {
    add_name("h264_cuvid");
    add_id(AV_CODEC_ID_H264);
  }
  return out;
}

std::optional<Codec> codec_from_avcodec(AVCodecID codec) {
  if (codec == AV_CODEC_ID_H264) return Codec::H264;
  if (codec == AV_CODEC_ID_HEVC) return Codec::HEVC;
  return std::nullopt;
}

bool has_h264_idr(std::span<const uint8_t> data) {
  const auto n = data.size();
  for (size_t i = 0; i + 4 < n; ++i) {
    size_t start = std::string::npos;
    if (i + 3 < n && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
      start = i + 3;
    } else if (i + 4 < n && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1) {
      start = i + 4;
    }
    if (start == std::string::npos || start >= n) continue;
    const uint8_t nal = data[start] & 0x1Fu;
    if (nal == 5 || nal == 7 || nal == 8) return true;
  }
  return false;
}

bool has_hevc_idr(std::span<const uint8_t> data) {
  const auto n = data.size();
  for (size_t i = 0; i + 5 < n; ++i) {
    size_t start = std::string::npos;
    if (i + 3 < n && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1) {
      start = i + 3;
    } else if (i + 4 < n && data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1) {
      start = i + 4;
    }
    if (start == std::string::npos || start >= n) continue;
    const uint8_t nal = static_cast<uint8_t>((data[start] >> 1) & 0x3Fu);
    if (nal == 19 || nal == 20 || nal == 21) return true; // IDR/CRA
  }
  return false;
}

QImage avframe_to_qimage(const AVFrame* frame) {
  if (!frame || frame->width <= 0 || frame->height <= 0) return {};
  SwsContext* sws = sws_getContext(frame->width, frame->height, static_cast<AVPixelFormat>(frame->format),
                                   frame->width, frame->height, AV_PIX_FMT_RGB24, SWS_BILINEAR, nullptr, nullptr, nullptr);
  if (!sws) return {};

  std::vector<uint8_t> rgb(static_cast<size_t>(frame->width) * static_cast<size_t>(frame->height) * 3u);
  uint8_t* dst_data[4] = {rgb.data(), nullptr, nullptr, nullptr};
  int dst_linesize[4] = {frame->width * 3, 0, 0, 0};
  sws_scale(sws, frame->data, frame->linesize, 0, frame->height, dst_data, dst_linesize);
  sws_freeContext(sws);

  QImage img(rgb.data(), frame->width, frame->height, dst_linesize[0], QImage::Format_RGB888);
  return img.copy();
}

} // namespace

struct Encoder::Impl {
  const AVCodec* codec = nullptr;
  AVCodecContext* ctx = nullptr;
  AVFrame* frame = nullptr;
  AVPacket* pkt = nullptr;
  int64_t nextPts = 0;
};

struct Decoder::Impl {
  const AVCodec* codec = nullptr;
  AVCodecContext* ctx = nullptr;
  AVFrame* frame = nullptr;
  AVFrame* swFrame = nullptr;
  AVPacket* pkt = nullptr;
  bool loggedHwTransfer = false;
};

bool isInputFourccSupported(uint32_t fourcc) {
  return fourcc_to_compressed_codec(fourcc).has_value() || fourcc_to_pixfmt(fourcc) != AV_PIX_FMT_NONE;
}

std::optional<Codec> codecFromInputFourcc(uint32_t fourcc) {
  const auto compressed = fourcc_to_compressed_codec(fourcc);
  if (!compressed) return std::nullopt;
  return codec_from_avcodec(*compressed);
}

bool isPassthroughCompatible(uint32_t fourcc, Codec networkCodec) {
  const auto c = codecFromInputFourcc(fourcc);
  return c.has_value() && c.value() == networkCodec;
}

bool passthroughFrame(const RawFrame& in, Codec networkCodec, EncodedFrame* out, QString* err) {
  if (!out) {
    if (err) *err = "null output";
    return false;
  }
  if (!isPassthroughCompatible(in.fourcc, networkCodec)) {
    if (err) *err = "capture format does not match selected passthrough codec";
    return false;
  }
  out->bytes = in.bytes;
  out->ptsMs = in.monotonicUs / 1000ull;
  std::span<const uint8_t> span(out->bytes.data(), out->bytes.size());
  if (networkCodec == Codec::HEVC) {
    out->keyframe = has_hevc_idr(span);
  } else {
    out->keyframe = has_h264_idr(span);
  }
  return true;
}

bool convertRawFrameToI420(const RawFrame& in, I420Frame* out, QString* err) {
  if (!out) return false;
  if (auto codec = fourcc_to_compressed_codec(in.fourcc)) {
    return compressed_to_i420(in, *codec, out, err);
  }
  if (!raw_to_i420_sws(in, out, err)) return false;
  out->ptsMs = in.monotonicUs / 1000ull;
  return true;
}

bool qimageToI420(const QImage& in, I420Frame* out, QString* err) {
  if (!out) return false;
  if (in.isNull()) {
    if (err) *err = "empty image";
    return false;
  }
  QImage rgb = in.convertToFormat(QImage::Format_RGB888);
  if (rgb.isNull()) {
    if (err) *err = "failed to convert image to RGB888";
    return false;
  }

  AVFrame* src = av_frame_alloc();
  if (!src) {
    if (err) *err = "av_frame_alloc failed";
    return false;
  }
  src->format = AV_PIX_FMT_RGB24;
  src->width = rgb.width();
  src->height = rgb.height();
  const int need = av_image_fill_arrays(src->data,
                                        src->linesize,
                                        reinterpret_cast<const uint8_t*>(rgb.constBits()),
                                        AV_PIX_FMT_RGB24,
                                        src->width,
                                        src->height,
                                        1);
  if (need < 0) {
    av_frame_free(&src);
    if (err) *err = "av_image_fill_arrays failed";
    return false;
  }

  const bool ok = scale_to_i420(src, out, err);
  av_frame_free(&src);
  return ok;
}

QImage i420ToQImage(const I420Frame& in) {
  if (in.width <= 0 || in.height <= 0 || in.y.empty() || in.u.empty() || in.v.empty()) return {};
  AVFrame* frame = av_frame_alloc();
  if (!frame) return {};
  frame->format = AV_PIX_FMT_YUV420P;
  frame->width = in.width;
  frame->height = in.height;
  frame->data[0] = const_cast<uint8_t*>(in.y.data());
  frame->data[1] = const_cast<uint8_t*>(in.u.data());
  frame->data[2] = const_cast<uint8_t*>(in.v.data());
  frame->linesize[0] = in.yStride;
  frame->linesize[1] = in.uStride;
  frame->linesize[2] = in.vStride;
  QImage out = avframe_to_qimage(frame);
  av_frame_free(&frame);
  return out;
}

Encoder::Encoder() : impl_(std::make_unique<Impl>()) {}
Encoder::~Encoder() { close(); }

bool Encoder::open(const EncodeParams& p, QString* err) {
  close();
  codec_ = p.codec;
  impl_ = std::make_unique<Impl>();

  const auto candidates = encoder_candidates(p.codec);
  if (candidates.empty()) {
    if (err) *err = "no suitable video encoder found";
    return false;
  }

  {
    QStringList names;
    for (const auto* c : candidates) {
      if (c && c->name) names.push_back(QString::fromLatin1(c->name));
    }
    codec_trace_log("encoder open request codec=" + codecToString(p.codec).toStdString() +
                    " size=" + std::to_string(p.width) + "x" + std::to_string(p.height) +
                    " fps=" + std::to_string(p.fpsDen) + "/" + std::to_string(p.fpsNum) +
                    " bitrate_kbps=" + std::to_string(p.bitrateKbps) +
                    " candidates=" + names.join(", ").toStdString());
  }

  QStringList failures;
  for (const AVCodec* candidate : candidates) {
    if (!candidate) continue;
    impl_->codec = candidate;
    impl_->ctx = avcodec_alloc_context3(impl_->codec);
    if (!impl_->ctx) {
      failures.push_back(QString::fromLatin1(candidate->name) + ": alloc failed");
      continue;
    }

    impl_->ctx->width = std::max(16, p.width);
    impl_->ctx->height = std::max(16, p.height);
    impl_->ctx->pix_fmt = AV_PIX_FMT_YUV420P;
    impl_->ctx->time_base = AVRational{1, 1000}; // ms
    impl_->ctx->framerate = AVRational{std::max(1, p.fpsNum), std::max(1, p.fpsDen)};
    impl_->ctx->bit_rate = std::clamp(p.bitrateKbps, 128, 20000) * 1000LL;
    impl_->ctx->gop_size = std::max(10, std::max(1, p.fpsNum / std::max(1, p.fpsDen)) * 2);
    impl_->ctx->max_b_frames = 0;
    impl_->ctx->thread_count = 1;

    const bool isNvenc = std::strstr(impl_->codec->name, "nvenc") != nullptr;
    if (impl_->codec->id == AV_CODEC_ID_H264) {
      if (isNvenc) {
        av_opt_set(impl_->ctx->priv_data, "preset", "p1", 0);
        av_opt_set(impl_->ctx->priv_data, "tune", "ll", 0);
      } else {
        av_opt_set(impl_->ctx->priv_data, "preset", "ultrafast", 0);
        av_opt_set(impl_->ctx->priv_data, "tune", "zerolatency", 0);
        av_opt_set(impl_->ctx->priv_data, "profile", "baseline", 0);
      }
    } else if (impl_->codec->id == AV_CODEC_ID_HEVC) {
      if (isNvenc) {
        av_opt_set(impl_->ctx->priv_data, "preset", "p1", 0);
        av_opt_set(impl_->ctx->priv_data, "tune", "ll", 0);
      } else {
        av_opt_set(impl_->ctx->priv_data, "preset", "ultrafast", 0);
        av_opt_set(impl_->ctx->priv_data, "tune", "zerolatency", 0);
      }
      av_opt_set(impl_->ctx->priv_data, "profile", "main", 0);
    }

    codec_trace_log(std::string("trying encoder=") + (candidate->name ? candidate->name : "unknown"));
    const int openRc = avcodec_open2(impl_->ctx, impl_->codec, nullptr);
    if (openRc < 0) {
      codec_trace_log(std::string("encoder open failed encoder=") + (candidate->name ? candidate->name : "unknown") +
                      " err=" + ffmpeg_err_string(openRc).toStdString());
      failures.push_back(QString::fromLatin1(candidate->name) + ": " + ffmpeg_err_string(openRc));
      avcodec_free_context(&impl_->ctx);
      impl_->ctx = nullptr;
      continue;
    }

    if (const auto normalized = codec_from_avcodec(impl_->codec->id)) {
      codec_ = *normalized;
    } else {
      codec_ = p.codec;
    }
    break;
  }

  if (!impl_->ctx || !impl_->codec) {
    if (err) {
      *err = failures.isEmpty() ? QString("avcodec_open2 failed")
                                : QString("avcodec_open2 failed (%1)").arg(failures.join("; "));
    }
    close();
    return false;
  }
  impl_->frame = av_frame_alloc();
  impl_->pkt = av_packet_alloc();
  if (!impl_->frame || !impl_->pkt) {
    if (err) *err = "failed to allocate frame/packet";
    close();
    return false;
  }
  impl_->frame->format = AV_PIX_FMT_YUV420P;
  impl_->frame->width = impl_->ctx->width;
  impl_->frame->height = impl_->ctx->height;
  if (av_frame_get_buffer(impl_->frame, 32) < 0) {
    if (err) *err = "av_frame_get_buffer failed";
    close();
    return false;
  }

  common::log("video: encoder open codec=" + codecToString(codec_).toStdString() +
              " encoder=" + std::string(impl_->codec ? impl_->codec->name : "unknown") +
              " " + std::to_string(impl_->ctx->width) + "x" + std::to_string(impl_->ctx->height));
  codec_trace_log("encoder open success encoder=" + std::string(impl_->codec ? impl_->codec->name : "unknown"));
  return true;
}

void Encoder::close() {
  if (!impl_) return;
  if (impl_->pkt) av_packet_free(&impl_->pkt);
  if (impl_->frame) av_frame_free(&impl_->frame);
  if (impl_->ctx) avcodec_free_context(&impl_->ctx);
  impl_.reset();
}

void Encoder::requestKeyframe() { forceKeyframe_ = true; }

bool Encoder::isOpen() const { return impl_ && impl_->ctx && impl_->frame && impl_->pkt; }

bool Encoder::encode(const I420Frame& in, std::vector<EncodedFrame>* out, QString* err) {
  if (!out) return false;
  out->clear();
  if (!isOpen()) {
    if (err) *err = "encoder not open";
    return false;
  }
  if (in.width != impl_->ctx->width || in.height != impl_->ctx->height) {
    if (err) *err = "input dimensions mismatch";
    return false;
  }

  if (av_frame_make_writable(impl_->frame) < 0) {
    if (err) *err = "av_frame_make_writable failed";
    return false;
  }

  for (int y = 0; y < in.height; ++y) {
    std::memcpy(impl_->frame->data[0] + y * impl_->frame->linesize[0],
                in.y.data() + static_cast<size_t>(y) * static_cast<size_t>(in.yStride),
                static_cast<size_t>(in.width));
  }
  for (int y = 0; y < in.height / 2; ++y) {
    std::memcpy(impl_->frame->data[1] + y * impl_->frame->linesize[1],
                in.u.data() + static_cast<size_t>(y) * static_cast<size_t>(in.uStride),
                static_cast<size_t>(in.width / 2));
    std::memcpy(impl_->frame->data[2] + y * impl_->frame->linesize[2],
                in.v.data() + static_cast<size_t>(y) * static_cast<size_t>(in.vStride),
                static_cast<size_t>(in.width / 2));
  }

  impl_->frame->pts = static_cast<int64_t>(in.ptsMs);
  impl_->frame->pict_type = forceKeyframe_ ? AV_PICTURE_TYPE_I : AV_PICTURE_TYPE_NONE;
  forceKeyframe_ = false;

  if (avcodec_send_frame(impl_->ctx, impl_->frame) < 0) {
    if (err) *err = "avcodec_send_frame failed";
    return false;
  }
  for (;;) {
    av_packet_unref(impl_->pkt);
    const int rc = avcodec_receive_packet(impl_->ctx, impl_->pkt);
    if (rc == AVERROR(EAGAIN) || rc == AVERROR_EOF) break;
    if (rc < 0) {
      if (err) *err = "avcodec_receive_packet failed";
      return false;
    }
    EncodedFrame ef;
    ef.bytes.resize(static_cast<size_t>(impl_->pkt->size));
    std::memcpy(ef.bytes.data(), impl_->pkt->data, ef.bytes.size());
    ef.keyframe = (impl_->pkt->flags & AV_PKT_FLAG_KEY) != 0;
    ef.ptsMs = static_cast<uint64_t>(impl_->pkt->pts >= 0 ? impl_->pkt->pts : in.ptsMs);
    out->push_back(std::move(ef));
  }
  return true;
}

Decoder::Decoder() : impl_(std::make_unique<Impl>()) {}
Decoder::~Decoder() { close(); }

bool Decoder::open(Codec codec, QString* err) {
  close();
  impl_ = std::make_unique<Impl>();
  const auto candidates = decoder_candidates(codec);
  if (candidates.empty()) {
    if (err) *err = "decoder not found";
    codec_trace_log("decoder open failed: decoder not found for codec=" + codecToString(codec).toStdString());
    return false;
  }

  {
    QStringList names;
    for (const auto* c : candidates) {
      if (c && c->name) names.push_back(QString::fromLatin1(c->name));
    }
    codec_trace_log("decoder open request codec=" + codecToString(codec).toStdString() +
                    " candidates=" + names.join(", ").toStdString());
  }

  QStringList failures;
  for (const AVCodec* candidate : candidates) {
    if (!candidate) continue;
    impl_->codec = candidate;
    impl_->ctx = avcodec_alloc_context3(impl_->codec);
    if (!impl_->ctx) {
      failures.push_back(QString::fromLatin1(candidate->name) + ": alloc failed");
      continue;
    }
    impl_->ctx->thread_count = 1;
    codec_trace_log(std::string("trying decoder=") + (candidate->name ? candidate->name : "unknown"));
    const int openRc = avcodec_open2(impl_->ctx, impl_->codec, nullptr);
    if (openRc < 0) {
      codec_trace_log(std::string("decoder open failed decoder=") + (candidate->name ? candidate->name : "unknown") +
                      " err=" + ffmpeg_err_string(openRc).toStdString());
      failures.push_back(QString::fromLatin1(candidate->name) + ": " + ffmpeg_err_string(openRc));
      avcodec_free_context(&impl_->ctx);
      impl_->ctx = nullptr;
      continue;
    }
    break;
  }

  if (!impl_->ctx || !impl_->codec) {
    if (err) {
      *err = failures.isEmpty() ? QString("avcodec_open2 failed")
                                : QString("avcodec_open2 failed (%1)").arg(failures.join("; "));
    }
    close();
    return false;
  }

  impl_->frame = av_frame_alloc();
  impl_->swFrame = av_frame_alloc();
  impl_->pkt = av_packet_alloc();
  if (!impl_->frame || !impl_->swFrame || !impl_->pkt) {
    if (err) *err = "alloc frame/packet failed";
    codec_trace_log("decoder open failed: alloc frame/packet");
    close();
    return false;
  }
  common::log("video: decoder open codec=" + codecToString(codec).toStdString() +
              " decoder=" + std::string(impl_->codec ? impl_->codec->name : "unknown"));
  codec_trace_log(std::string("decoder open success codec=") + codecToString(codec).toStdString() +
                  " decoder=" + (impl_->codec->name ? impl_->codec->name : "unknown"));
  return true;
}

void Decoder::close() {
  if (!impl_) return;
  if (impl_->pkt) av_packet_free(&impl_->pkt);
  if (impl_->swFrame) av_frame_free(&impl_->swFrame);
  if (impl_->frame) av_frame_free(&impl_->frame);
  if (impl_->ctx) avcodec_free_context(&impl_->ctx);
  impl_.reset();
}

bool Decoder::isOpen() const { return impl_ && impl_->ctx && impl_->frame && impl_->pkt; }

bool Decoder::decode(const uint8_t* data, size_t len, QImage* out, QString* err) {
  if (!out) return false;
  if (!isOpen()) {
    if (err) *err = "decoder not open";
    return false;
  }
  av_packet_unref(impl_->pkt);
  impl_->pkt->data = const_cast<uint8_t*>(data);
  impl_->pkt->size = static_cast<int>(len);
  if (avcodec_send_packet(impl_->ctx, impl_->pkt) < 0) {
    if (err) *err = "avcodec_send_packet failed";
    return false;
  }
  for (;;) {
    const int rc = avcodec_receive_frame(impl_->ctx, impl_->frame);
    if (rc == AVERROR(EAGAIN) || rc == AVERROR_EOF) break;
    if (rc < 0) {
      if (err) *err = "avcodec_receive_frame failed";
      return false;
    }

    AVFrame* viewFrame = impl_->frame;
    const auto* pixDesc = av_pix_fmt_desc_get(static_cast<AVPixelFormat>(impl_->frame->format));
    if (pixDesc && (pixDesc->flags & AV_PIX_FMT_FLAG_HWACCEL)) {
      av_frame_unref(impl_->swFrame);
      const int txRc = av_hwframe_transfer_data(impl_->swFrame, impl_->frame, 0);
      if (txRc < 0) {
        if (err) *err = "av_hwframe_transfer_data failed";
        return false;
      }
      if (!impl_->loggedHwTransfer) {
        common::log("video: decoder hwframe transfer active decoder=" +
                    std::string(impl_->codec ? impl_->codec->name : "unknown"));
        impl_->loggedHwTransfer = true;
      }
      viewFrame = impl_->swFrame;
    }

    QImage img = avframe_to_qimage(viewFrame);
    if (viewFrame == impl_->swFrame) av_frame_unref(impl_->swFrame);
    av_frame_unref(impl_->frame);
    if (!img.isNull()) {
      *out = std::move(img);
      return true;
    }
  }
  return false;
}
#endif

} // namespace video
