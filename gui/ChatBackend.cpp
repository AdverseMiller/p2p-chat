#include "gui/ChatBackend.hpp"
#include "gui/Profile.hpp"

#include "common/crypto.hpp"
#include "common/framing.hpp"
#include "common/identity.hpp"
#include "common/util.hpp"
#include "src/video/v4l2_capture.h"
#include "src/video/video_codec.h"
#include "src/video/video_packetizer.h"
#if defined(P2PCHAT_X11_SHM)
#include "src/video/x11_shm_capture.h"
#endif

#include <QCoreApplication>
#include <QPointer>
#include <QPixmap>
#include <QTimer>
#include <QScreen>
#include <QGuiApplication>
#if defined(P2PCHAT_VIDEO) && __has_include(<QScreenCapture>) && __has_include(<QMediaCaptureSession>) && __has_include(<QVideoSink>) && __has_include(<QVideoFrame>)
#define P2PCHAT_QT_SCREEN_CAPTURE 1
#include <QMediaCaptureSession>
#include <QScreenCapture>
#include <QVideoFrame>
#include <QVideoSink>
#endif

#if defined(_WIN32)
#include <mstcpip.h>
#include <winsock2.h>
#endif

#include <boost/asio.hpp>

#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#if defined(P2PCHAT_VOICE)
#include <QAudioDevice>
#include <QAudioFormat>
#include <QAudioSink>
#include <QAudioSource>
#include <QElapsedTimer>
#include <QHash>
#include <QIODevice>
#include <QMap>
#include <QSet>
#include <QMediaDevices>

#include <opus/opus.h>
#endif

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using common::json;

namespace {
constexpr auto kHeartbeatInterval = std::chrono::seconds(15);
constexpr auto kPollInterval = std::chrono::seconds(4);
constexpr auto kConnectTimeout = std::chrono::seconds(10);
constexpr auto kUdpPunchInterval = std::chrono::milliseconds(250);
constexpr auto kUdpHandshakeResend = std::chrono::milliseconds(400);
constexpr auto kUdpDataResend = std::chrono::milliseconds(500);
constexpr int kVoiceJitterStartFrames = 5;
constexpr int kVoiceJitterTargetFrames = 4;
constexpr int kVoiceJitterMaxFrames = 30;
constexpr quint64 kVoiceSeqResetGap = 2000;
constexpr int kVoiceMaxDecodeSamplesPerChannel = 2880; // 60 ms @ 48 kHz
constexpr uint64_t kVideoFrameExpireMs = 250;
constexpr uint64_t kVideoJitterWaitMs = 120;
constexpr auto kNoneAudioDeviceId = "none";

bool is_none_audio_device(const QString& id) {
  return id.compare(QString::fromLatin1(kNoneAudioDeviceId), Qt::CaseInsensitive) == 0;
}

#if defined(P2PCHAT_VOICE)
void configure_opus_encoder(OpusEncoder* encoder, int bitrate) {
  if (!encoder) return;
  opus_encoder_ctl(encoder, OPUS_SET_BITRATE(std::clamp(bitrate, 8000, 128000)));
  opus_encoder_ctl(encoder, OPUS_SET_INBAND_FEC(1));
  opus_encoder_ctl(encoder, OPUS_SET_PACKET_LOSS_PERC(8));
  opus_encoder_ctl(encoder, OPUS_SET_SIGNAL(OPUS_SIGNAL_VOICE));
}
#endif

uint32_t parse_fourcc_text(const QString& s) {
  const auto b = s.toLatin1();
  if (b.size() < 4) return 0;
  return static_cast<uint32_t>(static_cast<uint8_t>(b[0])) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[3])) << 24);
}

QString resolve_network_video_codec(const ChatBackend::VoiceSettings& settings) {
  const auto requested = settings.videoCodec.trimmed().toLower();
  if (requested == "hevc" || requested == "h265") return "hevc";
  if (requested == "av1" || requested == "av01") return "av1";
  if (requested == "h264") return "h264";
  return "h264";
}

QString normalize_video_codec(const QString& raw) {
  const auto requested = raw.trimmed().toLower();
  if (requested == "hevc" || requested == "h265") return "hevc";
  if (requested == "av1" || requested == "av01") return "av1";
  if (requested == "h264") return "h264";
  return "h264";
}

QString normalize_video_provider(const QString& raw) { return video::normalizeProviderKey(raw); }

video::Codec next_video_codec_fallback(video::Codec codec) {
  switch (codec) {
    case video::Codec::AV1:
      return video::Codec::H264;
    case video::Codec::HEVC:
      return video::Codec::AV1;
    case video::Codec::H264:
    default:
      return video::Codec::HEVC;
  }
}

bool debug_logs_enabled() {
  static const bool enabled = [] {
#if !defined(NDEBUG)
    const bool default_enabled = true;
#else
    const bool default_enabled = false;
#endif
    const char* raw = std::getenv("P2PCHAT_DEBUG");
    if (!raw || !*raw) return default_enabled;

    std::string value(raw);
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; }),
                value.end());
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (value == "1" || value == "true" || value == "yes" || value == "on") return true;
    if (value == "0" || value == "false" || value == "no" || value == "off") return false;
    return default_enabled;
  }();
  return enabled;
}

constexpr common::AeadCipher kStreamCipher = common::AeadCipher::Aes128Gcm;

std::string stream_cipher_to_wire(common::AeadCipher cipher) {
  return std::string(common::aead_cipher_to_string(cipher));
}

std::vector<std::string> supported_stream_ciphers_wire() {
  return {stream_cipher_to_wire(kStreamCipher)};
}

bool supports_stream_cipher(const json& j, common::AeadCipher want) {
  if (j.contains("aead_supported") && j["aead_supported"].is_array()) {
    for (const auto& v : j["aead_supported"]) {
      if (!v.is_string()) continue;
      if (common::aead_cipher_from_string(v.get<std::string>()) == want) return true;
    }
    return false;
  }
  if (j.contains("aead_pref") && j["aead_pref"].is_string()) {
    return common::aead_cipher_from_string(j["aead_pref"].get<std::string>()) == want;
  }
  if (j.contains("aead") && j["aead"].is_string()) {
    return common::aead_cipher_from_string(j["aead"].get<std::string>()) == want;
  }
  return false;
}

bool running_as_root() {
#if defined(_WIN32)
  return false;
#else
  return ::geteuid() == 0;
#endif
}

#if defined(_WIN32)
void disable_udp_connreset(udp::socket& socket) {
  DWORD bytes = 0;
  BOOL behavior = FALSE;
  (void)::WSAIoctl(socket.native_handle(),
                   SIO_UDP_CONNRESET,
                   &behavior,
                   sizeof(behavior),
                   nullptr,
                   0,
                   &bytes,
                   nullptr,
                   nullptr);
}
#endif

bool is_x11_platform();

bool prefer_qt_screen_capture_backend() {
#if defined(P2PCHAT_QT_SCREEN_CAPTURE) && defined(__linux__)
  const char* raw = std::getenv("P2PCHAT_SCREEN_BACKEND");
  if (!raw || !*raw) return !is_x11_platform(); // on X11 prefer x11shm backend by default
  QString v = QString::fromUtf8(raw).trimmed().toLower();
  if (v == "x11" || v == "legacy" || v == "grabwindow") return false;
  if (v == "x11shm" || v == "xshm" || v == "x11-shm") return false;
  if (v == "qt" || v == "qtscreen" || v == "portal") return true;
  return !is_x11_platform();
#else
  return false;
#endif
}

bool allow_legacy_screen_fallback() {
#if defined(P2PCHAT_QT_SCREEN_CAPTURE) && defined(__linux__)
  const char* raw = std::getenv("P2PCHAT_SCREEN_ALLOW_LEGACY_FALLBACK");
  if (!raw || !*raw) return false;
  QString v = QString::fromUtf8(raw).trimmed().toLower();
  return v == "1" || v == "true" || v == "yes" || v == "on";
#else
  return true;
#endif
}

bool is_x11_platform() {
#if defined(__linux__)
  const QString platform = QGuiApplication::platformName().trimmed().toLower();
  if (platform.contains("xcb") || platform == "x11") return true;
  const char* session = std::getenv("XDG_SESSION_TYPE");
  if (session && *session) {
    const QString s = QString::fromUtf8(session).trimmed().toLower();
    if (s == "x11") return true;
    if (s == "wayland") return false;
  }
#endif
  return false;
}

bool prefer_x11_shm_screen_backend() {
#if defined(P2PCHAT_X11_SHM) && defined(__linux__)
  const char* raw = std::getenv("P2PCHAT_SCREEN_BACKEND");
  if (raw && *raw) {
    QString v = QString::fromUtf8(raw).trimmed().toLower();
    return v == "x11shm" || v == "xshm" || v == "x11-shm";
  }
  return is_x11_platform();
#else
  return false;
#endif
}

QScreen* find_screen_by_name(const QString& name) {
  const auto wanted = name.trimmed();
  if (wanted.isEmpty()) return QGuiApplication::primaryScreen();
  const auto screens = QGuiApplication::screens();
  for (auto* screen : screens) {
    if (!screen) continue;
    if (screen->name() == wanted) return screen;
  }
  return QGuiApplication::primaryScreen();
}

#if defined(P2PCHAT_VOICE)
constexpr uint32_t kVoiceMagic = 0x50325056u; // "P2PV"
constexpr uint8_t kVoiceVersion = 1;
constexpr uint32_t kVideoMagic = video::kVideoPktMagic;
constexpr uint8_t kVideoVersion = video::kVideoPktVersion;

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
inline void write_u64be(uint8_t* p, uint64_t v) {
  p[0] = static_cast<uint8_t>((v >> 56) & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 48) & 0xFF);
  p[2] = static_cast<uint8_t>((v >> 40) & 0xFF);
  p[3] = static_cast<uint8_t>((v >> 32) & 0xFF);
  p[4] = static_cast<uint8_t>((v >> 24) & 0xFF);
  p[5] = static_cast<uint8_t>((v >> 16) & 0xFF);
  p[6] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[7] = static_cast<uint8_t>(v & 0xFF);
}
inline uint16_t read_u16be(const uint8_t* p) {
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}
inline uint32_t read_u32be(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
inline uint64_t read_u64be(const uint8_t* p) {
  return (static_cast<uint64_t>(p[0]) << 56) | (static_cast<uint64_t>(p[1]) << 48) |
         (static_cast<uint64_t>(p[2]) << 40) | (static_cast<uint64_t>(p[3]) << 32) |
         (static_cast<uint64_t>(p[4]) << 24) | (static_cast<uint64_t>(p[5]) << 16) |
         (static_cast<uint64_t>(p[6]) << 8) | static_cast<uint64_t>(p[7]);
}

class PcmRingBufferIODevice final : public QIODevice {
public:
  explicit PcmRingBufferIODevice(QObject* parent = nullptr) : QIODevice(parent) {}

  void start() { open(QIODevice::ReadOnly); }
  void stop() { close(); }

  bool isSequential() const override { return true; }

  void push(const QByteArray& pcm) {
    if (pcm.isEmpty()) return;
    std::lock_guard lk(m_);
    if (buf_.size() > kMaxBytes) {
      // Drop oldest data under pressure.
      const int drop = std::min<int>(buf_.size(), pcm.size());
      buf_.remove(0, drop);
    }
    buf_.append(pcm);
  }

  qint64 bytesAvailable() const override {
    std::lock_guard lk(m_);
    return QIODevice::bytesAvailable() + buf_.size();
  }

  qint64 readData(char* data, qint64 maxlen) override {
    std::lock_guard lk(m_);
    if (buf_.isEmpty()) return 0;
    const qint64 n = std::min<qint64>(maxlen, buf_.size());
    std::memcpy(data, buf_.constData(), static_cast<std::size_t>(n));
    buf_.remove(0, static_cast<int>(n));
    return n;
  }

  qint64 writeData(const char*, qint64) override { return -1; }

private:
  static constexpr int kMaxBytes = 48000 * 2 / 6; // ~166ms @48kHz mono s16
  mutable std::mutex m_;
  QByteArray buf_;
};

#if !defined(_WIN32)
bool pipewireSpaSupportPresent() {
  // PipeWire needs the SPA support plugin for its system handle.
  // Many minimal installs have libpipewire but miss this plugin directory, and QtMultimedia may abort.
  const char* env = std::getenv("SPA_PLUGIN_DIR");
  auto exists = [](const std::string& dir) {
    const std::string a = dir + "/support/libspa-support.so";
    const std::string b = dir + "/support/libspa-support.so.0";
    return ::access(a.c_str(), R_OK) == 0 || ::access(b.c_str(), R_OK) == 0;
  };
  if (env && *env) {
    std::string s(env);
    std::size_t pos = 0;
    while (pos <= s.size()) {
      const auto next = s.find(':', pos);
      const auto part = s.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
      if (!part.empty() && exists(part)) return true;
      if (next == std::string::npos) break;
      pos = next + 1;
    }
  }
  return exists("/usr/lib/spa-0.2") || exists("/usr/lib64/spa-0.2") || exists("/lib/spa-0.2") || exists("/lib64/spa-0.2");
}
#endif
#endif // P2PCHAT_VOICE

class PeerSession : public std::enable_shared_from_this<PeerSession> {
public:
  enum class Role { Initiator, Acceptor };
  using OnReady = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnName = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnAvatar = std::function<void(const std::string& peer_id, const std::vector<uint8_t>& png_bytes)>;
  using OnChat = std::function<void(const std::string& peer_id, const std::string& peer_name, const std::string& text)>;
  using OnControl = std::function<void(const std::string& peer_id, json inner)>;
  using OnClosed = std::function<void()>;

  PeerSession(tcp::socket socket,
              Role role,
              std::string self_id,
              std::shared_ptr<common::Identity> identity,
              std::function<std::string(const std::string&)> get_self_name,
              std::function<std::vector<uint8_t>()> get_self_avatar_png,
              std::function<bool(const std::string&)> allow_peer,
              common::AeadCipher preferred_cipher,
              std::string expected_peer_id = {})
      : socket_(std::move(socket)),
        role_(role),
        self_id_(std::move(self_id)),
        identity_(std::move(identity)),
        get_self_name_(std::move(get_self_name)),
        get_self_avatar_png_(std::move(get_self_avatar_png)),
        allow_peer_(std::move(allow_peer)),
        preferred_cipher_(preferred_cipher),
        negotiated_cipher_(kStreamCipher),
        expected_peer_id_(std::move(expected_peer_id)),
        writer_(std::make_shared<common::JsonWriteQueue<tcp::socket>>(socket_)) {}

  void start(OnReady on_ready,
             OnName on_name,
             OnAvatar on_avatar,
             OnChat on_chat,
             OnControl on_control,
             OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_avatar_ = std::move(on_avatar);
    on_chat_ = std::move(on_chat);
    on_control_ = std::move(on_control);
    on_closed_ = std::move(on_closed);
    if (role_ == Role::Initiator) {
      start_secure_initiator();
    } else {
      wait_for_secure_hello();
    }
  }

  void start_accept_with_first(json first,
                               OnReady on_ready,
                               OnName on_name,
                               OnAvatar on_avatar,
                               OnChat on_chat,
                               OnControl on_control,
                               OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_avatar_ = std::move(on_avatar);
    on_chat_ = std::move(on_chat);
    on_control_ = std::move(on_control);
    on_closed_ = std::move(on_closed);
    if (!first.contains("type") || !first["type"].is_string()) return send_error_and_close("missing type");
    const std::string type = first["type"].get<std::string>();
    if (type != "secure_hello") return send_error_and_close("expected secure_hello");
    handle_secure_hello(std::move(first));
  }

  void send_chat(std::string text) {
    if (!ready_) return;
    json inner;
    inner["type"] = "chat";
    inner["text"] = std::move(text);
    send_secure(std::move(inner));
  }

  void send_name(std::string name) {
    if (!ready_) return;
    if (name.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = std::move(name);
    send_secure(std::move(inner));
  }

  void send_avatar(std::vector<uint8_t> png) {
    if (!ready_) return;
    if (png.empty()) return;
    if (png.size() > 48 * 1024) return;
    json inner;
    inner["type"] = "avatar";
    inner["png"] = common::base64url_encode(png);
    send_secure(std::move(inner));
  }

  void send_control(json inner) {
    if (!ready_) return;
    send_secure(std::move(inner));
  }

  void close() {
    if (closed_) return;
    closed_ = true;
    boost::system::error_code ignored;
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    if (on_closed_) on_closed_();
  }

  std::string_view peer_id() const { return peer_id_; }
  std::string_view peer_name() const { return peer_name_; }

private:
  static constexpr std::string_view kProto = "p2p-chat-secure-v1";

  static std::vector<uint8_t> bytes(std::string_view s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                reinterpret_cast<const uint8_t*>(s.data() + s.size()));
  }

  static std::string transcript_string(std::string_view init_id,
                                       std::string_view init_eph_b64,
                                       std::string_view resp_id,
                                       std::string_view resp_eph_b64) {
    std::string t;
    t.reserve(kProto.size() + init_id.size() + init_eph_b64.size() + resp_id.size() + resp_eph_b64.size() + 16);
    t.append(kProto);
    t.push_back('|');
    t.append(init_id);
    t.push_back('|');
    t.append(init_eph_b64);
    t.push_back('|');
    t.append(resp_id);
    t.push_back('|');
    t.append(resp_eph_b64);
    return t;
  }

  void send_error_and_close(std::string message) {
    auto self = shared_from_this();
    json e;
    e["type"] = "error";
    e["message"] = std::move(message);
    common::async_write_json(socket_, e, [self](const boost::system::error_code&) { self->close(); });
  }

  void start_secure_initiator() {
    if (!identity_) return send_error_and_close("identity not loaded");
    eph_ = common::x25519_generate();
    const std::string eph_b64 = common::base64url_encode(eph_->public_key);

    // Signature binds claimed identity to initiator ephemeral key.
    const std::string sig_msg = std::string(kProto) + "|init|" + self_id_ + "|" + eph_b64;
    const std::string sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sig_msg.data()), sig_msg.size()));
    if (sig.empty()) return send_error_and_close("failed to sign");

    json hello;
    hello["type"] = "secure_hello";
    hello["id"] = self_id_;
    hello["eph"] = eph_b64;
    hello["sig"] = sig;
    hello["aead_pref"] = stream_cipher_to_wire(kStreamCipher);
    hello["aead_supported"] = supported_stream_ciphers_wire();
    writer_->send(std::move(hello));
    wait_for_secure_hello_ack();
  }

  void wait_for_secure_hello() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "secure_hello") {
        return self->send_error_and_close("expected secure_hello");
      }
      self->handle_secure_hello(std::move(j));
    });
  }

  void handle_secure_hello(json j) {
    if (!identity_) return send_error_and_close("identity not loaded");
    if (!j.contains("id") || !j["id"].is_string()) return send_error_and_close("secure_hello missing id");
    if (!j.contains("eph") || !j["eph"].is_string()) return send_error_and_close("secure_hello missing eph");
    if (!j.contains("sig") || !j["sig"].is_string()) return send_error_and_close("secure_hello missing sig");

    const std::string init_id = j["id"].get<std::string>();
    if (!common::is_valid_id(init_id)) return send_error_and_close("invalid peer id");
    if (allow_peer_ && !allow_peer_(init_id)) return send_error_and_close("not friends");
    if (!supports_stream_cipher(j, kStreamCipher)) {
      return send_error_and_close("peer does not support required stream cipher");
    }
    negotiated_cipher_ = kStreamCipher;

    const std::string init_eph_b64 = j["eph"].get<std::string>();
    const auto init_eph = common::base64url_decode(init_eph_b64);
    if (!init_eph || init_eph->size() != 32) return send_error_and_close("invalid eph");

    // Verify initiator signature.
    const std::string sig_msg = std::string(kProto) + "|init|" + init_id + "|" + init_eph_b64;
    const auto sig_msg_bytes = bytes(sig_msg);
    if (!common::Identity::verify_bytes_b64url(init_id, sig_msg_bytes, j["sig"].get<std::string>())) {
      return send_error_and_close("bad signature");
    }

    // Generate responder ephemeral and reply with ack signature over full transcript.
    peer_id_ = init_id;
    peer_eph_pub_ = *init_eph;
    eph_ = common::x25519_generate();
    const std::string resp_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(init_id, init_eph_b64, self_id_, resp_eph_b64);

    const std::string ack_msg = transcript_ + "|resp";
    const std::string ack_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(ack_msg.data()), ack_msg.size()));
    if (ack_sig.empty()) return send_error_and_close("failed to sign");

    json ack;
    ack["type"] = "secure_hello_ack";
    ack["id"] = self_id_;
    ack["eph"] = resp_eph_b64;
    ack["sig"] = ack_sig;
    ack["aead"] = stream_cipher_to_wire(negotiated_cipher_);
    writer_->send(std::move(ack));
    wait_for_secure_finish();
  }

  void wait_for_secure_hello_ack() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string()) return self->send_error_and_close("missing type");
      const std::string type = j["type"].get<std::string>();
      if (type == "busy") return self->send_error_and_close("peer busy");
      if (type != "secure_hello_ack") return self->send_error_and_close("expected secure_hello_ack");
      if (!j.contains("id") || !j["id"].is_string()) return self->send_error_and_close("secure_hello_ack missing id");
      if (!j.contains("eph") || !j["eph"].is_string()) return self->send_error_and_close("secure_hello_ack missing eph");
      if (!j.contains("sig") || !j["sig"].is_string()) return self->send_error_and_close("secure_hello_ack missing sig");

      const std::string resp_id = j["id"].get<std::string>();
      if (!common::is_valid_id(resp_id)) return self->send_error_and_close("invalid peer id");
      if (!self->expected_peer_id_.empty() && resp_id != self->expected_peer_id_) {
        return self->send_error_and_close("unexpected peer id");
      }
      if (self->allow_peer_ && !self->allow_peer_(resp_id)) return self->send_error_and_close("not friends");

      const std::string resp_eph_b64 = j["eph"].get<std::string>();
      const auto resp_eph = common::base64url_decode(resp_eph_b64);
      if (!resp_eph || resp_eph->size() != 32) return self->send_error_and_close("invalid eph");

      const std::string init_eph_b64 = common::base64url_encode(self->eph_->public_key);
      self->transcript_ = transcript_string(self->self_id_, init_eph_b64, resp_id, resp_eph_b64);
      const std::string ack_msg = self->transcript_ + "|resp";
      const auto ack_msg_bytes = bytes(ack_msg);
      if (!common::Identity::verify_bytes_b64url(resp_id, ack_msg_bytes, j["sig"].get<std::string>())) {
        return self->send_error_and_close("bad signature");
      }

      self->peer_id_ = resp_id;
      self->peer_eph_pub_ = *resp_eph;
      if (!j.contains("aead") || !j["aead"].is_string() ||
          common::aead_cipher_from_string(j["aead"].get<std::string>()) != kStreamCipher) {
        return self->send_error_and_close("peer selected unsupported stream cipher");
      }
      self->negotiated_cipher_ = kStreamCipher;

      // Send finish signature binding initiator to full transcript.
      const std::string fin_msg = self->transcript_ + "|init";
      const std::string fin_sig = self->identity_->sign_bytes_b64url(std::span<const uint8_t>(
          reinterpret_cast<const uint8_t*>(fin_msg.data()), fin_msg.size()));
      if (fin_sig.empty()) return self->send_error_and_close("failed to sign");
      json fin;
      fin["type"] = "secure_finish";
      fin["sig"] = fin_sig;
      self->writer_->send(std::move(fin));

      if (!self->derive_keys()) return self->send_error_and_close("key derivation failed");
      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      self->send_name_update();
      self->send_avatar_update();
      self->read_loop_secure();
    });
  }

  void wait_for_secure_finish() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string() || j["type"].get<std::string>() != "secure_finish") {
        return self->send_error_and_close("expected secure_finish");
      }
      if (!j.contains("sig") || !j["sig"].is_string()) return self->send_error_and_close("secure_finish missing sig");
      const std::string fin_sig = j["sig"].get<std::string>();
      const std::string fin_msg = self->transcript_ + "|init";
      const auto fin_msg_bytes = bytes(fin_msg);
      if (!common::Identity::verify_bytes_b64url(self->peer_id_, fin_msg_bytes, fin_sig)) {
        return self->send_error_and_close("bad signature");
      }
      if (!self->derive_keys()) return self->send_error_and_close("key derivation failed");
      self->ready_ = true;
      if (self->on_ready_) self->on_ready_(self->peer_id_, self->peer_name_);
      self->send_name_update();
      self->send_avatar_update();
      self->read_loop_secure();
    });
  }

  bool derive_keys() {
    if (!eph_) return false;
    if (peer_eph_pub_.size() != 32) return false;

    const auto shared = common::x25519_derive_shared_secret(eph_->pkey.get(), peer_eph_pub_);
    if (!shared) return false;

    const auto salt = common::sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(transcript_.data()), transcript_.size()));

    auto hkdf32 = [&](std::string_view info) -> std::optional<std::array<uint8_t, 32>> {
      return common::hkdf_sha256_32(*shared, salt, info);
    };

    const auto k_init_to_resp = hkdf32(std::string(kProto) + " key init->resp");
    const auto k_resp_to_init = hkdf32(std::string(kProto) + " key resp->init");
    const auto n_init_to_resp = hkdf32(std::string(kProto) + " nonce init->resp");
    const auto n_resp_to_init = hkdf32(std::string(kProto) + " nonce resp->init");
    if (!k_init_to_resp || !k_resp_to_init || !n_init_to_resp || !n_resp_to_init) return false;

    if (role_ == Role::Initiator) {
      send_key_.key = *k_init_to_resp;
      recv_key_.key = *k_resp_to_init;
      std::copy_n(n_init_to_resp->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_resp_to_init->data(), 4, recv_nonce_prefix_.data());
    } else {
      send_key_.key = *k_resp_to_init;
      recv_key_.key = *k_init_to_resp;
      std::copy_n(n_resp_to_init->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_init_to_resp->data(), 4, recv_nonce_prefix_.data());
    }
    send_key_.counter = 0;
    recv_expected_seq_ = 0;
    return true;
  }

  void send_name_update() {
    if (peer_id_.empty()) return;
    const auto nm = get_self_name_ ? get_self_name_(peer_id_) : std::string();
    if (nm.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = nm;
    send_secure(std::move(inner));
  }

  void send_avatar_update() {
    const auto png = get_self_avatar_png_ ? get_self_avatar_png_() : std::vector<uint8_t>{};
    if (png.empty()) return;
    send_avatar(std::move(png));
  }

  void send_secure(json inner) {
    if (!ready_) return;
    const std::string pt = inner.dump();
    const uint64_t seq = send_key_.counter; // make_nonce increments; keep seq consistent with counter pre-increment.
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = common::make_nonce(send_key_);
    const auto ct = common::aead_encrypt(
        negotiated_cipher_,
        send_key_.key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pt.data()), pt.size()));
    if (!ct) return close();

    json outer;
    outer["type"] = "secure_msg";
    outer["seq"] = static_cast<std::uint64_t>(seq);
    outer["ct"] = common::base64url_encode(*ct);
    writer_->send(std::move(outer));
  }

  std::array<uint8_t, 12> make_recv_nonce(uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = recv_nonce_prefix_[0];
    nonce[1] = recv_nonce_prefix_[1];
    nonce[2] = recv_nonce_prefix_[2];
    nonce[3] = recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  void read_loop_secure() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->close();
      if (!j.contains("type") || !j["type"].is_string()) {
        self->read_loop_secure();
        return;
      }
      const std::string type = j["type"].get<std::string>();
      if (type == "secure_msg") {
        if (!j.contains("seq") || !j["seq"].is_number_unsigned() || !j.contains("ct") || !j["ct"].is_string()) {
          return self->send_error_and_close("bad secure_msg");
        }
        const uint64_t seq = j["seq"].get<std::uint64_t>();
        if (seq != self->recv_expected_seq_) return self->send_error_and_close("out of order");
        const auto ct = common::base64url_decode(j["ct"].get<std::string>());
        if (!ct) return self->send_error_and_close("bad ct");
        const std::string aad = self->transcript_ + "|msg|" + std::to_string(seq);
        const auto nonce = self->make_recv_nonce(seq);
        const auto pt = common::aead_decrypt(
            self->negotiated_cipher_,
            self->recv_key_.key,
            nonce,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
            *ct);
        if (!pt) return self->send_error_and_close("decrypt failed");
        self->recv_expected_seq_++;
        try {
          const std::string s(reinterpret_cast<const char*>(pt->data()), pt->size());
          json inner = json::parse(s);
          self->handle_inner(std::move(inner));
        } catch (...) {
          return self->send_error_and_close("bad inner json");
        }
      }
      self->read_loop_secure();
    });
  }

  void handle_inner(json inner) {
    if (!inner.contains("type") || !inner["type"].is_string()) return;
    const std::string t = inner["type"].get<std::string>();
    if (t == "chat") {
      if (inner.contains("text") && inner["text"].is_string()) {
        const std::string text = inner["text"].get<std::string>();
        if (on_chat_) on_chat_(peer_id_, peer_name_, text);
      }
      return;
    }
    if (t == "name") {
      if (inner.contains("name") && inner["name"].is_string()) {
        peer_name_ = inner["name"].get<std::string>();
        if (on_name_) on_name_(peer_id_, peer_name_);
      }
      return;
    }
    if (t == "avatar") {
      if (!inner.contains("png") || !inner["png"].is_string()) return;
      const auto bytes = common::base64url_decode(inner["png"].get<std::string>());
      if (!bytes) return;
      if (bytes->size() > 48 * 1024) return;
      if (on_avatar_) on_avatar_(peer_id_, *bytes);
      return;
    }
    if (on_control_) on_control_(peer_id_, std::move(inner));
  }

  tcp::socket socket_;
  Role role_;
  std::string self_id_;
  std::shared_ptr<common::Identity> identity_;
  std::function<std::string(const std::string&)> get_self_name_;
  std::function<std::vector<uint8_t>()> get_self_avatar_png_;
  std::string peer_id_;
  std::string peer_name_;
  std::string expected_peer_id_;
  std::function<bool(const std::string&)> allow_peer_;
  common::AeadCipher preferred_cipher_ = kStreamCipher;
  common::AeadCipher negotiated_cipher_ = kStreamCipher;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;
  bool ready_ = false;
  bool closed_ = false;
  OnReady on_ready_;
  OnName on_name_;
  OnAvatar on_avatar_;
  OnChat on_chat_;
  OnControl on_control_;
  OnClosed on_closed_;

  std::optional<common::X25519KeyPair> eph_;
  std::vector<uint8_t> peer_eph_pub_;
  std::string transcript_;
  common::AeadKey send_key_;
  common::AeadKey recv_key_;
  std::array<uint8_t, 4> recv_nonce_prefix_{};
  uint64_t recv_expected_seq_ = 0;
};

class UdpPeerSession : public std::enable_shared_from_this<UdpPeerSession> {
public:
  enum class Role { Initiator, Acceptor };
  using OnReady = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnName = std::function<void(const std::string& peer_id, const std::string& peer_name)>;
  using OnAvatar = std::function<void(const std::string& peer_id, const std::vector<uint8_t>& png_bytes)>;
  using OnChat = std::function<void(const std::string& peer_id, const std::string& peer_name, const std::string& text)>;
  using OnControl = std::function<void(const std::string& peer_id, json inner)>;
  using OnVoice = std::function<void(const std::string& peer_id, uint64_t seq, uint32_t ts, const std::vector<uint8_t>& opus)>;
  using OnVideo = std::function<void(const std::string& peer_id, uint32_t frame_id, bool keyframe, uint32_t pts_ms, const std::vector<uint8_t>& encoded)>;
  using OnClosed = std::function<void()>;

  UdpPeerSession(udp::socket& socket,
                 udp::endpoint peer_ep,
                 Role role,
                 std::string self_id,
                 std::shared_ptr<common::Identity> identity,
                 std::function<std::string(const std::string&)> get_self_name,
                 std::function<std::vector<uint8_t>()> get_self_avatar_png,
                 std::function<bool(const std::string&)> allow_peer,
                 common::AeadCipher preferred_cipher,
                 std::string expected_peer_id = {},
                 std::function<void(const std::string&)> debug_log = {})
      : socket_(socket),
        peer_ep_(std::move(peer_ep)),
        role_(role),
        self_id_(std::move(self_id)),
        identity_(std::move(identity)),
        get_self_name_(std::move(get_self_name)),
        get_self_avatar_png_(std::move(get_self_avatar_png)),
        allow_peer_(std::move(allow_peer)),
        preferred_cipher_(preferred_cipher),
        negotiated_cipher_(kStreamCipher),
        expected_peer_id_(std::move(expected_peer_id)),
        debug_log_(std::move(debug_log)),
        punch_timer_(socket_.get_executor()),
        hs_timer_(socket_.get_executor()),
        data_timer_(socket_.get_executor()),
        deadline_timer_(socket_.get_executor()),
        keepalive_timer_(socket_.get_executor()) {}

  void start(OnReady on_ready,
             OnName on_name,
             OnAvatar on_avatar,
             OnChat on_chat,
             OnControl on_control,
             OnVoice on_voice,
             OnVideo on_video,
             OnClosed on_closed) {
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_avatar_ = std::move(on_avatar);
    on_chat_ = std::move(on_chat);
    on_control_ = std::move(on_control);
    on_voice_ = std::move(on_voice);
    on_video_ = std::move(on_video);
    on_closed_ = std::move(on_closed);
    dlog(std::string("start role=") + (role_ == Role::Initiator ? "initiator" : "acceptor") +
         " peer_ep=" + common::endpoint_to_string(peer_ep_) + " expected_peer_id=" + expected_peer_id_);
    schedule_punch();
    schedule_deadline();
    if (role_ == Role::Initiator) {
      send_secure_hello();
    }
  }

  void start_accept_with_first(const json& first, const udp::endpoint& from, OnReady on_ready, OnName on_name,
                               OnAvatar on_avatar, OnChat on_chat, OnControl on_control, OnVoice on_voice, OnVideo on_video,
                               OnClosed on_closed) {
    peer_ep_ = from;
    on_ready_ = std::move(on_ready);
    on_name_ = std::move(on_name);
    on_avatar_ = std::move(on_avatar);
    on_chat_ = std::move(on_chat);
    on_control_ = std::move(on_control);
    on_voice_ = std::move(on_voice);
    on_video_ = std::move(on_video);
    on_closed_ = std::move(on_closed);
    schedule_punch();
    schedule_deadline();
    handle_datagram(first, from);
  }

  void handle_datagram(const json& j, const udp::endpoint& from) {
    if (closed_) return;
    // Lock peer endpoint once we have it (initiator already has it; acceptor learns it from first packet).
    if (peer_ep_.port() != 0 && from != peer_ep_) {
      // Before the handshake is confirmed, allow the peer's NAT mapping to "settle" to a final port.
      if (!ready_confirmed_ && from.address() == peer_ep_.address()) {
        peer_ep_ = from;
      } else {
        return;
      }
    }

    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();
    if (type == "punch") return;
    if (type == "secure_hello") return handle_secure_hello(j);
    if (type == "secure_hello_ack") return handle_secure_hello_ack(j);
    if (type == "secure_finish") return handle_secure_finish(j);
    if (type == "secure_msg") return handle_secure_msg(j);
    if (type == "ack") return handle_ack(j);
    if (type == "busy" || type == "error") return close();
  }

  void send_chat(std::string text) {
    if (text.empty()) return;
    json inner;
    inner["type"] = "chat";
    inner["text"] = std::move(text);
    enqueue_secure(std::move(inner));
  }

  void send_name(std::string name) {
    if (name.empty()) return;
    json inner;
    inner["type"] = "name";
    inner["name"] = std::move(name);
    enqueue_secure(std::move(inner));
  }

  void send_avatar(std::vector<uint8_t> png) {
    if (png.empty()) return;
    if (png.size() > 48 * 1024) return;
    json inner;
    inner["type"] = "avatar";
    inner["png"] = common::base64url_encode(png);
    enqueue_secure(std::move(inner));
  }

  void send_control(json inner) { enqueue_secure(std::move(inner)); }

#if defined(P2PCHAT_VIDEO)
  void pump_video_send_queue() {
    if (closed_) {
      video_send_inflight_ = false;
      video_send_queue_.clear();
      video_send_queue_bytes_ = 0;
      return;
    }
    if (video_send_inflight_) return;
    if (video_send_queue_.empty()) return;
    if (peer_ep_.port() == 0) return;
    video_send_inflight_ = true;
    auto buf = video_send_queue_.front();
    auto self = shared_from_this();
    socket_.async_send_to(boost::asio::buffer(*buf), peer_ep_, [self, buf](const boost::system::error_code&, std::size_t) {
      if (!self->video_send_queue_.empty()) {
        const auto sent = self->video_send_queue_.front();
        if (sent) {
          if (self->video_send_queue_bytes_ >= sent->size()) {
            self->video_send_queue_bytes_ -= sent->size();
          } else {
            self->video_send_queue_bytes_ = 0;
          }
        }
        self->video_send_queue_.pop_front();
      }
      self->video_send_inflight_ = false;
      self->pump_video_send_queue();
    });
  }

  bool enqueue_video_packet(std::shared_ptr<std::vector<uint8_t>> buf) {
    if (!buf || buf->empty()) return false;
    constexpr std::size_t kMaxVideoQueuePackets = 256;
    constexpr std::size_t kMaxVideoQueueBytes = 2 * 1024 * 1024;
    if (video_send_queue_.size() >= kMaxVideoQueuePackets ||
        (video_send_queue_bytes_ + buf->size()) > kMaxVideoQueueBytes) {
      video_tx_drop_queue_++;
      if (debug_logs_enabled() && (video_tx_drop_queue_ % 50) == 1) {
        dlog("video tx drop: queue full packets=" + std::to_string(video_send_queue_.size()) +
             " bytes=" + std::to_string(video_send_queue_bytes_));
      }
      return false;
    }
    video_send_queue_bytes_ += buf->size();
    video_send_queue_.push_back(std::move(buf));
    pump_video_send_queue();
    return true;
  }
#endif

  void send_video_frame(const std::vector<uint8_t>& encoded, bool keyframe, uint32_t pts_ms) {
#if !defined(P2PCHAT_VIDEO)
    (void)encoded;
    (void)keyframe;
    (void)pts_ms;
    return;
#else
    if (!voice_ready()) return;
    if (peer_ep_.port() == 0) return;
    if (encoded.empty()) return;
    constexpr std::size_t kVideoDropNonKeyQueuePackets = 96;
    constexpr std::size_t kVideoDropAnyQueuePackets = 220;
    if (!keyframe && video_send_queue_.size() >= kVideoDropNonKeyQueuePackets) {
      if (debug_logs_enabled() && ((++video_tx_drop_queue_) % 50) == 1) {
        dlog("video tx drop: congestion(non-key) queue_packets=" + std::to_string(video_send_queue_.size()));
      }
      return;
    }
    if (video_send_queue_.size() >= kVideoDropAnyQueuePackets) {
      if (debug_logs_enabled() && ((++video_tx_drop_queue_) % 50) == 1) {
        dlog("video tx drop: congestion(hard) queue_packets=" + std::to_string(video_send_queue_.size()));
      }
      return;
    }

    video::VideoPktHdr h {};
    h.flags = keyframe ? video::kVideoFlagKeyframe : 0;
    h.streamId = video_stream_id_;
    h.frameId = video_next_frame_id_++;
    h.ptsMs = pts_ms;
    auto packets = video::packetizeFrame(h, encoded.data(), encoded.size(), 1200);
    for (const auto& pkt : packets) {
      video::ParsedPacket parsed;
      if (!video::parsePacket(pkt.data(), pkt.size(), &parsed)) continue;
      const uint64_t nonce_seq = (static_cast<uint64_t>(parsed.hdr.frameId) << 16) | parsed.hdr.fragIndex;
      const std::string aad = transcript_ + "|video|" + std::to_string(parsed.hdr.frameId) + "|" +
                              std::to_string(parsed.hdr.fragIndex) + "|" + std::to_string(parsed.hdr.fragCount);
      auto key = voice_send_key_;
      key.counter = nonce_seq;
      const auto nonce = common::make_nonce(key);
      const auto ct = common::aead_encrypt(
          negotiated_cipher_,
          voice_send_key_.key,
          nonce,
          std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
          std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));
      if (!ct) continue;

      std::vector<uint8_t> out(sizeof(video::VideoPktHdr) + ct->size());
      write_u32be(out.data() + 0, kVideoMagic);
      out[4] = kVideoVersion;
      out[5] = parsed.hdr.flags;
      write_u16be(out.data() + 6, static_cast<uint16_t>(sizeof(video::VideoPktHdr)));
      write_u32be(out.data() + 8, parsed.hdr.streamId);
      write_u32be(out.data() + 12, parsed.hdr.frameId);
      write_u16be(out.data() + 16, parsed.hdr.fragIndex);
      write_u16be(out.data() + 18, parsed.hdr.fragCount);
      write_u32be(out.data() + 20, parsed.hdr.ptsMs);
      std::memcpy(out.data() + sizeof(video::VideoPktHdr), ct->data(), ct->size());
      auto buf = std::make_shared<std::vector<uint8_t>>(std::move(out));
      enqueue_video_packet(std::move(buf));
    }
#endif
  }

  bool voice_ready() const { return ready_ && ready_confirmed_ && !closed_; }

  void set_voice_frame_ms(int frame_ms) {
#if defined(P2PCHAT_VOICE)
    if (frame_ms != 10 && frame_ms != 20) frame_ms = 20;
    voice_frame_samples_ = 48000 * frame_ms / 1000;
#else
    (void)frame_ms;
#endif
  }

  void send_voice_frame(std::vector<uint8_t> opus_frame) {
#if !defined(P2PCHAT_VOICE)
    (void)opus_frame;
    return;
#else
    if (!voice_ready()) {
      if (debug_logs_enabled()) {
        voice_tx_drop_not_ready_++;
        if ((voice_tx_drop_not_ready_ % 200) == 1) {
          dlog("voice tx drop: not ready (ready=" + std::to_string(ready_) + " confirmed=" +
               std::to_string(ready_confirmed_) + " closed=" + std::to_string(closed_) + ")");
        }
      }
      return;
    }
    if (opus_frame.empty()) return;
    if (opus_frame.size() > 1200) {
      if (debug_logs_enabled()) dlog("voice tx drop: opus_frame too big=" + std::to_string(opus_frame.size()));
      return; // conservative MTU-ish cap
    }
    if (peer_ep_.port() == 0) {
      if (debug_logs_enabled()) dlog("voice tx drop: peer_ep port=0");
      return;
    }

    const uint64_t seq = voice_send_key_.counter;
    const std::string aad = transcript_ + "|voice|" + std::to_string(seq);
    const auto nonce = common::make_nonce(voice_send_key_);
    const auto ct = common::aead_encrypt(
        negotiated_cipher_,
        voice_send_key_.key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(opus_frame.data(), opus_frame.size()));
    if (!ct) {
      if (debug_logs_enabled()) dlog("voice tx encrypt failed seq=" + std::to_string(seq));
      return;
    }

    voice_timestamp_ += static_cast<uint32_t>(voice_frame_samples_);
    const uint32_t ts = voice_timestamp_;

    const uint16_t ct_len = static_cast<uint16_t>(ct->size());
    std::vector<uint8_t> pkt;
    pkt.resize(20u + ct_len);
    write_u32be(pkt.data(), kVoiceMagic);
    pkt[4] = kVoiceVersion;
    pkt[5] = 0;
    write_u64be(pkt.data() + 6, seq);
    write_u32be(pkt.data() + 14, ts);
    write_u16be(pkt.data() + 18, ct_len);
    std::memcpy(pkt.data() + 20, ct->data(), ct_len);

    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(pkt));
    if (debug_logs_enabled()) {
      voice_tx_ok_++;
      if ((voice_tx_ok_ % 50) == 1) {
        dlog("voice tx ok seq=" + std::to_string(seq) + " ts=" + std::to_string(ts) + " ct_len=" +
             std::to_string(ct_len) + " to=" + common::endpoint_to_string(peer_ep_));
      }
    }
    socket_.async_send_to(boost::asio::buffer(*buf), peer_ep_, [buf](const boost::system::error_code&, std::size_t) {});
#endif
  }

  void close() {
    if (closed_) return;
    closed_ = true;
    punch_timer_.cancel();
    hs_timer_.cancel();
    data_timer_.cancel();
    deadline_timer_.cancel();
    keepalive_timer_.cancel();
    if (on_closed_) on_closed_();
  }

  std::string_view peer_id() const { return peer_id_; }
  std::string_view peer_name() const { return peer_name_; }
  const udp::endpoint& peer_endpoint() const { return peer_ep_; }

  void handle_voice_packet(uint64_t seq, uint32_t ts, std::span<const uint8_t> ct, const udp::endpoint& from) {
#if !defined(P2PCHAT_VOICE)
    (void)seq;
    (void)ts;
    (void)ct;
    (void)from;
    return;
#else
    if (!voice_ready()) return;
    if (from != peer_ep_) return;
    if (ct.size() < 16) return;

    const std::string aad = transcript_ + "|voice|" + std::to_string(seq);
    const auto nonce = make_voice_recv_nonce(seq);
    const auto pt = common::aead_decrypt(
        negotiated_cipher_,
        voice_recv_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        ct);
    if (!pt) {
      if (debug_logs_enabled()) {
        voice_rx_decrypt_fail_++;
        if ((voice_rx_decrypt_fail_ % 200) == 1) {
          dlog("voice rx decrypt failed count=" + std::to_string(voice_rx_decrypt_fail_) + " seq=" + std::to_string(seq) +
               " ct_len=" + std::to_string(ct.size()));
        }
      }
      return;
    }
    if (pt->size() > 1200) return;
    if (debug_logs_enabled()) {
      voice_rx_ok_++;
      if ((voice_rx_ok_ % 50) == 1) {
        dlog("voice rx ok seq=" + std::to_string(seq) + " ts=" + std::to_string(ts) + " opus_len=" +
             std::to_string(pt->size()));
      }
    }
    if (on_voice_) on_voice_(peer_id_, seq, ts, *pt);
#endif
  }

  void handle_video_packet(std::span<const uint8_t> pkt, const udp::endpoint& from) {
#if !defined(P2PCHAT_VIDEO)
    (void)pkt;
    (void)from;
    return;
#else
    if (!voice_ready()) return;
    if (from != peer_ep_) return;
    video::ParsedPacket parsed;
    if (!video::parsePacket(pkt.data(), pkt.size(), &parsed)) return;
    const uint64_t nonce_seq = (static_cast<uint64_t>(parsed.hdr.frameId) << 16) | parsed.hdr.fragIndex;
    const std::string aad = transcript_ + "|video|" + std::to_string(parsed.hdr.frameId) + "|" +
                            std::to_string(parsed.hdr.fragIndex) + "|" + std::to_string(parsed.hdr.fragCount);
    std::array<uint8_t, 12> nonce{};
    nonce[0] = voice_recv_nonce_prefix_[0];
    nonce[1] = voice_recv_nonce_prefix_[1];
    nonce[2] = voice_recv_nonce_prefix_[2];
    nonce[3] = voice_recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((nonce_seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((nonce_seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((nonce_seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((nonce_seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((nonce_seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((nonce_seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((nonce_seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(nonce_seq & 0xFF);
    const auto pt = common::aead_decrypt(
        negotiated_cipher_,
        voice_recv_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(parsed.payload.data(), parsed.payload.size()));
    if (!pt) {
      if (debug_logs_enabled()) dlog("video rx decrypt failed frame=" + std::to_string(parsed.hdr.frameId) +
                                     " frag=" + std::to_string(parsed.hdr.fragIndex));
      return;
    }
    video::ParsedPacket plain = parsed;
    plain.payload.assign(pt->begin(), pt->end());
    const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::steady_clock::now().time_since_epoch())
                                                     .count());
    auto complete = video_reasm_.add(plain, nowMs);
    video_reasm_.expire(nowMs, kVideoFrameExpireMs);
    if (!complete) return;
    video_jitter_.push(std::move(*complete), nowMs);
    while (auto ready = video_jitter_.pop(nowMs, kVideoJitterWaitMs)) {
      if (debug_logs_enabled() && ((ready->frameId % 60u) == 0u)) {
        dlog("video rx frame ready frame=" + std::to_string(ready->frameId) +
             " bytes=" + std::to_string(ready->bytes.size()));
      }
      if (on_video_) on_video_(peer_id_, ready->frameId, ready->keyframe, ready->ptsMs, ready->bytes);
    }
#endif
  }

private:
  static constexpr std::string_view kProto = "p2p-chat-secure-v1";

  static std::vector<uint8_t> bytes(std::string_view s) {
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(s.data()),
                                reinterpret_cast<const uint8_t*>(s.data() + s.size()));
  }

  static std::string transcript_string(std::string_view init_id,
                                       std::string_view init_eph_b64,
                                       std::string_view resp_id,
                                       std::string_view resp_eph_b64) {
    std::string t;
    t.reserve(kProto.size() + init_id.size() + init_eph_b64.size() + resp_id.size() + resp_eph_b64.size() + 16);
    t.append(kProto);
    t.push_back('|');
    t.append(init_id);
    t.push_back('|');
    t.append(init_eph_b64);
    t.push_back('|');
    t.append(resp_id);
    t.push_back('|');
    t.append(resp_eph_b64);
    return t;
  }

  void send_datagram(const json& j) {
    auto framed = common::frame_json_bytes(j);
    if (!framed) return;
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(*framed));
    auto self = shared_from_this();
    socket_.async_send_to(boost::asio::buffer(*buf), peer_ep_, [self, buf](const boost::system::error_code&, std::size_t) {});
  }

  void send_punch_once() {
    json p;
    p["type"] = "punch";
    send_datagram(p);
  }

  void schedule_punch() {
    if (closed_) return;
    if (punch_remaining_ == 0) return;
    send_punch_once();
    punch_remaining_--;
    auto self = shared_from_this();
    punch_timer_.expires_after(kUdpPunchInterval);
    punch_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      self->schedule_punch();
    });
  }

  void schedule_deadline() {
    auto self = shared_from_this();
    deadline_timer_.expires_after(std::chrono::seconds(25));
    deadline_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_) return;
      if (!self->ready_confirmed_) self->close();
    });
  }

  void schedule_keepalive() {
    if (closed_ || !ready_confirmed_) return;
    auto self = shared_from_this();
    keepalive_timer_.expires_after(std::chrono::seconds(15));
    keepalive_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_) return;
      if (self->ready_confirmed_) self->send_punch_once();
      self->schedule_keepalive();
    });
  }

  void send_secure_hello() {
    if (!identity_) return close();
    if (hello_sent_) return;
    eph_ = common::x25519_generate();
    const std::string eph_b64 = common::base64url_encode(eph_->public_key);
    const std::string sig_msg = std::string(kProto) + "|init|" + self_id_ + "|" + eph_b64;
    const std::string sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(sig_msg.data()), sig_msg.size()));
    if (sig.empty()) return close();

    json hello;
    hello["type"] = "secure_hello";
    hello["id"] = self_id_;
    hello["eph"] = eph_b64;
    hello["sig"] = sig;
    hello["aead_pref"] = stream_cipher_to_wire(kStreamCipher);
    hello["aead_supported"] = supported_stream_ciphers_wire();

    hello_sent_ = true;
    last_hs_msg_ = hello;
    send_datagram(hello);
    dlog("sent secure_hello");
    schedule_hs_resend();
  }

  void schedule_hs_resend() {
    if (closed_) return;
    if (ready_confirmed_) return;
    if (last_hs_msg_.is_null()) return;
    auto self = shared_from_this();
    hs_timer_.expires_after(kUdpHandshakeResend);
    hs_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_ || self->ready_confirmed_) return;
      if (self->last_hs_msg_.is_null()) return;
      if (++self->hs_retries_ > 30) return self->close();
      self->send_datagram(self->last_hs_msg_);
      self->schedule_hs_resend();
    });
  }

  void handle_secure_hello(const json& j) {
    if (role_ != Role::Acceptor) return;
    if (!identity_) return close();
    if (!j.contains("id") || !j["id"].is_string()) return close();
    if (!j.contains("eph") || !j["eph"].is_string()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();

    const std::string init_id = j["id"].get<std::string>();
    if (!common::is_valid_id(init_id)) return close();
    if (allow_peer_ && !allow_peer_(init_id)) {
      dlog("reject secure_hello: allow_peer=false id=" + init_id);
      return close();
    }
    if (!supports_stream_cipher(j, kStreamCipher)) return close();
    negotiated_cipher_ = kStreamCipher;

    const std::string init_eph_b64 = j["eph"].get<std::string>();
    const auto init_eph = common::base64url_decode(init_eph_b64);
    if (!init_eph || init_eph->size() != 32) return close();

    const std::string sig_msg = std::string(kProto) + "|init|" + init_id + "|" + init_eph_b64;
    const auto sig_msg_bytes = bytes(sig_msg);
    if (!common::Identity::verify_bytes_b64url(init_id, sig_msg_bytes, j["sig"].get<std::string>())) return close();

    peer_id_ = init_id;
    peer_eph_pub_ = *init_eph;
    eph_ = common::x25519_generate();
    const std::string resp_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(init_id, init_eph_b64, self_id_, resp_eph_b64);

    const std::string ack_msg = transcript_ + "|resp";
    const std::string ack_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(ack_msg.data()), ack_msg.size()));
    if (ack_sig.empty()) return close();

    json ack;
    ack["type"] = "secure_hello_ack";
    ack["id"] = self_id_;
    ack["eph"] = resp_eph_b64;
    ack["sig"] = ack_sig;
    ack["aead"] = stream_cipher_to_wire(negotiated_cipher_);
    last_hs_msg_ = ack;
    send_datagram(ack);
    dlog("sent secure_hello_ack peer_id=" + peer_id_);
    // Wait for finish; keep resending ack for a short while (duplicate hellos will also refresh it).
    schedule_hs_resend();
  }

  void handle_secure_hello_ack(const json& j) {
    if (role_ != Role::Initiator) return;
    if (!identity_ || !eph_) return close();
    if (!j.contains("id") || !j["id"].is_string()) return close();
    if (!j.contains("eph") || !j["eph"].is_string()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();

    const std::string resp_id = j["id"].get<std::string>();
    if (!common::is_valid_id(resp_id)) return close();
    if (!expected_peer_id_.empty() && resp_id != expected_peer_id_) return close();
    if (allow_peer_ && !allow_peer_(resp_id)) return close();

    const std::string resp_eph_b64 = j["eph"].get<std::string>();
    const auto resp_eph = common::base64url_decode(resp_eph_b64);
    if (!resp_eph || resp_eph->size() != 32) return close();

    const std::string init_eph_b64 = common::base64url_encode(eph_->public_key);
    transcript_ = transcript_string(self_id_, init_eph_b64, resp_id, resp_eph_b64);
    const std::string ack_msg = transcript_ + "|resp";
    const auto ack_msg_bytes = bytes(ack_msg);
    if (!common::Identity::verify_bytes_b64url(resp_id, ack_msg_bytes, j["sig"].get<std::string>())) return close();

    peer_id_ = resp_id;
    peer_eph_pub_ = *resp_eph;
    if (!j.contains("aead") || !j["aead"].is_string() ||
        common::aead_cipher_from_string(j["aead"].get<std::string>()) != kStreamCipher) {
      return close();
    }
    negotiated_cipher_ = kStreamCipher;

    const std::string fin_msg = transcript_ + "|init";
    const std::string fin_sig = identity_->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(fin_msg.data()), fin_msg.size()));
    if (fin_sig.empty()) return close();
    json fin;
    fin["type"] = "secure_finish";
    fin["sig"] = fin_sig;
    last_hs_msg_ = fin;
    send_datagram(fin);
    dlog("sent secure_finish");

    if (!derive_keys()) return close();
    ready_ = true;
    if (on_ready_) on_ready_(peer_id_, peer_name_);
    send_name_update();
    send_avatar_update();
    try_send_next();
    dlog("handshake ready (initiator) peer_id=" + peer_id_);
    // Keep resending finish until the peer proves readiness (ack/secure_msg).
    schedule_hs_resend();
  }

  void handle_secure_finish(const json& j) {
    if (role_ != Role::Acceptor) return;
    if (!identity_ || transcript_.empty() || peer_id_.empty()) return close();
    if (!j.contains("sig") || !j["sig"].is_string()) return close();
    const std::string fin_sig = j["sig"].get<std::string>();
    const std::string fin_msg = transcript_ + "|init";
    const auto fin_msg_bytes = bytes(fin_msg);
    if (!common::Identity::verify_bytes_b64url(peer_id_, fin_msg_bytes, fin_sig)) return close();

    if (!derive_keys()) return close();
    ready_ = true;
    ready_confirmed_ = true; // acceptor knows both sides are ready at this point
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    schedule_keepalive();
    if (on_ready_) on_ready_(peer_id_, peer_name_);
    send_name_update();
    send_avatar_update();
    try_send_next();
    dlog("handshake ready (acceptor) peer_id=" + peer_id_);
  }

  bool derive_keys() {
    if (!eph_) return false;
    if (peer_eph_pub_.size() != 32) return false;

    const auto shared = common::x25519_derive_shared_secret(eph_->pkey.get(), peer_eph_pub_);
    if (!shared) return false;

    const auto salt = common::sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(transcript_.data()), transcript_.size()));

    auto hkdf32 = [&](std::string_view info) -> std::optional<std::array<uint8_t, 32>> {
      return common::hkdf_sha256_32(*shared, salt, info);
    };

    const auto k_init_to_resp = hkdf32(std::string(kProto) + " key init->resp");
    const auto k_resp_to_init = hkdf32(std::string(kProto) + " key resp->init");
    const auto n_init_to_resp = hkdf32(std::string(kProto) + " nonce init->resp");
    const auto n_resp_to_init = hkdf32(std::string(kProto) + " nonce resp->init");
    const auto vk_init_to_resp = hkdf32(std::string(kProto) + " voice key init->resp");
    const auto vk_resp_to_init = hkdf32(std::string(kProto) + " voice key resp->init");
    const auto vn_init_to_resp = hkdf32(std::string(kProto) + " voice nonce init->resp");
    const auto vn_resp_to_init = hkdf32(std::string(kProto) + " voice nonce resp->init");
    const auto ak_init_to_resp = hkdf32(std::string(kProto) + " ack key init->resp");
    const auto ak_resp_to_init = hkdf32(std::string(kProto) + " ack key resp->init");
    const auto an_init_to_resp = hkdf32(std::string(kProto) + " ack nonce init->resp");
    const auto an_resp_to_init = hkdf32(std::string(kProto) + " ack nonce resp->init");
    if (!k_init_to_resp || !k_resp_to_init || !n_init_to_resp || !n_resp_to_init ||
        !vk_init_to_resp || !vk_resp_to_init || !vn_init_to_resp || !vn_resp_to_init ||
        !ak_init_to_resp || !ak_resp_to_init || !an_init_to_resp || !an_resp_to_init) return false;

    if (role_ == Role::Initiator) {
      send_key_.key = *k_init_to_resp;
      recv_key_.key = *k_resp_to_init;
      std::copy_n(n_init_to_resp->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_resp_to_init->data(), 4, recv_nonce_prefix_.data());

      voice_send_key_.key = *vk_init_to_resp;
      voice_recv_key_ = *vk_resp_to_init;
      std::copy_n(vn_init_to_resp->data(), 4, voice_send_key_.nonce_prefix.data());
      std::copy_n(vn_resp_to_init->data(), 4, voice_recv_nonce_prefix_.data());

      ack_send_key_ = *ak_resp_to_init;
      ack_recv_key_ = *ak_init_to_resp;
      std::copy_n(an_resp_to_init->data(), 4, ack_send_nonce_prefix_.data());
      std::copy_n(an_init_to_resp->data(), 4, ack_recv_nonce_prefix_.data());
    } else {
      send_key_.key = *k_resp_to_init;
      recv_key_.key = *k_init_to_resp;
      std::copy_n(n_resp_to_init->data(), 4, send_key_.nonce_prefix.data());
      std::copy_n(n_init_to_resp->data(), 4, recv_nonce_prefix_.data());

      voice_send_key_.key = *vk_resp_to_init;
      voice_recv_key_ = *vk_init_to_resp;
      std::copy_n(vn_resp_to_init->data(), 4, voice_send_key_.nonce_prefix.data());
      std::copy_n(vn_init_to_resp->data(), 4, voice_recv_nonce_prefix_.data());

      ack_send_key_ = *ak_init_to_resp;
      ack_recv_key_ = *ak_resp_to_init;
      std::copy_n(an_init_to_resp->data(), 4, ack_send_nonce_prefix_.data());
      std::copy_n(an_resp_to_init->data(), 4, ack_recv_nonce_prefix_.data());
    }
    send_key_.counter = 0;
    recv_expected_seq_ = 0;
    voice_send_key_.counter = 0;
    voice_timestamp_ = 0;
    voice_frame_samples_ = 960; // default 20ms @ 48kHz mono
    dlog("keys derived ok aead=" + stream_cipher_to_wire(negotiated_cipher_));
    return true;
  }

  void send_name_update() {
    if (peer_id_.empty()) return;
    const auto nm = get_self_name_ ? get_self_name_(peer_id_) : std::string();
    if (nm.empty()) return;
    send_name(nm);
  }

  void send_avatar_update() {
    const auto png = get_self_avatar_png_ ? get_self_avatar_png_() : std::vector<uint8_t>{};
    if (png.empty()) return;
    send_avatar(std::move(png));
  }

  void enqueue_secure(json inner) {
    if (closed_) return;
    send_queue_.push_back(std::move(inner));
    // Cap pre-handshake queue size.
    if (send_queue_.size() > 256) send_queue_.pop_front();
    if (ready_) try_send_next();
  }

  void try_send_next() {
    if (!ready_ || closed_ || inflight_) return;
    if (send_queue_.empty()) return;
    json inner = std::move(send_queue_.front());
    send_queue_.pop_front();

    const std::string pt = inner.dump();
    const uint64_t seq = send_key_.counter;
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = common::make_nonce(send_key_);
    const auto ct = common::aead_encrypt(
        negotiated_cipher_,
        send_key_.key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(pt.data()), pt.size()));
    if (!ct) return close();

    json outer;
    outer["type"] = "secure_msg";
    outer["seq"] = static_cast<std::uint64_t>(seq);
    outer["ct"] = common::base64url_encode(*ct);

    inflight_ = true;
    inflight_seq_ = seq;
    inflight_outer_ = outer;
    inflight_retries_ = 0;
    send_datagram(outer);
    schedule_data_resend();
  }

  void schedule_data_resend() {
    if (closed_) return;
    if (!inflight_) return;
    auto self = shared_from_this();
    data_timer_.expires_after(kUdpDataResend);
    data_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      if (self->closed_ || !self->inflight_) return;
      if (++self->inflight_retries_ > 12) return self->close();
      self->send_datagram(self->inflight_outer_);
      self->schedule_data_resend();
    });
  }

  std::array<uint8_t, 12> make_recv_nonce(uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = recv_nonce_prefix_[0];
    nonce[1] = recv_nonce_prefix_[1];
    nonce[2] = recv_nonce_prefix_[2];
    nonce[3] = recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  std::array<uint8_t, 12> make_voice_recv_nonce(uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = voice_recv_nonce_prefix_[0];
    nonce[1] = voice_recv_nonce_prefix_[1];
    nonce[2] = voice_recv_nonce_prefix_[2];
    nonce[3] = voice_recv_nonce_prefix_[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  std::array<uint8_t, 12> make_ack_nonce(std::array<uint8_t, 4> prefix, uint64_t seq) const {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = prefix[0];
    nonce[1] = prefix[1];
    nonce[2] = prefix[2];
    nonce[3] = prefix[3];
    nonce[4] = static_cast<uint8_t>((seq >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((seq >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((seq >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((seq >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(seq & 0xFF);
    return nonce;
  }

  void send_ack(uint64_t seq) {
    if (!ready_) return;
    const std::string aad = transcript_ + "|ack|" + std::to_string(seq);
    const auto nonce = make_ack_nonce(ack_send_nonce_prefix_, seq);
    const auto tag = common::aead_encrypt(
        negotiated_cipher_,
        ack_send_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        std::span<const uint8_t>{});
    if (!tag || tag->size() != 16) return;
    json a;
    a["type"] = "ack";
    a["seq"] = static_cast<std::uint64_t>(seq);
    a["tag"] = common::base64url_encode(*tag);
    send_datagram(a);
  }

  void handle_ack(const json& j) {
    if (!inflight_ || !ready_) return;
    if (!j.contains("seq") || !j["seq"].is_number_unsigned()) return;
    if (!j.contains("tag") || !j["tag"].is_string()) return;
    const uint64_t seq = j["seq"].get<std::uint64_t>();
    if (seq != inflight_seq_) return;
    const auto tag = common::base64url_decode(j["tag"].get<std::string>());
    if (!tag || tag->size() != 16) return;
    const std::string aad = transcript_ + "|ack|" + std::to_string(seq);
    const auto nonce = make_ack_nonce(ack_recv_nonce_prefix_, seq);
    const auto pt = common::aead_decrypt(
        negotiated_cipher_,
        ack_recv_key_,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        *tag);
    if (!pt || !pt->empty()) return;

    inflight_ = false;
    ready_confirmed_ = true;
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    data_timer_.cancel();
    schedule_keepalive();
    try_send_next();
  }

  void handle_secure_msg(const json& j) {
    if (!ready_) return;
    if (!j.contains("seq") || !j["seq"].is_number_unsigned()) return;
    if (!j.contains("ct") || !j["ct"].is_string()) return;
    const uint64_t seq = j["seq"].get<std::uint64_t>();

    if (seq < recv_expected_seq_) {
      send_ack(seq);
      return;
    }
    if (seq != recv_expected_seq_) return;

    const auto ct = common::base64url_decode(j["ct"].get<std::string>());
    if (!ct) return;
    const std::string aad = transcript_ + "|msg|" + std::to_string(seq);
    const auto nonce = make_recv_nonce(seq);
    const auto pt = common::aead_decrypt(
        negotiated_cipher_,
        recv_key_.key,
        nonce,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(aad.data()), aad.size()),
        *ct);
    if (!pt) return;
    recv_expected_seq_++;
    send_ack(seq);

    ready_confirmed_ = true;
    last_hs_msg_ = json{};
    hs_timer_.cancel();
    deadline_timer_.cancel();
    schedule_keepalive();

    try {
      const std::string s(reinterpret_cast<const char*>(pt->data()), pt->size());
      json inner = json::parse(s);
      handle_inner(std::move(inner));
    } catch (...) {
      return;
    }
  }

  void handle_inner(json inner) {
    if (!inner.contains("type") || !inner["type"].is_string()) return;
    const std::string t = inner["type"].get<std::string>();
    if (t == "chat") {
      if (inner.contains("text") && inner["text"].is_string()) {
        const std::string text = inner["text"].get<std::string>();
        if (on_chat_) on_chat_(peer_id_, peer_name_, text);
      }
      return;
    }
    if (t == "name") {
      if (inner.contains("name") && inner["name"].is_string()) {
        peer_name_ = inner["name"].get<std::string>();
        if (on_name_) on_name_(peer_id_, peer_name_);
      }
      return;
    }
    if (t == "avatar") {
      if (!inner.contains("png") || !inner["png"].is_string()) return;
      const auto bytes = common::base64url_decode(inner["png"].get<std::string>());
      if (!bytes) return;
      if (bytes->size() > 48 * 1024) return;
      if (on_avatar_) on_avatar_(peer_id_, *bytes);
      return;
    }
    if (on_control_) on_control_(peer_id_, std::move(inner));
  }

  void dlog(const std::string& msg) const {
    if (!debug_logs_enabled()) return;
    if (!debug_log_) return;
    const std::string who = !peer_id_.empty() ? peer_id_ : expected_peer_id_;
    debug_log_("udp[" + who + "] " + msg);
  }

  udp::socket& socket_;
  udp::endpoint peer_ep_;
  Role role_;
  std::string self_id_;
  std::shared_ptr<common::Identity> identity_;
  std::function<std::string(const std::string&)> get_self_name_;
  std::function<std::vector<uint8_t>()> get_self_avatar_png_;
  std::string peer_id_;
  std::string peer_name_;
  std::string expected_peer_id_;
  std::function<bool(const std::string&)> allow_peer_;
  common::AeadCipher preferred_cipher_ = kStreamCipher;
  common::AeadCipher negotiated_cipher_ = kStreamCipher;
  std::function<void(const std::string&)> debug_log_;
  bool ready_ = false;
  bool closed_ = false;
  bool hello_sent_ = false;
  bool ready_confirmed_ = false;

  OnReady on_ready_;
  OnName on_name_;
  OnAvatar on_avatar_;
  OnChat on_chat_;
  OnControl on_control_;
  OnVoice on_voice_;
  OnVideo on_video_;
  OnClosed on_closed_;

  boost::asio::steady_timer punch_timer_;
  boost::asio::steady_timer hs_timer_;
  boost::asio::steady_timer data_timer_;
  boost::asio::steady_timer deadline_timer_;
  boost::asio::steady_timer keepalive_timer_;
  int punch_remaining_ = 24;
  int hs_retries_ = 0;

  std::optional<common::X25519KeyPair> eph_;
  std::vector<uint8_t> peer_eph_pub_;
  std::string transcript_;

  json last_hs_msg_{};

  common::AeadKey send_key_;
  common::AeadKey recv_key_;
  std::array<uint8_t, 4> recv_nonce_prefix_{};
  uint64_t recv_expected_seq_ = 0;

  common::AeadKey voice_send_key_;
  std::array<uint8_t, 32> voice_recv_key_{};
  std::array<uint8_t, 4> voice_recv_nonce_prefix_{};
  uint32_t voice_timestamp_ = 0;
  int voice_frame_samples_ = 960;
  uint64_t voice_tx_ok_ = 0;
  uint64_t voice_tx_drop_not_ready_ = 0;
  uint64_t voice_rx_ok_ = 0;
  uint64_t voice_rx_decrypt_fail_ = 0;
  uint32_t video_stream_id_ = 1;
  uint32_t video_next_frame_id_ = 1;
  bool video_send_inflight_ = false;
  std::size_t video_send_queue_bytes_ = 0;
  uint64_t video_tx_drop_queue_ = 0;
  std::deque<std::shared_ptr<std::vector<uint8_t>>> video_send_queue_;
  video::Reassembler video_reasm_;
  video::JitterBuffer video_jitter_;

  std::array<uint8_t, 32> ack_send_key_{};
  std::array<uint8_t, 32> ack_recv_key_{};
  std::array<uint8_t, 4> ack_send_nonce_prefix_{};
  std::array<uint8_t, 4> ack_recv_nonce_prefix_{};

  std::deque<json> send_queue_;
  bool inflight_ = false;
  uint64_t inflight_seq_ = 0;
  json inflight_outer_{};
  int inflight_retries_ = 0;
};

class RendezvousClient : public std::enable_shared_from_this<RendezvousClient> {
public:
  struct Config {
    std::string server_host;
    uint16_t server_port = 0;
    std::string id;
    std::function<std::string(std::string_view)> sign_challenge;
    std::function<void(std::string)> log;
  };

  struct LookupResult {
    bool ok = false;
    std::string target_id;
    std::string ip;
    std::string udp_ip;
    uint16_t udp_port = 0;
  };

  using OnLookup = std::function<void(LookupResult)>;
  using OnFriendRequest = std::function<void(const std::string& from_id)>;
  using OnFriendAccept = std::function<void(const std::string& from_id)>;

  RendezvousClient(boost::asio::io_context& io, Config cfg)
      : io_(io),
        cfg_(std::move(cfg)),
        socket_(io),
        resolver_(io),
        heartbeat_timer_(io),
        poll_timer_(io),
        reconnect_timer_(io) {}

  void start(std::function<void()> on_registered, OnFriendRequest on_friend_request, OnFriendAccept on_friend_accept) {
    on_registered_ = std::move(on_registered);
    on_friend_request_ = std::move(on_friend_request);
    on_friend_accept_ = std::move(on_friend_accept);
    schedule_reconnect(/*immediate*/ true);
  }

  void stop() {
    stopped_ = true;
    boost::system::error_code ignored;
    heartbeat_timer_.cancel();
    poll_timer_.cancel();
    reconnect_timer_.cancel();
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
  }

  std::string_view id() const { return id_; }
  uint16_t udp_port() const { return udp_port_; }
  std::string_view observed_ip() const { return observed_ip_; }

  void enable_polling(bool enabled) {
    polling_enabled_ = enabled;
    if (!polling_enabled_) {
      poll_timer_.cancel();
      return;
    }
    if (can_send()) schedule_poll();
  }

  void send_lookup(std::string target_id, OnLookup cb) {
    pending_lookups_.push_back({std::move(target_id), std::move(cb)});
    const std::string tid = pending_lookups_.back().target_id;
    enqueue_or_send([this, tid] {
      json j;
      j["type"] = "lookup";
      j["from_id"] = id_;
      j["target_id"] = tid;
      writer_->send(std::move(j));
    });
  }

  void send_friend_request(const std::string& to_id) {
    enqueue_or_send([this, to_id] {
      json j;
      j["type"] = "friend_request";
      j["from_id"] = id_;
      j["to_id"] = to_id;
      writer_->send(std::move(j));
    });
  }

  void send_friend_accept(const std::string& requester_id) {
    enqueue_or_send([this, requester_id] {
      json j;
      j["type"] = "friend_accept";
      j["from_id"] = id_;
      j["to_id"] = requester_id;
      writer_->send(std::move(j));
    });
  }

private:
  bool can_send() const { return writer_ && socket_.is_open() && !id_.empty() && !stopped_; }

  void log(std::string msg) {
    if (cfg_.log) {
      cfg_.log(std::move(msg));
      return;
    }
    common::log(msg);
  }

  void enqueue_or_send(std::function<void()> fn) {
    if (can_send()) {
      fn();
      return;
    }
    pending_actions_.push_back(std::move(fn));
  }

  void flush_pending() {
    while (can_send() && !pending_actions_.empty()) {
      auto fn = std::move(pending_actions_.front());
      pending_actions_.pop_front();
      fn();
    }
  }

  struct PendingLookup {
    std::string target_id;
    OnLookup cb;
  };

  void schedule_reconnect(bool immediate) {
    if (stopped_) return;

    boost::system::error_code ignored;
    resolver_.cancel();
    heartbeat_timer_.cancel();
    poll_timer_.cancel();
    socket_.shutdown(tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    writer_.reset();

    id_.clear();
    observed_ip_.clear();
    udp_ip_.clear();
    udp_port_ = 0;

    const int delay = immediate ? 0 : reconnect_backoff_secs_;
    reconnect_backoff_secs_ = std::min(reconnect_backoff_secs_ * 2, 30);

    if (delay == 0) {
      log("rendezvous: connecting…");
    } else {
      log("rendezvous: reconnecting in " + std::to_string(delay) + "s…");
    }

    reconnect_timer_.expires_after(std::chrono::seconds(delay));
    auto self = shared_from_this();
    reconnect_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_) return;
      self->do_resolve();
    });
  }

  void do_resolve() {
    if (stopped_) return;
    auto self = shared_from_this();
    resolver_.async_resolve(cfg_.server_host, std::to_string(cfg_.server_port),
                            [self](const boost::system::error_code& ec, tcp::resolver::results_type results) {
                              if (ec || self->stopped_) return self->schedule_reconnect(false);
                              self->connect(results);
                            });
  }

  void connect(const tcp::resolver::results_type& results) {
    auto self = shared_from_this();
    auto timer = std::make_shared<boost::asio::steady_timer>(io_);
    timer->expires_after(kConnectTimeout);
    timer->async_wait([self](const boost::system::error_code& ec) {
      if (ec) return;
      self->schedule_reconnect(false);
    });

    boost::asio::async_connect(socket_, results,
                               [self, timer](const boost::system::error_code& ec, const tcp::endpoint&) {
                                 timer->cancel();
                                 if (ec) return self->schedule_reconnect(false);
                                 self->writer_ = std::make_shared<common::JsonWriteQueue<tcp::socket>>(self->socket_);
                                 self->reconnect_backoff_secs_ = 1;
                                 self->send_register_init();
                                 self->read_loop();
                               });
  }

  void send_register_init() {
    json j;
    j["type"] = "register_init";
    j["id"] = cfg_.id;
    writer_->send(std::move(j));
  }

  void schedule_heartbeat() {
    if (!can_send()) return;
    heartbeat_timer_.expires_after(kHeartbeatInterval);
    auto self = shared_from_this();
    heartbeat_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_) return;
      if (!self->can_send()) return;
      json hb;
      hb["type"] = "heartbeat";
      hb["id"] = self->id_;
      self->writer_->send(std::move(hb));
      self->schedule_heartbeat();
    });
  }

  void schedule_poll() {
    if (!polling_enabled_ || !can_send()) return;
    poll_timer_.expires_after(kPollInterval);
    auto self = shared_from_this();
    poll_timer_.async_wait([self](const boost::system::error_code& ec) {
      if (ec || self->stopped_ || !self->polling_enabled_) return;
      if (!self->can_send()) return;
      json p;
      p["type"] = "poll";
      p["id"] = self->id_;
      self->writer_->send(std::move(p));
      self->schedule_poll();
    });
  }

  void read_loop() {
    auto self = shared_from_this();
    common::async_read_json(socket_, common::kMaxFrameSize, [self](const boost::system::error_code& ec, json j) {
      if (ec) return self->schedule_reconnect(false);
      self->handle_message(j);
      self->read_loop();
    });
  }

  void handle_message(const json& j) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();

    if (type == "register_challenge") {
      if (!cfg_.sign_challenge) return stop();
      if (!j.contains("challenge") || !j["challenge"].is_string()) return stop();
      const std::string challenge = j["challenge"].get<std::string>();
      const std::string sig = cfg_.sign_challenge(challenge);
      if (sig.empty()) return stop();
      json fin;
      fin["type"] = "register_finish";
      fin["id"] = cfg_.id;
      fin["signature"] = sig;
      if (!writer_) return schedule_reconnect(false);
      writer_->send(std::move(fin));
      return;
    }

    if (type == "register_ok") {
      if (!j.contains("id") || !j["id"].is_string()) return;
      id_ = j["id"].get<std::string>();
      observed_ip_ = (j.contains("observed_ip") && j["observed_ip"].is_string()) ? j["observed_ip"].get<std::string>() : "";
      // udp_ip is the best contact address for UDP punching.
      if (j.contains("udp_ip") && j["udp_ip"].is_string()) udp_ip_ = j["udp_ip"].get<std::string>();
      udp_port_ = j.contains("udp_port") && j["udp_port"].is_number_integer()
                      ? static_cast<uint16_t>(j["udp_port"].get<int>())
                      : 0;
      if (!udp_ip_.empty() && common::is_private_ipv4(udp_ip_)) {
        log("warning: rendezvous sees your UDP address as private (" + udp_ip_ +
            "); hole punching will not work for internet peers unless rendezvous is on a public IP");
      } else if (!observed_ip_.empty() && common::is_private_ipv4(observed_ip_)) {
        log("warning: rendezvous sees your TCP address as private (" + observed_ip_ +
            "); run rendezvous on a public IP for internet discovery");
      }
      schedule_heartbeat();
      if (polling_enabled_) schedule_poll();
      flush_pending();
      if (on_registered_) on_registered_();
      return;
    }

    if (type == "lookup_result") {
      LookupResult r;
      r.ok = j.contains("ok") && j["ok"].is_boolean() ? j["ok"].get<bool>() : false;
      r.target_id = (j.contains("target_id") && j["target_id"].is_string()) ? j["target_id"].get<std::string>() : "";
      r.ip = (j.contains("ip") && j["ip"].is_string()) ? j["ip"].get<std::string>() : "";
      r.udp_ip = (j.contains("udp_ip") && j["udp_ip"].is_string()) ? j["udp_ip"].get<std::string>() : "";
      r.udp_port = j.contains("udp_port") && j["udp_port"].is_number_integer()
                       ? static_cast<uint16_t>(j["udp_port"].get<int>())
                       : 0;
      for (auto it = pending_lookups_.begin(); it != pending_lookups_.end(); ++it) {
        if (it->target_id == r.target_id) {
          auto cb = std::move(it->cb);
          pending_lookups_.erase(it);
          cb(std::move(r));
          return;
        }
      }
      return;
    }

    if (type == "poll_result") {
      if (j.contains("friend_requests") && j["friend_requests"].is_array()) {
        for (const auto& fr : j["friend_requests"]) {
          if (!fr.is_object()) continue;
          if (!fr.contains("from_id") || !fr["from_id"].is_string()) continue;
          if (on_friend_request_) on_friend_request_(fr["from_id"].get<std::string>());
        }
      }
      if (j.contains("friend_accepts") && j["friend_accepts"].is_array()) {
        for (const auto& fa : j["friend_accepts"]) {
          if (!fa.is_object()) continue;
          if (!fa.contains("from_id") || !fa["from_id"].is_string()) continue;
          if (on_friend_accept_) on_friend_accept_(fa["from_id"].get<std::string>());
        }
      }
      return;
    }
  }

  boost::asio::io_context& io_;
  Config cfg_;

  tcp::socket socket_;
  tcp::resolver resolver_;
  std::shared_ptr<common::JsonWriteQueue<tcp::socket>> writer_;

  boost::asio::steady_timer heartbeat_timer_;
  boost::asio::steady_timer poll_timer_;
  boost::asio::steady_timer reconnect_timer_;
  bool polling_enabled_ = false;
  bool stopped_ = false;

  std::string id_;
  std::string observed_ip_;
  std::string udp_ip_;
  uint16_t udp_port_ = 0;
  int reconnect_backoff_secs_ = 1;

  std::vector<PendingLookup> pending_lookups_;
  std::deque<std::function<void()>> pending_actions_;
  std::function<void()> on_registered_;
  OnFriendRequest on_friend_request_;
  OnFriendAccept on_friend_accept_;

};

} // namespace

struct ChatBackend::Impl {
  ChatBackend* q = nullptr;

  std::mutex m;
  std::unordered_set<std::string> accepted_friends;
  std::unordered_set<std::string> server_members;
  std::unordered_set<std::string> muted_voice_peers;
  std::unordered_map<std::string, std::deque<std::string>> queued_outgoing;
  std::unordered_map<std::string, std::deque<json>> queued_control;
  std::unordered_map<std::string, std::string> peer_names;
  std::atomic<bool> localVideoPreviewEnabled{true};
  std::string self_name;
  std::vector<uint8_t> self_avatar_png;
  common::AeadCipher stream_cipher_pref = kStreamCipher;

  // Call state (Qt thread only).
  QString callPeerId;
  QString callId;
  bool callOutgoing = false;
  bool callLocalAccepted = false;
  bool callRemoteAccepted = false;
  int callBitrate = 32000;
  int callFrameMs = 20;
  int callChannels = 1;
  QString callVideoCodec = "h264";
  QString callRemoteVideoCodec = "h264";
  bool callRemoteVideoEnabled = false;
  bool callRemoteWatchingVideo = true;
  ChatBackend::VoiceSettings callSettings;

#if defined(P2PCHAT_VOICE)
  struct VoiceRuntime {
    struct RxPeerState {
      OpusDecoder* dec = nullptr;
      QMap<quint64, QByteArray> jitter; // seq -> opus frame
      quint64 expectedSeq = 0;
      bool playoutStarted = false;
      uint64_t rxFrames = 0;
      uint64_t decFrames = 0;
    };

    QString peerId;
    QString callId;
    bool channelMode = false;
    int frameMs = 20;
    int bitrate = 32000;
    int sampleRate = 48000;
    int channels = 1;

    OpusEncoder* enc = nullptr;
    OpusDecoder* dec = nullptr;

    QPointer<QAudioSource> source;
    QPointer<QIODevice> sourceDev;
    QByteArray captureBuf;

    QPointer<QAudioSink> sink;
    QPointer<PcmRingBufferIODevice> sinkDev;

    QPointer<QTimer> playoutTimer;
    QSet<QString> txPeers;
    QHash<QString, RxPeerState> rxPeers;
    QMap<quint64, QByteArray> jitter; // seq -> opus frame
    quint64 expectedSeq = 0;
    bool playoutStarted = false;

    QElapsedTimer logTimer;
    uint64_t capBytes = 0;
    uint64_t encFrames = 0;
    uint64_t txFrames = 0;
    uint64_t rxFrames = 0;
    uint64_t decFrames = 0;
  };
  std::unique_ptr<VoiceRuntime> voice;
  bool voiceChannelActive = false;
  ChatBackend::VoiceSettings voiceChannelSettings;
  QSet<QString> voiceChannelPeers;
#endif

#if defined(P2PCHAT_VIDEO)
  struct VideoRuntime {
    bool channelMode = false;
    QString peerId;
    QString callId;
    video::Codec codec = video::Codec::H264;
    video::Codec rxCodec = video::Codec::H264;
    bool passthrough = false;
    uint32_t captureFourcc = 0;
    int width = 640;
    int height = 480;
    int fpsNum = 1;
    int fpsDen = 30;
    int bitrateKbps = 1500;
    QString provider = "auto";
    uint32_t streamId = 1;
    uint64_t txFrames = 0;
    uint64_t rxFrames = 0;
    uint64_t decodeFailures = 0;
    uint64_t captureFrames = 0;
    uint64_t convertFailures = 0;
    uint64_t encodeFailures = 0;
    uint64_t lastKeyframeReqMs = 0;
    bool sharing = false;
    bool screenShare = false;
    QString screenName;
    bool qtScreenBackend = false;
    QString screenBackendName = "legacy";
    int screenMinIntervalMs = 33;
    uint64_t lastScreenFrameMs = 0;
    std::atomic<bool> screenCaptureStop{false};
    std::atomic<bool> remoteWatching{true};
    std::thread screenCaptureThread;
    std::mutex screenWorkMu;
    std::condition_variable screenWorkCv;
    bool screenWorkStop = false;
    bool screenWorkHasFrame = false;
    QImage screenWorkFrame;
    std::thread screenWorkThread;
    QSet<QString> txPeers;
    std::unordered_map<std::string, std::unique_ptr<video::Decoder>> channelDecoders;
    std::unordered_map<std::string, video::Codec> channelDecoderCodecs;
    std::unordered_map<std::string, video::Codec> channelPeerCodecHints;
    std::unordered_map<std::string, uint64_t> channelDecodeFailures;
    std::unordered_map<std::string, uint64_t> channelLastKeyframeReqMs;

    std::unique_ptr<video::V4L2Capture> capture;
#if defined(P2PCHAT_X11_SHM)
    std::unique_ptr<video::X11ShmCapture> screenCaptureX11Shm;
#endif
    QPointer<QTimer> screenTimer;
#if defined(P2PCHAT_QT_SCREEN_CAPTURE)
    QPointer<QScreenCapture> screenCaptureQt;
    QPointer<QMediaCaptureSession> screenSessionQt;
    QPointer<QVideoSink> screenSinkQt;
    QPointer<QTimer> screenFallbackTimerQt;
#endif
    video::Encoder encoder;
    video::Decoder decoder;
  };
  std::unique_ptr<VideoRuntime> videoRt;
#endif

  boost::asio::io_context io;
  std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work;
  std::thread io_thread;

  std::shared_ptr<common::Identity> identity;
  uint16_t listen_port = 0;

  tcp::acceptor acceptor{io};
  udp::socket udp_socket{io};
  udp::resolver udp_resolver{io};
  udp::endpoint udp_server_ep;
  bool udp_server_ready = false;
  bool udp_resolving = false;
  bool udp_announce_confirmed = false;
  boost::asio::steady_timer udp_announce_timer{io};
  std::string server_host;
  uint16_t server_port = 0;
#if defined(P2PCHAT_VOICE)
  uint64_t udp_voice_routed = 0;
  uint64_t udp_voice_drop_no_map = 0;
  uint64_t udp_voice_drop_no_session = 0;
  uint64_t udp_voice_drop_bad_frame = 0;
#endif

  std::shared_ptr<RendezvousClient> rendezvous;
  std::unordered_map<std::string, std::shared_ptr<PeerSession>> tcp_sessions;
  std::unordered_map<std::string, std::shared_ptr<UdpPeerSession>> udp_sessions;
  std::unordered_map<std::string, std::string> udp_ep_to_peer;
  std::unordered_map<std::string, RendezvousClient::LookupResult> last_lookup;
  std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_connect_attempt;
  boost::asio::steady_timer friend_connect_timer{io};
  bool friend_connect_running = false;

  void postToQt(std::function<void()> fn) {
    // All UI objects (including `ChatBackend`) have GUI-thread affinity.
    // Networking runs on a background thread; never touch Qt/GUI state directly from it.
    //
    // Use a QPointer guard so we don't dispatch into a deleted QObject.
    QPointer<ChatBackend> weak(q);
    auto* app = QCoreApplication::instance();
    if (!app) return;
    QMetaObject::invokeMethod(app,
                              [weak, fn = std::move(fn)] {
                                if (!weak) return;
                                fn();
                              },
                              Qt::QueuedConnection);
  }

  void resetCallStateQt() {
    callPeerId.clear();
    callId.clear();
    callOutgoing = false;
    callLocalAccepted = false;
    callRemoteAccepted = false;
    callBitrate = 32000;
    callFrameMs = 20;
    callChannels = 1;
    callVideoCodec = "h264";
    callRemoteVideoCodec = "h264";
    callRemoteVideoEnabled = false;
    callRemoteWatchingVideo = true;
    callSettings = {};
  }

#if defined(P2PCHAT_VOICE)
  void stopVoiceQt() {
    stopVideoQt();
    if (!voice) return;
    if (debug_logs_enabled()) {
      const QString mode = voice->channelMode ? "channel" : "direct";
      emit q->logLine("[dbg] voice stop mode=" + mode + " peer=" + voice->peerId + " capBytes=" + QString::number(voice->capBytes) +
                      " encFrames=" + QString::number(voice->encFrames) + " rxFrames=" + QString::number(voice->rxFrames) +
                      " decFrames=" + QString::number(voice->decFrames));
    }

    if (voice->playoutTimer) {
      voice->playoutTimer->stop();
      voice->playoutTimer->deleteLater();
      voice->playoutTimer = nullptr;
    }
    if (voice->source) {
      voice->source->stop();
      voice->source->deleteLater();
      voice->source = nullptr;
    }
    voice->sourceDev = nullptr;
    voice->captureBuf.clear();

    if (voice->sink) {
      voice->sink->stop();
      voice->sink->deleteLater();
      voice->sink = nullptr;
    }
    if (voice->sinkDev) {
      voice->sinkDev->stop();
      voice->sinkDev->deleteLater();
      voice->sinkDev = nullptr;
    }

    if (voice->enc) {
      opus_encoder_destroy(voice->enc);
      voice->enc = nullptr;
    }
    if (voice->dec) {
      opus_decoder_destroy(voice->dec);
      voice->dec = nullptr;
    }
    for (auto it = voice->rxPeers.begin(); it != voice->rxPeers.end(); ++it) {
      if (it->dec) {
        opus_decoder_destroy(it->dec);
        it->dec = nullptr;
      }
    }
    voice->rxPeers.clear();
    voice->txPeers.clear();
    voice.reset();
  }

  static QAudioDevice findAudioDeviceByHexId(const QList<QAudioDevice>& devices, const QString& hexId) {
    if (is_none_audio_device(hexId)) return QAudioDevice();
    if (hexId.isEmpty()) return QAudioDevice();
    for (const auto& d : devices) {
      if (QString::fromLatin1(d.id().toHex()) == hexId) return d;
    }
    return QAudioDevice();
  }

  void syncVoiceChannelPeersQt() {
    if (!voice || !voice->channelMode) return;

    // Keep TX peers in sync.
    voice->txPeers = voiceChannelPeers;

    // Drop decoder/jitter state for peers no longer in channel.
    for (auto it = voice->rxPeers.begin(); it != voice->rxPeers.end();) {
      if (!voice->txPeers.contains(it.key())) {
        if (it->dec) opus_decoder_destroy(it->dec);
        it = voice->rxPeers.erase(it);
      } else {
        ++it;
      }
    }

    const int frameMs = voice->frameMs;
    const QStringList peers = voice->txPeers.values();
    boost::asio::post(io, [this, peers, frameMs] {
      for (const auto& peerId : peers) {
        auto it = udp_sessions.find(peerId.toStdString());
        if (it != udp_sessions.end() && it->second) it->second->set_voice_frame_ms(frameMs);
      }
    });
  }

  void startVoiceChannelQt() {
    if (!voiceChannelActive || voiceChannelPeers.isEmpty()) {
      if (voice && voice->channelMode) stopVoiceQt();
      return;
    }
    if (voice) {
      if (voice->channelMode) {
        syncVoiceChannelPeersQt();
        maybeStartVideoQt();
      }
      return;
    }

    const int frameMs = (voiceChannelSettings.frameMs == 10) ? 10 : 20;
    const int sampleRate = 48000;
    const int channels = (voiceChannelSettings.channels == 2) ? 2 : 1;
    const int frameSamples = sampleRate * frameMs / 1000;
    const int bitrate = std::clamp(voiceChannelSettings.bitrate, 8000, 128000);

    int err = 0;
    OpusEncoder* enc = opus_encoder_create(sampleRate, channels, OPUS_APPLICATION_VOIP, &err);
    if (!enc || err != OPUS_OK) {
      if (enc) opus_encoder_destroy(enc);
      emit q->logLine("voice: failed to create Opus encoder for voice channel");
      return;
    }
    configure_opus_encoder(enc, bitrate);

    QAudioFormat fmt;
    fmt.setSampleRate(sampleRate);
    fmt.setChannelCount(channels);
    fmt.setSampleFormat(QAudioFormat::Int16);

    const bool disableInput = is_none_audio_device(voiceChannelSettings.inputDeviceIdHex);
    const bool disableOutput = is_none_audio_device(voiceChannelSettings.outputDeviceIdHex);
    auto inDev = findAudioDeviceByHexId(QMediaDevices::audioInputs(), voiceChannelSettings.inputDeviceIdHex);
    if (!disableInput && inDev.isNull()) inDev = QMediaDevices::defaultAudioInput();
    auto outDev = findAudioDeviceByHexId(QMediaDevices::audioOutputs(), voiceChannelSettings.outputDeviceIdHex);
    if (!disableOutput && outDev.isNull()) outDev = QMediaDevices::defaultAudioOutput();

    auto vr = std::make_unique<VoiceRuntime>();
    vr->channelMode = true;
    vr->peerId = "__voice_channel__";
    vr->frameMs = frameMs;
    vr->bitrate = bitrate;
    vr->sampleRate = sampleRate;
    vr->channels = channels;
    vr->enc = enc;
    vr->txPeers = voiceChannelPeers;
    vr->logTimer.start();

    if (!disableOutput && !outDev.isNull()) {
      vr->sinkDev = new PcmRingBufferIODevice(q);
      vr->sinkDev->start();
      vr->sink = new QAudioSink(outDev, fmt, q);
      vr->sink->setBufferSize(frameSamples * channels * static_cast<int>(sizeof(opus_int16)) * 6);
      vr->sink->setVolume(std::clamp(voiceChannelSettings.speakerVolume, 0, 100) / 100.0);
      vr->sink->start(vr->sinkDev.data());
    }

    if (!disableInput && !inDev.isNull()) {
      vr->source = new QAudioSource(inDev, fmt, q);
      vr->source->setBufferSize(frameSamples * channels * static_cast<int>(sizeof(opus_int16)) * 6);
      vr->source->setVolume(std::clamp(voiceChannelSettings.micVolume, 0, 100) / 100.0);
      vr->sourceDev = vr->source->start();
    }

    vr->playoutTimer = new QTimer(q);
    vr->playoutTimer->setInterval(frameMs);
    QObject::connect(vr->playoutTimer, &QTimer::timeout, q, [this, frameSamples] {
      if (!voice || !voice->channelMode) return;
      if (!voice->sinkDev) return;

      std::vector<int32_t> mixed(static_cast<std::size_t>(frameSamples * voice->channels), 0);
      int activeStreams = 0;

      for (auto it = voice->rxPeers.begin(); it != voice->rxPeers.end(); ++it) {
        const auto peerId = it.key();
        auto& st = it.value();
        if (!st.dec) continue;

        {
          std::lock_guard lk(m);
          if (muted_voice_peers.find(peerId.toStdString()) != muted_voice_peers.end()) continue;
        }

        if (!st.playoutStarted && st.jitter.size() >= kVoiceJitterStartFrames) {
          const quint64 newest = st.jitter.lastKey();
          const quint64 startAt = (newest >= static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                      ? (newest - static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                      : newest;
          st.expectedSeq = startAt;
          while (!st.jitter.isEmpty() && st.jitter.firstKey() < st.expectedSeq) {
            st.jitter.erase(st.jitter.begin());
          }
          st.playoutStarted = true;
        }
        if (!st.playoutStarted) continue;

        if (st.jitter.size() > kVoiceJitterMaxFrames) {
          const quint64 newest = st.jitter.lastKey();
          const quint64 want = (newest >= static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                   ? (newest - static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                   : newest;
          if (want > st.expectedSeq) st.expectedSeq = want;
        }
        while (!st.jitter.isEmpty() && st.jitter.firstKey() < st.expectedSeq) {
          st.jitter.erase(st.jitter.begin());
        }

        const quint64 playSeq = st.expectedSeq;
        QByteArray frame;
        if (st.jitter.contains(playSeq)) {
          frame = st.jitter.take(playSeq);
        }
        st.expectedSeq++;

        QByteArray fecFrame;
        bool useFec = false;
        if (frame.isEmpty()) {
          auto next = st.jitter.find(playSeq + 1);
          if (next != st.jitter.end()) {
            fecFrame = next.value();
            useFec = true;
          }
        }

        std::vector<opus_int16> pcm(static_cast<std::size_t>(kVoiceMaxDecodeSamplesPerChannel * voice->channels));
        int outSamples = 0;
        if (!frame.isEmpty()) {
          outSamples = opus_decode(st.dec,
                                   reinterpret_cast<const unsigned char*>(frame.constData()),
                                   frame.size(),
                                   pcm.data(),
                                   kVoiceMaxDecodeSamplesPerChannel,
                                   0);
        } else if (useFec) {
          outSamples = opus_decode(st.dec,
                                   reinterpret_cast<const unsigned char*>(fecFrame.constData()),
                                   fecFrame.size(),
                                   pcm.data(),
                                   kVoiceMaxDecodeSamplesPerChannel,
                                   1);
        } else {
          outSamples = opus_decode(st.dec, nullptr, 0, pcm.data(), kVoiceMaxDecodeSamplesPerChannel, 0);
        }
        if (outSamples <= 0) continue;

        const int sampleCount = std::min(outSamples, frameSamples) * voice->channels;
        for (int i = 0; i < sampleCount; ++i) {
          mixed[static_cast<std::size_t>(i)] += static_cast<int32_t>(pcm[static_cast<std::size_t>(i)]);
        }
        ++activeStreams;
      }

      if (activeStreams <= 0) return;

      std::vector<opus_int16> out(static_cast<std::size_t>(frameSamples * voice->channels));
      for (std::size_t i = 0; i < out.size(); ++i) {
        int32_t v = mixed[i] / activeStreams;
        if (v > 32767) v = 32767;
        if (v < -32768) v = -32768;
        out[i] = static_cast<opus_int16>(v);
      }
      voice->sinkDev->push(QByteArray(reinterpret_cast<const char*>(out.data()),
                                      static_cast<int>(out.size() * sizeof(opus_int16))));
    });
    vr->playoutTimer->start();

    if (vr->sourceDev) {
      QObject::connect(vr->sourceDev.data(), &QIODevice::readyRead, q, [this, frameSamples, channels] {
        if (!voice || !voice->channelMode) return;
        if (!voice->sourceDev) return;
        const QByteArray got = voice->sourceDev->readAll();
        voice->capBytes += static_cast<uint64_t>(got.size());
        voice->captureBuf.append(got);
        const int frameBytes = frameSamples * channels * static_cast<int>(sizeof(opus_int16));
        while (voice && voice->captureBuf.size() >= frameBytes) {
          const QByteArray pcm = voice->captureBuf.left(frameBytes);
          voice->captureBuf.remove(0, frameBytes);

          std::array<unsigned char, 1500> out{};
          const int n = opus_encode(voice->enc,
                                    reinterpret_cast<const opus_int16*>(pcm.constData()),
                                    frameSamples,
                                    out.data(),
                                    static_cast<opus_int32>(out.size()));
          if (n <= 0) continue;
          std::vector<uint8_t> pkt(out.data(), out.data() + n);
          const QStringList peers = voice->txPeers.values();
          boost::asio::post(io, [this, peers, pkt = std::move(pkt)]() mutable {
            for (const auto& peerId : peers) {
              auto it = udp_sessions.find(peerId.toStdString());
              if (it == udp_sessions.end() || !it->second) continue;
              it->second->send_voice_frame(std::vector<uint8_t>(pkt.begin(), pkt.end()));
            }
          });
        }
      });
    }

    voice = std::move(vr);
    syncVoiceChannelPeersQt();
    emit q->logLine("voice channel: active (" + QString::number(voice->txPeers.size()) + " peers)");
    maybeStartVideoQt();
  }

  void maybeStartVoiceQt() {
    if (voiceChannelActive) {
      startVoiceChannelQt();
      return;
    }
    if (callPeerId.isEmpty() || callId.isEmpty()) return;
    if (!(callLocalAccepted && callRemoteAccepted)) return;
    if (voice && voice->channelMode) return;
    if (voice) {
      maybeStartVideoQt();
      return;
    }

    const int frameMs = (callFrameMs == 10) ? 10 : 20;
    const int sampleRate = 48000;
    const int channels = (callChannels == 2) ? 2 : 1;
    const int frameSamples = sampleRate * frameMs / 1000;

    int err = 0;
    OpusEncoder* enc = opus_encoder_create(sampleRate, channels, OPUS_APPLICATION_VOIP, &err);
    if (!enc || err != OPUS_OK) {
      if (enc) opus_encoder_destroy(enc);
      emit q->callEnded(callPeerId, "failed to create Opus encoder");
      resetCallStateQt();
      return;
    }
    OpusDecoder* dec = opus_decoder_create(sampleRate, channels, &err);
    if (!dec || err != OPUS_OK) {
      opus_encoder_destroy(enc);
      if (dec) opus_decoder_destroy(dec);
      emit q->callEnded(callPeerId, "failed to create Opus decoder");
      resetCallStateQt();
      return;
    }

    configure_opus_encoder(enc, callBitrate);

    QAudioFormat fmt;
    fmt.setSampleRate(sampleRate);
    fmt.setChannelCount(channels);
    fmt.setSampleFormat(QAudioFormat::Int16);

    const bool disableInput = is_none_audio_device(callSettings.inputDeviceIdHex);
    const bool disableOutput = is_none_audio_device(callSettings.outputDeviceIdHex);
    auto inDev = findAudioDeviceByHexId(QMediaDevices::audioInputs(), callSettings.inputDeviceIdHex);
    if (!disableInput && inDev.isNull()) inDev = QMediaDevices::defaultAudioInput();
    auto outDev = findAudioDeviceByHexId(QMediaDevices::audioOutputs(), callSettings.outputDeviceIdHex);
    if (!disableOutput && outDev.isNull()) outDev = QMediaDevices::defaultAudioOutput();

    auto vr = std::make_unique<VoiceRuntime>();
    vr->peerId = callPeerId;
    vr->callId = callId;
    vr->frameMs = frameMs;
    vr->bitrate = callBitrate;
    vr->sampleRate = sampleRate;
    vr->channels = channels;
    vr->enc = enc;
    vr->dec = dec;
    vr->logTimer.start();

    if (debug_logs_enabled()) {
      const bool inOk = disableInput ? true : (!inDev.isNull() && inDev.isFormatSupported(fmt));
      const bool outOk = disableOutput ? true : (!outDev.isNull() && outDev.isFormatSupported(fmt));
      emit q->logLine("[dbg] voice init peer=" + vr->peerId + " frameMs=" + QString::number(frameMs) +
                      " channels=" + QString::number(channels) +
                      " bitrate=" + QString::number(callBitrate) + " inDev=" + inDev.description() +
                      " outDev=" + outDev.description() + " fmtSupported(in/out)=" + (inOk ? "Y" : "N") + "/" +
                      (outOk ? "Y" : "N"));
    }

    auto stateName = [](QAudio::State s) -> const char* {
      switch (s) {
        case QAudio::ActiveState:
          return "active";
        case QAudio::SuspendedState:
          return "suspended";
        case QAudio::StoppedState:
          return "stopped";
        case QAudio::IdleState:
          return "idle";
      }
      return "unknown";
    };

    if (!disableOutput && !outDev.isNull()) {
      vr->sinkDev = new PcmRingBufferIODevice(q);
      vr->sinkDev->start();
      vr->sink = new QAudioSink(outDev, fmt, q);
      vr->sink->setBufferSize(frameSamples * channels * static_cast<int>(sizeof(opus_int16)) * 4);
      vr->sink->setVolume(std::clamp(callSettings.speakerVolume, 0, 100) / 100.0);
      vr->sink->start(vr->sinkDev.data());
      if (debug_logs_enabled()) {
        QObject::connect(vr->sink.data(), &QAudioSink::stateChanged, q, [this, stateName](QAudio::State st) {
          emit q->logLine("[dbg] voice sink state=" + QString::fromLatin1(stateName(st)) +
                          " err=" + QString::number(static_cast<int>(voice && voice->sink ? voice->sink->error() : 0)));
        });
        emit q->logLine("[dbg] voice sink started state=" + QString::fromLatin1(stateName(vr->sink->state())) +
                        " err=" + QString::number(static_cast<int>(vr->sink->error())));
      }
    } else if (debug_logs_enabled()) {
      emit q->logLine("[dbg] voice sink disabled");
    }

    if (!disableInput && !inDev.isNull()) {
      vr->source = new QAudioSource(inDev, fmt, q);
      vr->source->setBufferSize(frameSamples * channels * static_cast<int>(sizeof(opus_int16)) * 4);
      vr->source->setVolume(std::clamp(callSettings.micVolume, 0, 100) / 100.0);
      vr->sourceDev = vr->source->start();
      if (debug_logs_enabled()) {
        QObject::connect(vr->source.data(), &QAudioSource::stateChanged, q, [this, stateName](QAudio::State st) {
          emit q->logLine("[dbg] voice source state=" + QString::fromLatin1(stateName(st)) +
                          " err=" + QString::number(static_cast<int>(voice && voice->source ? voice->source->error() : 0)));
        });
        emit q->logLine("[dbg] voice source started state=" + QString::fromLatin1(stateName(vr->source->state())) +
                        " err=" + QString::number(static_cast<int>(vr->source->error())) +
                        " dev=" + (vr->sourceDev ? "ok" : "null"));
      }
    } else if (debug_logs_enabled()) {
      emit q->logLine("[dbg] voice source disabled");
    }

    vr->playoutTimer = new QTimer(q);
    vr->playoutTimer->setInterval(frameMs);
    QObject::connect(vr->playoutTimer, &QTimer::timeout, q, [this] {
      if (!voice) return;
      if (!voice->sinkDev) return;
      if (!voice->playoutStarted) return;

      if (voice->jitter.size() > kVoiceJitterMaxFrames) {
        const quint64 newest = voice->jitter.lastKey();
        const quint64 want = (newest >= static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                 ? (newest - static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                 : newest;
        if (want > voice->expectedSeq) {
          if (debug_logs_enabled()) {
            emit q->logLine("[dbg] voice catch-up expected=" + QString::number(voice->expectedSeq) +
                            " -> " + QString::number(want) +
                            " jitter=" + QString::number(voice->jitter.size()));
          }
          voice->expectedSeq = want;
        }
      }

      // Drop overly old packets.
      while (!voice->jitter.isEmpty() && voice->jitter.firstKey() < voice->expectedSeq) {
        voice->jitter.erase(voice->jitter.begin());
      }

      const quint64 playSeq = voice->expectedSeq;
      QByteArray frame;
      if (voice->jitter.contains(playSeq)) {
        frame = voice->jitter.take(playSeq);
      }
      voice->expectedSeq++;

      QByteArray fecFrame;
      bool useFec = false;
      if (frame.isEmpty()) {
        auto next = voice->jitter.find(playSeq + 1);
        if (next != voice->jitter.end()) {
          fecFrame = next.value();
          useFec = true;
        }
      }

      std::vector<opus_int16> pcm;
      pcm.resize(kVoiceMaxDecodeSamplesPerChannel * voice->channels);
      int outSamples = 0;
      if (!frame.isEmpty()) {
        if (debug_logs_enabled()) voice->rxFrames++;
        outSamples = opus_decode(voice->dec,
                                 reinterpret_cast<const unsigned char*>(frame.constData()),
                                 frame.size(),
                                 pcm.data(),
                                 kVoiceMaxDecodeSamplesPerChannel,
                                 0);
      } else if (useFec) {
        outSamples = opus_decode(voice->dec,
                                 reinterpret_cast<const unsigned char*>(fecFrame.constData()),
                                 fecFrame.size(),
                                 pcm.data(),
                                 kVoiceMaxDecodeSamplesPerChannel,
                                 1);
      } else {
        // PLC.
        outSamples = opus_decode(voice->dec, nullptr, 0, pcm.data(), kVoiceMaxDecodeSamplesPerChannel, 0);
      }
      if (outSamples <= 0) return;
      if (debug_logs_enabled()) {
        voice->decFrames++;
        if (voice->logTimer.elapsed() > 1000 && (voice->decFrames % 50) == 1) {
          emit q->logLine("[dbg] voice playout decFrames=" + QString::number(voice->decFrames) +
                          " jitter=" + QString::number(voice->jitter.size()));
        }
      }
      const int outBytes = outSamples * voice->channels * static_cast<int>(sizeof(opus_int16));
      voice->sinkDev->push(QByteArray(reinterpret_cast<const char*>(pcm.data()), outBytes));
    });

    QObject::connect(vr->sourceDev.data(), &QIODevice::readyRead, q, [this, frameSamples, channels] {
      if (!voice) return;
      if (!voice->sourceDev) return;
      const QByteArray got = voice->sourceDev->readAll();
      voice->capBytes += static_cast<uint64_t>(got.size());
      voice->captureBuf.append(got);
      const int frameBytes = frameSamples * channels * static_cast<int>(sizeof(opus_int16));
      while (voice && voice->captureBuf.size() >= frameBytes) {
        const QByteArray pcm = voice->captureBuf.left(frameBytes);
        voice->captureBuf.remove(0, frameBytes);

        std::array<unsigned char, 1500> out{};
        const int n = opus_encode(voice->enc,
                                  reinterpret_cast<const opus_int16*>(pcm.constData()),
                                  frameSamples,
                                  out.data(),
                                  static_cast<opus_int32>(out.size()));
        if (n <= 0) continue;
        if (debug_logs_enabled()) voice->encFrames++;
        std::vector<uint8_t> pkt(out.data(), out.data() + n);
        const auto peer = voice->peerId.toStdString();
        boost::asio::post(io, [this, peer, pkt = std::move(pkt)]() mutable {
          auto it = udp_sessions.find(peer);
          if (it == udp_sessions.end() || !it->second) return;
          if (debug_logs_enabled()) {
            postToQt([this, peer] {
              static uint64_t once = 0;
              if ((++once % 200) == 1) emit q->logLine("[dbg] voice tx path using udp session peer=" + QString::fromStdString(peer));
            });
          }
          it->second->send_voice_frame(std::move(pkt));
        });
        if (debug_logs_enabled() && voice->logTimer.elapsed() > 1000 && (voice->encFrames % 50) == 1) {
          emit q->logLine("[dbg] voice capture capBytes=" + QString::number(voice->capBytes) +
                          " encFrames=" + QString::number(voice->encFrames) +
                          " buf=" + QString::number(voice->captureBuf.size()));
        }
      }
    });

    voice = std::move(vr);

    // Tell the UDP session what our frame size is (affects timestamps).
    const auto peer = callPeerId.toStdString();
    boost::asio::post(io, [this, peer, frameMs] {
      auto it = udp_sessions.find(peer);
      if (it != udp_sessions.end() && it->second) it->second->set_voice_frame_ms(frameMs);
    });

    emit q->callStateChanged(callPeerId, "in_call");
    maybeStartVideoQt();
  }

  void handleVoiceFrameQt(const QString& peerId, quint64 seq, const QByteArray& opusFrame) {
    if (!voice) return;
    if (voice->channelMode) {
      if (!voice->txPeers.contains(peerId)) return;
      if (opusFrame.isEmpty()) return;
      {
        std::lock_guard lk(m);
        if (muted_voice_peers.find(peerId.toStdString()) != muted_voice_peers.end()) return;
      }

      auto it = voice->rxPeers.find(peerId);
      if (it == voice->rxPeers.end()) {
        int err = 0;
        OpusDecoder* dec = opus_decoder_create(voice->sampleRate, voice->channels, &err);
        if (!dec || err != OPUS_OK) {
          if (dec) opus_decoder_destroy(dec);
          return;
        }
        VoiceRuntime::RxPeerState st;
        st.dec = dec;
        it = voice->rxPeers.insert(peerId, std::move(st));
      }

      if (it->playoutStarted && it->expectedSeq > seq &&
          (it->expectedSeq - seq) > kVoiceSeqResetGap) {
        const quint64 oldExpected = it->expectedSeq;
        if (it->dec) opus_decoder_ctl(it->dec, OPUS_RESET_STATE);
        it->jitter.clear();
        it->expectedSeq = 0;
        it->playoutStarted = false;
        if (debug_logs_enabled()) {
          emit q->logLine("[dbg] voice rx reset(channel) peer=" + peerId + " old_expected=" +
                          QString::number(oldExpected) + " new_seq=" + QString::number(seq));
        }
      }

      if (!it->jitter.contains(seq)) it->jitter.insert(seq, opusFrame);
      if (!it->playoutStarted && it->jitter.size() >= kVoiceJitterStartFrames) {
        const quint64 newest = it->jitter.lastKey();
        const quint64 startAt = (newest >= static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                    ? (newest - static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                    : newest;
        it->expectedSeq = startAt;
        while (!it->jitter.isEmpty() && it->jitter.firstKey() < it->expectedSeq) {
          it->jitter.erase(it->jitter.begin());
        }
        it->playoutStarted = true;
      }
      return;
    }
    if (voice->peerId != peerId) return;
    if (opusFrame.isEmpty()) return;
    {
      std::lock_guard lk(m);
      if (muted_voice_peers.find(peerId.toStdString()) != muted_voice_peers.end()) return;
    }

    if (debug_logs_enabled()) {
      voice->rxFrames++;
      if (voice->logTimer.elapsed() > 1000 && (voice->rxFrames % 50) == 1) {
        emit q->logLine("[dbg] voice rx frame seq=" + QString::number(seq) + " len=" + QString::number(opusFrame.size()) +
                        " jitter=" + QString::number(voice->jitter.size()) + " expected=" +
                        QString::number(voice->expectedSeq));
      }
    }

    if (voice->playoutStarted && voice->expectedSeq > seq &&
        (voice->expectedSeq - seq) > kVoiceSeqResetGap) {
      const quint64 oldExpected = voice->expectedSeq;
      if (voice->dec) opus_decoder_ctl(voice->dec, OPUS_RESET_STATE);
      voice->jitter.clear();
      voice->expectedSeq = 0;
      voice->playoutStarted = false;
      if (voice->playoutTimer) voice->playoutTimer->stop();
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] voice rx reset(dm) peer=" + peerId + " old_expected=" +
                        QString::number(oldExpected) + " new_seq=" + QString::number(seq));
      }
    }
    if (!voice->jitter.contains(seq)) voice->jitter.insert(seq, opusFrame);

    if (!voice->playoutStarted && voice->jitter.size() >= kVoiceJitterStartFrames) {
      const quint64 newest = voice->jitter.lastKey();
      const quint64 startAt = (newest >= static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                  ? (newest - static_cast<quint64>(kVoiceJitterTargetFrames - 1))
                                  : newest;
      voice->expectedSeq = startAt;
      while (!voice->jitter.isEmpty() && voice->jitter.firstKey() < voice->expectedSeq) {
        voice->jitter.erase(voice->jitter.begin());
      }
      voice->playoutStarted = true;
      voice->playoutTimer->start();
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] voice playout started expectedSeq=" + QString::number(voice->expectedSeq) +
                        " jitter=" + QString::number(voice->jitter.size()));
      }
    }
  }

#if defined(P2PCHAT_VIDEO)
  void stopVideoQt() {
    if (!videoRt) return;
    QStringList clearPeers;
    if (videoRt->channelMode) {
      for (const auto& id : videoRt->txPeers) clearPeers.push_back(id);
      for (const auto& it : videoRt->channelDecoders) {
        clearPeers.push_back(QString::fromStdString(it.first));
      }
      clearPeers.removeDuplicates();
    }
    if (videoRt->screenTimer) {
      videoRt->screenTimer->stop();
      videoRt->screenTimer->deleteLater();
      videoRt->screenTimer = nullptr;
    }
    videoRt->screenCaptureStop.store(true, std::memory_order_relaxed);
    if (videoRt->screenCaptureThread.joinable()) videoRt->screenCaptureThread.join();
    {
      std::lock_guard lk(videoRt->screenWorkMu);
      videoRt->screenWorkStop = true;
      videoRt->screenWorkHasFrame = false;
      videoRt->screenWorkFrame = QImage();
    }
    videoRt->screenWorkCv.notify_all();
    if (videoRt->screenWorkThread.joinable()) videoRt->screenWorkThread.join();
#if defined(P2PCHAT_QT_SCREEN_CAPTURE)
    if (videoRt->screenFallbackTimerQt) {
      videoRt->screenFallbackTimerQt->stop();
      videoRt->screenFallbackTimerQt->deleteLater();
      videoRt->screenFallbackTimerQt = nullptr;
    }
    if (videoRt->screenCaptureQt) {
      videoRt->screenCaptureQt->stop();
      videoRt->screenCaptureQt->deleteLater();
      videoRt->screenCaptureQt = nullptr;
    }
    if (videoRt->screenSinkQt) {
      videoRt->screenSinkQt->deleteLater();
      videoRt->screenSinkQt = nullptr;
    }
    if (videoRt->screenSessionQt) {
      videoRt->screenSessionQt->deleteLater();
      videoRt->screenSessionQt = nullptr;
    }
#endif
#if defined(P2PCHAT_X11_SHM)
    videoRt->screenCaptureX11Shm.reset();
#endif
    if (videoRt->capture) videoRt->capture->stop();
    videoRt->encoder.close();
    videoRt->decoder.close();
    videoRt.reset();
    emit q->localVideoFrame(QImage());
    if (!clearPeers.isEmpty()) {
      for (const auto& peerId : clearPeers) {
        if (peerId.isEmpty()) continue;
        emit q->remoteVideoFrame(peerId, QImage());
        emit q->remoteVideoAvailabilityChanged(peerId, false);
      }
    } else if (!callPeerId.isEmpty()) {
      emit q->remoteVideoFrame(callPeerId, QImage());
      emit q->remoteVideoAvailabilityChanged(callPeerId, false);
    }
  }

  void maybeStartVideoQt() {
    if (!voice) return;
    const bool channelMode = voice->channelMode;
    if (!channelMode) {
      if (callPeerId.isEmpty() || callId.isEmpty()) return;
      if (!(callLocalAccepted && callRemoteAccepted)) return;
    } else {
      if (!voiceChannelActive || voiceChannelPeers.isEmpty()) {
        stopVideoQt();
        return;
      }
    }

    const auto& settings = channelMode ? voiceChannelSettings : callSettings;
    const QString runtimePeerId = channelMode ? QString() : callPeerId;
    const QString runtimeCallId = channelMode ? QString("__voice_channel__") : callId;
    const bool wantCapture = settings.videoEnabled && !settings.videoDevicePath.trimmed().isEmpty();
    const auto selectedTxCodec = channelMode
                                     ? resolve_network_video_codec(settings)
                                     : (callVideoCodec.trimmed().isEmpty() ? QString("h264")
                                                                           : callVideoCodec.trimmed().toLower());
    const auto selectedRxCodec = channelMode
                                     ? selectedTxCodec
                                     : (callRemoteVideoCodec.trimmed().isEmpty() ? QString("h264")
                                                                                 : callRemoteVideoCodec.trimmed().toLower());
    const bool useScreenCapture = settings.videoDevicePath.startsWith("screen://");
    const QString selectedScreenName =
        useScreenCapture ? settings.videoDevicePath.mid(static_cast<int>(std::strlen("screen://"))).trimmed() : QString();
    const uint32_t selectedFourcc = useScreenCapture ? 0u : parse_fourcc_text(settings.videoFourcc);
    const auto selectedNetworkCodec = video::codecFromString(selectedTxCodec);
    const auto selectedRxCodecEnum = video::codecFromString(selectedRxCodec);
    const auto selectedProvider = normalize_video_provider(settings.videoProvider);
    const bool canPassthrough = !useScreenCapture && video::isPassthroughCompatible(selectedFourcc, selectedNetworkCodec);
    int selectedWidth = settings.videoWidth;
    int selectedHeight = settings.videoHeight;
    if (useScreenCapture) {
      auto* screen = find_screen_by_name(selectedScreenName);
      if (!screen) {
        emit q->logLine("video: no display available for screen share");
        return;
      }
      if (selectedWidth <= 0 || selectedHeight <= 0) {
        const QRect g = screen->geometry();
        selectedWidth = g.width();
        selectedHeight = g.height();
      }
    }
    selectedWidth = std::max(16, selectedWidth);
    selectedHeight = std::max(16, selectedHeight);
    const int selectedFpsNum = std::max(1, settings.videoFpsNum);
    const int selectedFpsDen = std::max(1, settings.videoFpsDen);
    const int selectedBitrate = std::clamp(settings.videoBitrateKbps, 100, 20000);

    const bool same =
        videoRt &&
        videoRt->channelMode == channelMode &&
        videoRt->peerId == runtimePeerId &&
        videoRt->callId == runtimeCallId &&
        videoRt->width == selectedWidth &&
        videoRt->height == selectedHeight &&
        videoRt->fpsNum == selectedFpsNum &&
        videoRt->fpsDen == selectedFpsDen &&
        videoRt->bitrateKbps == selectedBitrate &&
        videoRt->provider == selectedProvider &&
        videoRt->passthrough == canPassthrough &&
        videoRt->screenShare == useScreenCapture &&
        videoRt->screenName == selectedScreenName &&
        videoRt->captureFourcc == selectedFourcc &&
        video::codecToString(videoRt->codec) == video::codecToString(video::codecFromString(selectedTxCodec)) &&
        (channelMode || videoRt->rxCodec == selectedRxCodecEnum) &&
        videoRt->sharing == wantCapture;
    const bool samePeers = !videoRt || !channelMode ? true : (videoRt->txPeers == voiceChannelPeers);
    if (same && samePeers) return;

    stopVideoQt();

    auto vr = std::make_unique<VideoRuntime>();
    vr->channelMode = channelMode;
    vr->peerId = runtimePeerId;
    vr->callId = runtimeCallId;
    vr->codec = video::codecFromString(selectedTxCodec);
    vr->rxCodec = selectedRxCodecEnum;
    vr->passthrough = useScreenCapture ? false : canPassthrough;
    vr->screenShare = useScreenCapture;
    vr->screenName = selectedScreenName;
    vr->captureFourcc = selectedFourcc;
    vr->width = selectedWidth;
    vr->height = selectedHeight;
    vr->fpsNum = selectedFpsNum;
    vr->fpsDen = selectedFpsDen;
    vr->bitrateKbps = selectedBitrate;
    vr->provider = selectedProvider;
    vr->streamId = 1;
    vr->remoteWatching.store(callRemoteWatchingVideo, std::memory_order_relaxed);
    if (channelMode) vr->txPeers = voiceChannelPeers;

    QString err;
    if (!channelMode) {
      if (!vr->decoder.open(vr->rxCodec, &err)) {
        emit q->logLine("video: decoder unavailable: " + err);
        return;
      }
    }

    if (!wantCapture) {
      vr->sharing = false;
      videoRt = std::move(vr);
      emit q->logLine("video: receive-only mode (local capture disabled)");
      return;
    }

    if (!vr->passthrough) {
      video::EncodeParams ep;
      ep.codec = vr->codec;
      ep.provider = vr->provider;
      ep.width = vr->width;
      ep.height = vr->height;
      ep.fpsNum = vr->fpsDen;
      ep.fpsDen = vr->fpsNum;
      ep.bitrateKbps = vr->bitrateKbps;
      if (!vr->encoder.open(ep, &err)) {
        emit q->logLine("video: encoder unavailable: " + err);
        if (!channelMode) vr->decoder.close();
        return;
      }
      vr->codec = vr->encoder.codec();
    }

    auto sendEncodedFrames = [this](const std::vector<video::EncodedFrame>& out) {
      if (out.empty()) return;
      if (!videoRt) return;
      QStringList peers;
      if (videoRt->channelMode) {
        peers = videoRt->txPeers.values();
      } else {
        if (!callRemoteWatchingVideo) return;
        if (!videoRt->peerId.isEmpty()) peers.push_back(videoRt->peerId);
      }
      if (peers.isEmpty()) return;
      for (const auto& ef : out) {
        for (const auto& peerId : peers) {
          const auto pid = peerId.toStdString();
          const auto bytes = ef.bytes;
          const bool key = ef.keyframe;
          const uint32_t pts = static_cast<uint32_t>(ef.ptsMs & 0xFFFFFFFFu);
          boost::asio::post(io, [this, pid, bytes, key, pts]() mutable {
            auto it = udp_sessions.find(pid);
            if (it == udp_sessions.end() || !it->second) return;
            it->second->send_video_frame(bytes, key, pts);
          });
        }
        if (videoRt) videoRt->txFrames++;
        if (debug_logs_enabled() && videoRt && (videoRt->txFrames % 60) == 1) {
          emit q->logLine("[dbg] video tx frame bytes=" + QString::number(static_cast<int>(ef.bytes.size())) +
                          " key=" + QString::number(ef.keyframe ? 1 : 0));
        }
      }
    };

    if (useScreenCapture) {
      if (vr->screenName.trimmed().isEmpty()) {
        emit q->logLine("video: screen share requested but no display selected");
        vr->encoder.close();
        vr->decoder.close();
        return;
      }

      const double fps = static_cast<double>(std::max(1, vr->fpsDen)) / static_cast<double>(std::max(1, vr->fpsNum));
      int intervalMs = std::clamp(static_cast<int>(std::lround(1000.0 / std::max(1.0, fps))), 16, 250);
#if defined(__linux__)
      // On X11, high-frequency desktop capture can thrash compositor/game frame pacing.
      // Cap capture rate unless user explicitly opts out.
      const char* capRaw = std::getenv("P2PCHAT_X11_CAPTURE_MAX_FPS");
      int x11CapFps = 20;
      if (capRaw && *capRaw) {
        bool ok = false;
        const int parsed = QString::fromUtf8(capRaw).trimmed().toInt(&ok);
        if (ok && parsed >= 5 && parsed <= 60) x11CapFps = parsed;
      }
      if (is_x11_platform()) {
        const int cappedInterval = std::max(16, static_cast<int>(std::lround(1000.0 / static_cast<double>(x11CapFps))));
        intervalMs = std::max(intervalMs, cappedInterval);
      }
#endif
      vr->screenMinIntervalMs = intervalMs;

      vr->screenWorkStop = false;
      vr->screenWorkHasFrame = false;
      vr->screenWorkFrame = QImage();
      vr->screenWorkThread = std::thread([this, rt = vr.get()] {
        while (true) {
          QImage frame;
          {
            std::unique_lock lk(rt->screenWorkMu);
            rt->screenWorkCv.wait(lk, [rt] { return rt->screenWorkStop || rt->screenWorkHasFrame; });
            if (rt->screenWorkStop) break;
            frame = std::move(rt->screenWorkFrame);
            rt->screenWorkHasFrame = false;
          }
          if (frame.isNull()) continue;
          const bool previewEnabled = localVideoPreviewEnabled.load(std::memory_order_relaxed);
          if (!previewEnabled) {
            if (!rt->channelMode && !rt->remoteWatching.load(std::memory_order_relaxed)) continue;
            if (rt->channelMode && rt->txPeers.isEmpty()) continue;
          }
          if (frame.width() != rt->width || frame.height() != rt->height) {
            frame = frame.scaled(rt->width, rt->height, Qt::IgnoreAspectRatio, Qt::FastTransformation);
          }
          if (previewEnabled) {
            postToQt([this, frame]() mutable { emit q->localVideoFrame(frame); });
          }

          if (!rt->channelMode && !rt->remoteWatching.load(std::memory_order_relaxed)) continue;
          if (rt->channelMode && rt->txPeers.isEmpty()) continue;

          video::I420Frame i420;
          QString cvtErr;
          if (!video::qimageToI420(frame, &i420, &cvtErr)) {
            rt->convertFailures++;
            if (debug_logs_enabled() && (rt->convertFailures % 30) == 1) {
              postToQt([this, cvtErr] { emit q->logLine("[dbg] screen convert failed err=" + cvtErr); });
            }
            continue;
          }

          std::vector<video::EncodedFrame> out;
          QString encErr;
          if (!rt->encoder.encode(i420, &out, &encErr)) {
            rt->encodeFailures++;
            if (debug_logs_enabled() && (rt->encodeFailures % 30) == 1) {
              postToQt([this, encErr] { emit q->logLine("[dbg] screen encode failed err=" + encErr); });
            }
            continue;
          }

          QStringList peers;
          if (rt->channelMode) {
            peers = rt->txPeers.values();
          } else if (!rt->peerId.isEmpty()) {
            peers.push_back(rt->peerId);
          }
          if (peers.isEmpty()) continue;

          for (const auto& ef : out) {
            for (const auto& peerId : peers) {
              const auto pid = peerId.toStdString();
              const auto bytes = ef.bytes;
              const bool key = ef.keyframe;
              const uint32_t pts = static_cast<uint32_t>(ef.ptsMs & 0xFFFFFFFFu);
              boost::asio::post(io, [this, pid, bytes, key, pts]() mutable {
                auto it = udp_sessions.find(pid);
                if (it == udp_sessions.end() || !it->second) return;
                it->second->send_video_frame(bytes, key, pts);
              });
            }
            rt->txFrames++;
            if (debug_logs_enabled() && (rt->txFrames % 60) == 1) {
              postToQt([this, size = static_cast<int>(ef.bytes.size()), key = ef.keyframe] {
                emit q->logLine("[dbg] video tx frame bytes=" + QString::number(size) +
                                " key=" + QString::number(key ? 1 : 0));
              });
            }
          }
          rt->captureFrames++;
        }
      });

      vr->sharing = true;
      videoRt = std::move(vr);

      auto enqueueScreenFrame = [this, runtimePeerId](QImage frame) {
        if (!videoRt || !videoRt->screenShare) return;
        if (!videoRt->channelMode && videoRt->peerId != runtimePeerId) return;
        if (frame.isNull()) return;
        const bool previewEnabled = localVideoPreviewEnabled.load(std::memory_order_relaxed);
        if (!previewEnabled) {
          if (!videoRt->channelMode && !videoRt->remoteWatching.load(std::memory_order_relaxed)) return;
          if (videoRt->channelMode && videoRt->txPeers.isEmpty()) return;
        }
        {
          std::lock_guard lk(videoRt->screenWorkMu);
          videoRt->screenWorkFrame = std::move(frame);
          videoRt->screenWorkHasFrame = true;
        }
        videoRt->screenWorkCv.notify_one();
      };

      auto startLegacyScreenGrab = [this, runtimePeerId, enqueueScreenFrame]() {
        if (!videoRt || !videoRt->screenShare || videoRt->screenTimer) return;
        videoRt->qtScreenBackend = false;
        videoRt->screenBackendName = "legacy";
        videoRt->screenTimer = new QTimer(q);
        videoRt->screenTimer->setInterval(videoRt->screenMinIntervalMs);
        QObject::connect(videoRt->screenTimer, &QTimer::timeout, q, [this, runtimePeerId, enqueueScreenFrame] {
          if (!videoRt || !videoRt->screenShare) return;
          if (!videoRt->channelMode && videoRt->peerId != runtimePeerId) return;
          auto* screen = find_screen_by_name(videoRt->screenName);
          if (!screen) return;
          QPixmap shot = screen->grabWindow(0);
          if (shot.isNull()) return;
          enqueueScreenFrame(shot.toImage());
        });
        videoRt->screenTimer->start();
      };

      auto startX11ShmScreenGrab = [this, enqueueScreenFrame]() -> bool {
#if defined(P2PCHAT_X11_SHM)
        if (!videoRt || !videoRt->screenShare || videoRt->screenCaptureThread.joinable()) return false;
        auto* screen = find_screen_by_name(videoRt->screenName);
        if (!screen) return false;
        const QRect g = screen->geometry();
        auto cap = std::make_unique<video::X11ShmCapture>();
        QString openErr;
        if (!cap->open(g.x(), g.y(), g.width(), g.height(), &openErr)) {
          if (debug_logs_enabled()) emit q->logLine("[dbg] x11shm open failed: " + openErr);
          return false;
        }
        videoRt->screenCaptureX11Shm = std::move(cap);
        videoRt->screenCaptureStop.store(false, std::memory_order_relaxed);
        videoRt->qtScreenBackend = false;
        videoRt->screenBackendName = "x11shm";
        videoRt->screenCaptureThread = std::thread([this, rt = videoRt.get(), enqueueScreenFrame] {
          uint64_t failCount = 0;
          auto nextTick = std::chrono::steady_clock::now();
          while (!rt->screenCaptureStop.load(std::memory_order_relaxed)) {
            if (!rt->channelMode &&
                !localVideoPreviewEnabled.load(std::memory_order_relaxed) &&
                !rt->remoteWatching.load(std::memory_order_relaxed)) {
              nextTick += std::chrono::milliseconds(std::max(1, rt->screenMinIntervalMs));
              const auto now = std::chrono::steady_clock::now();
              if (nextTick > now) std::this_thread::sleep_until(nextTick);
              continue;
            }
            bool workerBusy = false;
            {
              std::lock_guard lk(rt->screenWorkMu);
              workerBusy = rt->screenWorkHasFrame;
            }
            if (!workerBusy) {
              QImage frame;
              QString grabErr;
              if (rt->screenCaptureX11Shm && rt->screenCaptureX11Shm->grab(&frame, &grabErr)) {
                enqueueScreenFrame(std::move(frame));
              } else {
                failCount++;
                if (debug_logs_enabled() && (failCount % 100) == 1) {
                  postToQt([this, grabErr] { emit q->logLine("[dbg] x11shm grab failed: " + grabErr); });
                }
              }
            }

            nextTick += std::chrono::milliseconds(std::max(1, rt->screenMinIntervalMs));
            const auto now = std::chrono::steady_clock::now();
            if (nextTick > now) {
              std::this_thread::sleep_until(nextTick);
            } else {
              nextTick = now;
            }
          }
        });
        return true;
#else
        (void)enqueueScreenFrame;
        return false;
#endif
      };

#if defined(P2PCHAT_QT_SCREEN_CAPTURE)
      bool startedCapture = false;
      if (prefer_x11_shm_screen_backend()) {
        startedCapture = startX11ShmScreenGrab();
      }
      bool startedQtCapture = false;
      if (!startedCapture && prefer_qt_screen_capture_backend()) {
        auto* screen = find_screen_by_name(videoRt->screenName);
        if (screen) {
          videoRt->qtScreenBackend = true;
          videoRt->screenBackendName = "qt";
          videoRt->screenCaptureQt = new QScreenCapture(q);
          videoRt->screenSessionQt = new QMediaCaptureSession(q);
          videoRt->screenSinkQt = new QVideoSink(q);
          videoRt->screenSessionQt->setScreenCapture(videoRt->screenCaptureQt);
          videoRt->screenSessionQt->setVideoSink(videoRt->screenSinkQt);
          videoRt->screenCaptureQt->setScreen(screen);
          QObject::connect(videoRt->screenSinkQt, &QVideoSink::videoFrameChanged, q, [this, enqueueScreenFrame](const QVideoFrame& vf) {
            if (!videoRt || !videoRt->screenShare || !videoRt->qtScreenBackend) return;
            const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                             std::chrono::steady_clock::now().time_since_epoch())
                                                             .count());
            if ((nowMs - videoRt->lastScreenFrameMs) < static_cast<uint64_t>(std::max(1, videoRt->screenMinIntervalMs))) return;
            videoRt->lastScreenFrameMs = nowMs;
            QImage frame = vf.toImage();
            if (frame.isNull()) return;
            enqueueScreenFrame(std::move(frame));
          });
          videoRt->screenCaptureQt->start();
          startedQtCapture = true;

          if (allow_legacy_screen_fallback()) {
            videoRt->screenFallbackTimerQt = new QTimer(q);
            videoRt->screenFallbackTimerQt->setSingleShot(true);
            videoRt->screenFallbackTimerQt->setInterval(5000);
            QObject::connect(videoRt->screenFallbackTimerQt, &QTimer::timeout, q, [this, startLegacyScreenGrab] {
              if (!videoRt || !videoRt->screenShare || !videoRt->qtScreenBackend) return;
              if (videoRt->captureFrames > 0) return;
              emit q->logLine("video: Qt screen capture produced no frames; falling back to legacy X grab");
              if (videoRt->screenCaptureQt) {
                videoRt->screenCaptureQt->stop();
                videoRt->screenCaptureQt->deleteLater();
                videoRt->screenCaptureQt = nullptr;
              }
              if (videoRt->screenSinkQt) {
                videoRt->screenSinkQt->deleteLater();
                videoRt->screenSinkQt = nullptr;
              }
              if (videoRt->screenSessionQt) {
                videoRt->screenSessionQt->deleteLater();
                videoRt->screenSessionQt = nullptr;
              }
              startLegacyScreenGrab();
            });
            videoRt->screenFallbackTimerQt->start();
          }
        }
      }
      startedCapture = startedCapture || startedQtCapture;
      if (!startedCapture) startLegacyScreenGrab();
#else
      if (!startX11ShmScreenGrab()) startLegacyScreenGrab();
#endif
      emit q->logLine("video: screen sharing started (" +
                      QString("%1 %2x%3 @ %4/%5 bitrate=%6kbps backend=%7 effective_fps<=%8")
                          .arg(videoRt->screenName)
                          .arg(videoRt->width)
                          .arg(videoRt->height)
                          .arg(videoRt->fpsNum)
                          .arg(videoRt->fpsDen)
                          .arg(videoRt->bitrateKbps)
                          .arg(videoRt->screenBackendName)
                          .arg(QString::number(std::max(1, static_cast<int>(std::lround(1000.0 / std::max(1, videoRt->screenMinIntervalMs)))))) +
                      ")");
      return;
    }

    vr->capture = std::make_unique<video::V4L2Capture>();
    video::CaptureConfig cfg;
    cfg.devicePath = settings.videoDevicePath;
    cfg.fourcc = selectedFourcc;
    cfg.width = static_cast<uint32_t>(vr->width);
    cfg.height = static_cast<uint32_t>(vr->height);
    cfg.fpsNum = static_cast<uint32_t>(vr->fpsNum);
    cfg.fpsDen = static_cast<uint32_t>(vr->fpsDen);
    if (cfg.fourcc == 0) {
      cfg.fourcc = static_cast<uint32_t>(
          static_cast<uint8_t>('M') |
          (static_cast<uint32_t>(static_cast<uint8_t>('J')) << 8) |
          (static_cast<uint32_t>(static_cast<uint8_t>('P')) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>('G')) << 24));
    }

    const bool ok = vr->capture->start(
        cfg,
        [this, runtimePeerId, sendEncodedFrames](const video::RawFrame& rf) {
          if (!videoRt) return;
          if (!videoRt->channelMode && videoRt->peerId != runtimePeerId) return;
          videoRt->captureFrames++;
          video::I420Frame i420;
          QString cvtErr;
          if (!video::convertRawFrameToI420(rf, &i420, &cvtErr)) {
            videoRt->convertFailures++;
            if (debug_logs_enabled() && (videoRt->convertFailures % 30) == 1) {
              emit q->logLine("[dbg] video convert failed fourcc=0x" + QString::number(static_cast<quint32>(rf.fourcc), 16) +
                              " " + QString::number(static_cast<int>(rf.width)) + "x" + QString::number(static_cast<int>(rf.height)) +
                              " err=" + cvtErr);
            }
            return;
          }
          if (localVideoPreviewEnabled.load(std::memory_order_relaxed)) {
            emit q->localVideoFrame(video::i420ToQImage(i420));
          }

          std::vector<video::EncodedFrame> out;
          if (videoRt->passthrough) {
            video::EncodedFrame ef;
            QString passErr;
            if (!video::passthroughFrame(rf, videoRt->codec, &ef, &passErr)) {
              videoRt->encodeFailures++;
              if (debug_logs_enabled() && (videoRt->encodeFailures % 30) == 1) {
                emit q->logLine("[dbg] video passthrough failed err=" + passErr);
              }
              return;
            }
            out.push_back(std::move(ef));
          } else {
            QString encErr;
            if (!videoRt->encoder.encode(i420, &out, &encErr)) {
              videoRt->encodeFailures++;
              if (debug_logs_enabled() && (videoRt->encodeFailures % 30) == 1) {
                emit q->logLine("[dbg] video encode failed err=" + encErr);
              }
              return;
            }
          }
          sendEncodedFrames(out);
        },
        [this](const QString& e) { emit q->logLine("video capture error: " + e); });
    if (!ok) {
      emit q->logLine("video: capture failed to start");
      vr->encoder.close();
      vr->decoder.close();
      return;
    }

    vr->sharing = true;
    videoRt = std::move(vr);
    emit q->logLine("video: sharing started (" +
                    QString("%1 %2x%3 @ %4/%5 bitrate=%6kbps mode=%7")
                        .arg(settings.videoFourcc)
                        .arg(settings.videoWidth)
                        .arg(settings.videoHeight)
                        .arg(settings.videoFpsNum)
                        .arg(settings.videoFpsDen)
                        .arg(settings.videoBitrateKbps)
                        .arg(videoRt->passthrough ? "passthrough" : ("re-encode/" + videoRt->provider)) +
                    ")");
  }

  void requestVideoKeyframeQt(const QString& peerId) {
    if (peerId.isEmpty()) return;
    const auto pid = peerId.toStdString();
    boost::asio::post(io, [this, pid] {
      json j;
      j["type"] = "video_keyframe_request";
      sendControlToPeer(pid, std::move(j));
    });
  }

  void handleVideoFrameQt(const QString& peerId, const QByteArray& encoded) {
    if (peerId.isEmpty() || encoded.isEmpty()) return;
    if (!videoRt) return;
    if (videoRt->channelMode) {
      if (!videoRt->txPeers.contains(peerId)) return;
      const auto key = peerId.toStdString();
      auto& decPtr = videoRt->channelDecoders[key];
      const auto hintedIt = videoRt->channelPeerCodecHints.find(key);
      const auto hintedCodec = hintedIt != videoRt->channelPeerCodecHints.end() ? hintedIt->second : videoRt->rxCodec;
      auto openDecoder = [&](video::Codec codec) -> bool {
        decPtr.reset();
        auto decoder = std::make_unique<video::Decoder>();
        QString openErr;
        if (!decoder->open(codec, &openErr)) {
          if (debug_logs_enabled()) {
            emit q->logLine("[dbg] video decoder open failed peer=" + peerId +
                            " codec=" + video::codecToString(codec) + " err=" + openErr);
          }
          return false;
        }
        decPtr = std::move(decoder);
        videoRt->channelDecoderCodecs[key] = codec;
        return true;
      };
      if (!decPtr) {
        if (!openDecoder(hintedCodec)) return;
      }
      QImage img;
      QString err;
      if (decPtr->decode(reinterpret_cast<const uint8_t*>(encoded.constData()),
                         static_cast<size_t>(encoded.size()),
                         &img,
                         &err)) {
        videoRt->channelDecodeFailures[key] = 0;
        videoRt->rxFrames++;
        if (!img.isNull()) {
          emit q->remoteVideoAvailabilityChanged(peerId, true);
          emit q->remoteVideoFrame(peerId, img);
        }
        return;
      }
      auto& fails = videoRt->channelDecodeFailures[key];
      fails++;
      if (debug_logs_enabled() && (fails % 20) == 1) {
        emit q->logLine("[dbg] video decode failed peer=" + peerId + " err=" + err + " bytes=" + QString::number(encoded.size()));
      }
      if (fails >= 8) {
        const auto currentIt = videoRt->channelDecoderCodecs.find(key);
        const auto currentCodec = currentIt != videoRt->channelDecoderCodecs.end() ? currentIt->second : hintedCodec;
        const auto fallbackCodec = next_video_codec_fallback(currentCodec);
        if (fallbackCodec != currentCodec && openDecoder(fallbackCodec)) {
          QImage retryImg;
          QString retryErr;
          if (decPtr->decode(reinterpret_cast<const uint8_t*>(encoded.constData()),
                             static_cast<size_t>(encoded.size()),
                             &retryImg,
                             &retryErr)) {
            videoRt->channelPeerCodecHints[key] = fallbackCodec;
            videoRt->channelDecodeFailures[key] = 0;
            videoRt->rxFrames++;
            if (debug_logs_enabled()) {
              emit q->logLine("[dbg] video codec autodetect peer=" + peerId +
                              " codec=" + video::codecToString(fallbackCodec));
            }
            if (!retryImg.isNull()) {
              emit q->remoteVideoAvailabilityChanged(peerId, true);
              emit q->remoteVideoFrame(peerId, retryImg);
            }
            return;
          }
        }
      }
      const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                       std::chrono::steady_clock::now().time_since_epoch())
                                                       .count());
      auto& lastReq = videoRt->channelLastKeyframeReqMs[key];
      if (fails >= 10 && (nowMs - lastReq) > 500) {
        lastReq = nowMs;
        requestVideoKeyframeQt(peerId);
      }
      return;
    }

    if (videoRt->peerId != peerId) return;
    QImage img;
    QString err;
    if (videoRt->decoder.decode(reinterpret_cast<const uint8_t*>(encoded.constData()),
                                static_cast<size_t>(encoded.size()),
                                &img,
                                &err)) {
      videoRt->decodeFailures = 0;
      videoRt->rxFrames++;
      if (debug_logs_enabled() && (videoRt->rxFrames % 60) == 1) {
        emit q->logLine("[dbg] video rx frame bytes=" + QString::number(encoded.size()));
      }
      if (!img.isNull()) emit q->remoteVideoFrame(peerId, img);
      return;
    }

    videoRt->decodeFailures++;
    if (debug_logs_enabled() && (videoRt->decodeFailures % 20) == 1) {
      emit q->logLine("[dbg] video decode failed err=" + err + " bytes=" + QString::number(encoded.size()));
    }
    if (videoRt->decodeFailures >= 8) {
      const auto fallbackCodec = next_video_codec_fallback(videoRt->rxCodec);
      videoRt->decoder.close();
      QString openErr;
      if (videoRt->decoder.open(fallbackCodec, &openErr)) {
        QImage retryImg;
        QString retryErr;
        if (videoRt->decoder.decode(reinterpret_cast<const uint8_t*>(encoded.constData()),
                                    static_cast<size_t>(encoded.size()),
                                    &retryImg,
                                    &retryErr)) {
          videoRt->rxCodec = fallbackCodec;
          callRemoteVideoCodec = video::codecToString(fallbackCodec);
          videoRt->decodeFailures = 0;
          videoRt->rxFrames++;
          if (debug_logs_enabled()) {
            emit q->logLine("[dbg] video codec autodetect peer=" + peerId +
                            " codec=" + video::codecToString(fallbackCodec));
          }
          if (!retryImg.isNull()) emit q->remoteVideoFrame(peerId, retryImg);
          return;
        }
      } else if (debug_logs_enabled()) {
        emit q->logLine("[dbg] video decoder reopen failed codec=" + video::codecToString(fallbackCodec) +
                        " err=" + openErr);
      }
    }
    const uint64_t nowMs = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                     std::chrono::steady_clock::now().time_since_epoch())
                                                     .count());
    if (videoRt->decodeFailures >= 10 && (nowMs - videoRt->lastKeyframeReqMs) > 500) {
      videoRt->lastKeyframeReqMs = nowMs;
      requestVideoKeyframeQt(peerId);
    }
  }
#else
  void stopVideoQt() {}
  void maybeStartVideoQt() {}
  void handleVideoFrameQt(const QString&, const QByteArray&) {}
#endif
#else
  void stopVoiceQt() {}
  void maybeStartVoiceQt() {}
  void handleVoiceFrameQt(const QString&, quint64, const QByteArray&) {}
#if defined(P2PCHAT_VIDEO)
  void stopVideoQt() {}
  void maybeStartVideoQt() {}
  void handleVideoFrameQt(const QString&, const QByteArray&) {}
#endif
#endif

  void endCallQt(const QString& reason, bool notifyPeer) {
    const QString peer = callPeerId;
    const QString cid = callId;
    stopVoiceQt();
    resetCallStateQt();
    if (!peer.isEmpty()) emit q->remoteVideoAvailabilityChanged(peer, false);
    if (!peer.isEmpty()) emit q->callEnded(peer, reason);

    if (notifyPeer && !peer.isEmpty() && !cid.isEmpty()) {
      const auto pid = peer.toStdString();
      const auto call_id = cid.toStdString();
      boost::asio::post(io, [this, pid, call_id] {
        json j;
        j["type"] = "call_end";
        j["call_id"] = call_id;
        sendControlToPeer(pid, std::move(j));
      });
    }
  }

  void handleControlQt(const QString& peerId, json inner) {
    if (!inner.contains("type") || !inner["type"].is_string()) return;
    const QString type = QString::fromStdString(inner["type"].get<std::string>());

    if (type == "signed_control") {
      if (!inner.contains("kind") || !inner["kind"].is_string()) return;
      if (!inner.contains("from") || !inner["from"].is_string()) return;
      if (!inner.contains("payload") || !inner["payload"].is_object()) return;
      if (!inner.contains("sig") || !inner["sig"].is_string()) return;

      const std::string from = inner["from"].get<std::string>();
      const std::string kind = inner["kind"].get<std::string>();
      const std::string sig = inner["sig"].get<std::string>();
      const json& payload = inner["payload"];
      const std::string payloadDump = payload.dump();
      if (from != peerId.toStdString()) return;
      if (!common::Identity::verify_bytes_b64url(
              from,
              std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(payloadDump.data()), payloadDump.size()),
              sig)) {
        return;
      }

      emit q->signedControlReceived(peerId,
                                    QString::fromStdString(kind),
                                    QString::fromStdString(payloadDump),
                                    QString::fromStdString(sig),
                                    QString::fromStdString(from));
      return;
    }
    if (type == "unsigned_control") {
      if (!inner.contains("kind") || !inner["kind"].is_string()) return;
      if (!inner.contains("from") || !inner["from"].is_string()) return;
      if (!inner.contains("payload") || !inner["payload"].is_object()) return;

      const std::string from = inner["from"].get<std::string>();
      const std::string kind = inner["kind"].get<std::string>();
      const json& payload = inner["payload"];
      const std::string payloadDump = payload.dump();
      if (from != peerId.toStdString()) return;

      emit q->unsignedControlReceived(peerId,
                                      QString::fromStdString(kind),
                                      QString::fromStdString(payloadDump),
                                      QString::fromStdString(from));
      return;
    }

    if (type == "video_keyframe_request") {
#if defined(P2PCHAT_VIDEO)
      if (videoRt && ((videoRt->channelMode && videoRt->txPeers.contains(peerId)) || videoRt->peerId == peerId)) {
        if (!videoRt->passthrough) {
          videoRt->encoder.requestKeyframe();
        } else if (debug_logs_enabled()) {
          emit q->logLine("[dbg] video keyframe request ignored in passthrough mode");
        }
      }
#endif
      return;
    }

    if (type == "video_state") {
#if defined(P2PCHAT_VIDEO)
      if (voice && voice->channelMode) {
        if (!voice->txPeers.contains(peerId)) return;
        const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                                ? QString::fromStdString(inner["call_id"].get<std::string>())
                                : QString();
        if (!cid.isEmpty() && cid != "__voice_channel__") return;
        const bool enabled =
            inner.contains("enabled") && inner["enabled"].is_boolean() ? inner["enabled"].get<bool>() : false;
        const QString remoteVideoCodec =
            inner.contains("video_codec") && inner["video_codec"].is_string()
                ? normalize_video_codec(QString::fromStdString(inner["video_codec"].get<std::string>()))
                : QString();
        if (!remoteVideoCodec.isEmpty() && videoRt && videoRt->channelMode) {
          const auto key = peerId.toStdString();
          const auto codec = video::codecFromString(remoteVideoCodec);
          videoRt->channelPeerCodecHints[key] = codec;
          auto cur = videoRt->channelDecoderCodecs.find(key);
          if (cur != videoRt->channelDecoderCodecs.end() && cur->second != codec) {
            videoRt->channelDecoders.erase(key);
            videoRt->channelDecoderCodecs.erase(cur);
          }
        }
        if (!enabled) {
          emit q->remoteVideoFrame(peerId, QImage());
        } else {
          requestVideoKeyframeQt(peerId);
        }
        emit q->remoteVideoAvailabilityChanged(peerId, enabled);
        if (debug_logs_enabled()) {
          emit q->logLine("[dbg] video_state(channel) from peer=" + peerId +
                          " enabled=" + QString::number(enabled ? 1 : 0) +
                          (remoteVideoCodec.isEmpty() ? "" : " codec=" + remoteVideoCodec));
        }
        return;
      }
      if (callPeerId != peerId) return;
      const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                              ? QString::fromStdString(inner["call_id"].get<std::string>())
                              : QString();
      if (!cid.isEmpty() && cid != callId) return;
      const bool enabled =
          inner.contains("enabled") && inner["enabled"].is_boolean() ? inner["enabled"].get<bool>() : false;
      const QString remoteVideoCodec =
          inner.contains("video_codec") && inner["video_codec"].is_string()
              ? normalize_video_codec(QString::fromStdString(inner["video_codec"].get<std::string>()))
              : QString();
      callRemoteVideoEnabled = enabled;
      if (!remoteVideoCodec.isEmpty()) {
        callRemoteVideoCodec = remoteVideoCodec;
        if (videoRt && !videoRt->channelMode && videoRt->peerId == peerId) {
          const auto wantedCodec = video::codecFromString(remoteVideoCodec);
          if (videoRt->rxCodec != wantedCodec) {
            videoRt->decoder.close();
            QString openErr;
            if (videoRt->decoder.open(wantedCodec, &openErr)) {
              videoRt->rxCodec = wantedCodec;
              videoRt->decodeFailures = 0;
              if (debug_logs_enabled()) {
                emit q->logLine("[dbg] video decoder switched peer=" + peerId + " codec=" + remoteVideoCodec);
              }
            } else if (debug_logs_enabled()) {
              emit q->logLine("[dbg] video decoder switch failed peer=" + peerId + " codec=" + remoteVideoCodec +
                              " err=" + openErr);
            }
          }
        }
      }
      if (!enabled) {
        emit q->remoteVideoFrame(peerId, QImage());
      } else {
        requestVideoKeyframeQt(peerId);
      }
      emit q->remoteVideoAvailabilityChanged(peerId, enabled);
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] video_state from peer=" + peerId + " enabled=" + QString::number(enabled ? 1 : 0) +
                        " codec=" + (remoteVideoCodec.isEmpty() ? callRemoteVideoCodec : remoteVideoCodec));
      }
#endif
      return;
    }

    if (type == "video_watch") {
#if defined(P2PCHAT_VIDEO)
      if (voice && voice->channelMode) return;
      if (callPeerId != peerId) return;
      const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                              ? QString::fromStdString(inner["call_id"].get<std::string>())
                              : QString();
      if (!cid.isEmpty() && cid != callId) return;
      const bool watching =
          inner.contains("watching") && inner["watching"].is_boolean() ? inner["watching"].get<bool>() : true;
      callRemoteWatchingVideo = watching;
      if (videoRt && !videoRt->channelMode && videoRt->peerId == peerId) {
        videoRt->remoteWatching.store(watching, std::memory_order_relaxed);
      }
      if (watching && videoRt && videoRt->peerId == peerId && videoRt->sharing && !videoRt->passthrough) {
        videoRt->encoder.requestKeyframe();
      }
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] video_watch from peer=" + peerId + " watching=" + QString::number(watching ? 1 : 0));
      }
#endif
      return;
    }

    if (type == "call_offer") {
      const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                              ? QString::fromStdString(inner["call_id"].get<std::string>())
                              : QString();
      if (cid.isEmpty()) return;

      const int frameMs = inner.contains("frame_ms") && inner["frame_ms"].is_number_integer()
                              ? inner["frame_ms"].get<int>()
                              : 20;
      const int channels = inner.contains("ch") && inner["ch"].is_number_integer()
                               ? inner["ch"].get<int>()
                               : 1;
      const int bitrate = inner.contains("bitrate") && inner["bitrate"].is_number_integer()
                              ? inner["bitrate"].get<int>()
                              : 32000;
      const bool remoteVideoEnabled =
          inner.contains("video_enabled") && inner["video_enabled"].is_boolean() ? inner["video_enabled"].get<bool>() : false;
      const QString remoteVideoCodec =
          inner.contains("video_codec") && inner["video_codec"].is_string()
              ? normalize_video_codec(QString::fromStdString(inner["video_codec"].get<std::string>()))
              : QString();

      if (!callPeerId.isEmpty()) {
        // Busy.
        const auto pid = peerId.toStdString();
        const auto call_id = cid.toStdString();
        boost::asio::post(io, [this, pid, call_id] {
          json a;
          a["type"] = "call_answer";
          a["call_id"] = call_id;
          a["accept"] = false;
          a["reason"] = "busy";
          sendControlToPeer(pid, std::move(a));
        });
        return;
      }

      callPeerId = peerId;
      callId = cid;
      callOutgoing = false;
      callLocalAccepted = false;
      callRemoteAccepted = true;
      callFrameMs = (frameMs == 10) ? 10 : 20;
      callChannels = (channels == 2) ? 2 : 1;
      callBitrate = std::clamp(bitrate, 8000, 128000);
      callRemoteVideoEnabled = remoteVideoEnabled;
      callRemoteWatchingVideo = true;
      if (!remoteVideoCodec.isEmpty()) callRemoteVideoCodec = remoteVideoCodec;
      emit q->remoteVideoAvailabilityChanged(callPeerId, callRemoteVideoEnabled);
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] incoming call offer peer=" + callPeerId + " call_id=" + callId +
                        " frameMs=" + QString::number(callFrameMs) + " bitrate=" + QString::number(callBitrate) +
                        " channels=" + QString::number(callChannels) +
                        " remoteVideo=" + QString::number(callRemoteVideoEnabled ? 1 : 0) +
                        " codec=" + callRemoteVideoCodec);
      }
      emit q->callStateChanged(callPeerId, "incoming");
      emit q->incomingCall(callPeerId);
      return;
    }

    if (type == "call_answer") {
      if (callPeerId != peerId) return;
      const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                              ? QString::fromStdString(inner["call_id"].get<std::string>())
                              : QString();
      if (cid.isEmpty() || cid != callId) return;
      const bool accept = inner.contains("accept") && inner["accept"].is_boolean() ? inner["accept"].get<bool>() : false;
      if (!accept) {
        endCallQt("call rejected", /*notifyPeer*/ false);
        return;
      }
      const int remoteFrameMs = inner.contains("frame_ms") && inner["frame_ms"].is_number_integer()
                                    ? inner["frame_ms"].get<int>()
                                    : callFrameMs;
      const int remoteChannels = inner.contains("ch") && inner["ch"].is_number_integer()
                                     ? inner["ch"].get<int>()
                                     : callChannels;
      const bool remoteVideoEnabled =
          inner.contains("video_enabled") && inner["video_enabled"].is_boolean() ? inner["video_enabled"].get<bool>() : callRemoteVideoEnabled;
      const QString remoteVideoCodec =
          inner.contains("video_codec") && inner["video_codec"].is_string()
              ? normalize_video_codec(QString::fromStdString(inner["video_codec"].get<std::string>()))
              : QString();
      const int negotiatedFrameMs = (remoteFrameMs == 10) ? 10 : 20;
      callFrameMs = negotiatedFrameMs;
      callChannels = (remoteChannels == 2) ? 2 : 1;
      callRemoteAccepted = true;
      callRemoteVideoEnabled = remoteVideoEnabled;
      if (!remoteVideoCodec.isEmpty()) callRemoteVideoCodec = remoteVideoCodec;
      emit q->remoteVideoAvailabilityChanged(callPeerId, callRemoteVideoEnabled);
      if (debug_logs_enabled()) {
        emit q->logLine("[dbg] call_answer accepted by peer=" + peerId + " call_id=" + callId +
                        " negotiatedFrameMs=" + QString::number(callFrameMs) +
                        " channels=" + QString::number(callChannels) +
                        " remoteVideo=" + QString::number(callRemoteVideoEnabled ? 1 : 0) +
                        " codec=" + callRemoteVideoCodec);
      }
      emit q->callStateChanged(callPeerId, "connecting");
      maybeStartVoiceQt();
      return;
    }

    if (type == "call_end") {
      const QString cid = inner.contains("call_id") && inner["call_id"].is_string()
                              ? QString::fromStdString(inner["call_id"].get<std::string>())
                              : QString();
      if (callPeerId == peerId && !cid.isEmpty() && cid == callId) {
        endCallQt("call ended", /*notifyPeer*/ false);
      }
      return;
    }
  }

  void onPeerReadyQt(const QString& peerId) {
    emit q->directPeerConnectionChanged(peerId, true);
    if (voice) {
      if (voice->channelMode) {
        auto it = voice->rxPeers.find(peerId);
        if (it != voice->rxPeers.end()) {
          if (it->dec) opus_decoder_ctl(it->dec, OPUS_RESET_STATE);
          it->jitter.clear();
          it->expectedSeq = 0;
          it->playoutStarted = false;
        }
      } else if (voice->peerId == peerId) {
        if (voice->dec) opus_decoder_ctl(voice->dec, OPUS_RESET_STATE);
        voice->jitter.clear();
        voice->expectedSeq = 0;
        voice->playoutStarted = false;
        if (voice->playoutTimer) voice->playoutTimer->stop();
      }
    }
    if (peerId != callPeerId) return;
    if (callPeerId.isEmpty()) return;
    if (callLocalAccepted && callRemoteAccepted) maybeStartVoiceQt();
  }

  bool isAccepted(const std::string& id) {
    std::lock_guard lk(m);
    return accepted_friends.find(id) != accepted_friends.end();
  }

  bool isServerMember(const std::string& id) {
    std::lock_guard lk(m);
    return server_members.find(id) != server_members.end();
  }

  bool isRoutablePeer(const std::string& id) {
    std::lock_guard lk(m);
    return accepted_friends.find(id) != accepted_friends.end() || server_members.find(id) != server_members.end();
  }

  std::string getSelfName() {
    std::lock_guard lk(m);
    return self_name;
  }

  std::string getSelfNameForPeer(const std::string& peer_id) {
    std::lock_guard lk(m);
    if (accepted_friends.find(peer_id) == accepted_friends.end()) return {};
    return self_name;
  }

  std::vector<uint8_t> getSelfAvatarPng() {
    std::lock_guard lk(m);
    return self_avatar_png;
  }

  void refreshIdentityForPeer(const std::string& peer_id) {
    const auto name = getSelfNameForPeer(peer_id);
    const auto avatar = getSelfAvatarPng();

    if (auto it = tcp_sessions.find(peer_id); it != tcp_sessions.end() && it->second) {
      if (!name.empty()) it->second->send_name(name);
      if (!avatar.empty()) it->second->send_avatar(avatar);
    }
    if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second) {
      if (!name.empty()) it->second->send_name(name);
      if (!avatar.empty()) it->second->send_avatar(avatar);
    }
  }

  void setAccepted(const std::string& id, bool ok) {
    std::lock_guard lk(m);
    if (ok) accepted_friends.insert(id);
    else accepted_friends.erase(id);
  }

  void setServerMembers(const std::unordered_set<std::string>& peers) {
    std::lock_guard lk(m);
    server_members = peers;
  }

  void queueOutgoing(const std::string& peer, std::string text) {
    std::lock_guard lk(m);
    queued_outgoing[peer].push_back(std::move(text));
  }

  void queueControl(const std::string& peer, json inner) {
    std::lock_guard lk(m);
    queued_control[peer].push_back(std::move(inner));
    if (queued_control[peer].size() > 64) queued_control[peer].pop_front();
  }

  void flushOutgoing(const std::string& peer) {
    std::deque<std::string> msgs;
    {
      std::lock_guard lk(m);
      auto it = queued_outgoing.find(peer);
      if (it == queued_outgoing.end()) return;
      msgs = std::move(it->second);
      queued_outgoing.erase(it);
    }
    auto u = udp_sessions.find(peer);
    if (u != udp_sessions.end() && u->second) {
      while (!msgs.empty()) {
        u->second->send_chat(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
    auto t = tcp_sessions.find(peer);
    if (t != tcp_sessions.end() && t->second) {
      while (!msgs.empty()) {
        t->second->send_chat(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
  }

  void flushControl(const std::string& peer) {
    std::deque<json> msgs;
    {
      std::lock_guard lk(m);
      auto it = queued_control.find(peer);
      if (it == queued_control.end()) return;
      msgs = std::move(it->second);
      queued_control.erase(it);
    }
    auto u = udp_sessions.find(peer);
    if (u != udp_sessions.end() && u->second) {
      while (!msgs.empty()) {
        u->second->send_control(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
    auto t = tcp_sessions.find(peer);
    if (t != tcp_sessions.end() && t->second) {
      while (!msgs.empty()) {
        t->second->send_control(std::move(msgs.front()));
        msgs.pop_front();
      }
      return;
    }
  }

  void sendControlToPeer(const std::string& peer, json inner) {
    if (auto u = udp_sessions.find(peer); u != udp_sessions.end() && u->second) {
      u->second->send_control(std::move(inner));
      return;
    }
    if (auto t = tcp_sessions.find(peer); t != tcp_sessions.end() && t->second) {
      t->second->send_control(std::move(inner));
      return;
    }
    queueControl(peer, std::move(inner));
    attemptDelivery(peer, /*silent*/ true);
  }

  void bindAcceptor(uint16_t port) {
    boost::system::error_code ec;
    tcp::endpoint ep(boost::asio::ip::address_v4::any(), port);
    acceptor.open(ep.protocol(), ec);
    acceptor.set_option(tcp::acceptor::reuse_address(true), ec);
    acceptor.bind(ep, ec);
    if (ec) throw std::runtime_error("bind failed");
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) throw std::runtime_error("listen failed");
  }

  void bindUdp(uint16_t port) {
    boost::system::error_code ec;
    udp_socket.open(udp::v4(), ec);
    if (ec) throw std::runtime_error("udp open failed");
#if defined(_WIN32)
    disable_udp_connreset(udp_socket);
#endif
    udp_socket.bind(udp::endpoint(boost::asio::ip::address_v4::any(), port), ec);
    if (ec) throw std::runtime_error("udp bind failed");
    udp_read_loop();
  }

  void udp_read_loop() {
    auto buf = std::make_shared<std::array<uint8_t, common::kMaxFrameSize + 4>>();
    auto remote = std::make_shared<udp::endpoint>();
    udp_socket.async_receive_from(boost::asio::buffer(*buf), *remote,
                                  [this, buf, remote](const boost::system::error_code& ec, std::size_t n) {
                                    if (ec) {
                                      if (ec == boost::asio::error::operation_aborted) return;
                                      if (debug_logs_enabled()) {
                                        postToQt([this, msg = QString::fromStdString(ec.message())] {
                                          emit q->logLine("[dbg] udp recv error: " + msg);
                                        });
                                      }
                                      return udp_read_loop();
                                    }
                                    if (n == 0) return udp_read_loop();
#if defined(P2PCHAT_VOICE)
                                    if (n >= 20 && read_u32be(buf->data()) == kVoiceMagic) {
                                      handle_udp_voice_packet(std::span<const uint8_t>(buf->data(), n), *remote);
                                      return udp_read_loop();
                                    }
#endif
#if defined(P2PCHAT_VIDEO)
                                    if (n >= sizeof(video::VideoPktHdr) && read_u32be(buf->data()) == kVideoMagic) {
                                      handle_udp_video_packet(std::span<const uint8_t>(buf->data(), n), *remote);
                                      return udp_read_loop();
                                    }
#endif
                                    const auto jopt = common::parse_framed_json_bytes(
                                        std::span<const uint8_t>(buf->data(), n), common::kMaxFrameSize);
                                    if (!jopt) return udp_read_loop();
                                    handle_udp_datagram(*jopt, *remote);
                                    udp_read_loop();
                                  });
  }

#if defined(P2PCHAT_VOICE)
  void handle_udp_voice_packet(std::span<const uint8_t> pkt, const udp::endpoint& from) {
    if (pkt.size() < 20) {
      if (debug_logs_enabled() && (++udp_voice_drop_bad_frame % 200) == 1) {
        postToQt([this] { emit q->logLine("[dbg] udp voice drop: short packet"); });
      }
      return;
    }
    if (read_u32be(pkt.data()) != kVoiceMagic) return;
    if (pkt[4] != kVoiceVersion) {
      if (debug_logs_enabled() && (++udp_voice_drop_bad_frame % 200) == 1) {
        postToQt([this] { emit q->logLine("[dbg] udp voice drop: bad version"); });
      }
      return;
    }
    const uint64_t seq = read_u64be(pkt.data() + 6);
    const uint32_t ts = read_u32be(pkt.data() + 14);
    const uint16_t ct_len = read_u16be(pkt.data() + 18);
    if (20u + static_cast<std::size_t>(ct_len) != pkt.size()) {
      if (debug_logs_enabled() && (++udp_voice_drop_bad_frame % 200) == 1) {
        postToQt([this, got = pkt.size(), want = 20u + static_cast<std::size_t>(ct_len)] {
          emit q->logLine("[dbg] udp voice drop: length mismatch got=" + QString::number(got) + " want=" +
                          QString::number(want));
        });
      }
      return;
    }
    const auto ct = pkt.subspan(20, ct_len);

    const std::string epkey = common::endpoint_to_string(from);
    auto it = udp_ep_to_peer.find(epkey);
    if (it == udp_ep_to_peer.end()) {
      if (debug_logs_enabled() && (++udp_voice_drop_no_map % 200) == 1) {
        postToQt([this, epkey] { emit q->logLine("[dbg] udp voice drop: no ep map for " + QString::fromStdString(epkey)); });
      }
      return;
    }
    const std::string& pid = it->second;
    auto sit = udp_sessions.find(pid);
    if (sit == udp_sessions.end() || !sit->second) {
      if (debug_logs_enabled() && (++udp_voice_drop_no_session % 200) == 1) {
        postToQt([this, pid] {
          emit q->logLine("[dbg] udp voice drop: no session for " + QString::fromStdString(pid));
        });
      }
      return;
    }
    if (debug_logs_enabled()) {
      udp_voice_routed++;
      if ((udp_voice_routed % 200) == 1) {
        postToQt([this, pid, seq, ts, ct_len] {
          emit q->logLine("[dbg] udp voice routed peer=" + QString::fromStdString(pid) + " seq=" + QString::number(seq) +
                          " ts=" + QString::number(ts) + " ct=" + QString::number(ct_len));
        });
      }
    }
    sit->second->handle_voice_packet(seq, ts, ct, from);
  }
#endif

#if defined(P2PCHAT_VIDEO)
  void handle_udp_video_packet(std::span<const uint8_t> pkt, const udp::endpoint& from) {
    if (pkt.size() < sizeof(video::VideoPktHdr)) return;
    if (read_u32be(pkt.data()) != kVideoMagic) return;
    if (pkt[4] != kVideoVersion) return;

    const std::string epkey = common::endpoint_to_string(from);
    auto it = udp_ep_to_peer.find(epkey);
    if (it == udp_ep_to_peer.end()) return;
    const std::string& pid = it->second;
    auto sit = udp_sessions.find(pid);
    if (sit == udp_sessions.end() || !sit->second) return;
    sit->second->handle_video_packet(pkt, from);
  }
#endif

  void handle_udp_datagram(const json& j, const udp::endpoint& from) {
    if (!j.contains("type") || !j["type"].is_string()) return;
    const std::string type = j["type"].get<std::string>();
    if (type == "udp_announce_ok") {
      if (!udp_announce_confirmed) {
        udp_announce_confirmed = true;
        postToQt([this] { emit q->logLine("udp rendezvous announce confirmed"); });
      }
      return;
    }

    const std::string epkey = common::endpoint_to_string(from);
    if (auto it = udp_ep_to_peer.find(epkey); it != udp_ep_to_peer.end()) {
      const std::string& pid = it->second;
      if (auto sit = udp_sessions.find(pid); sit != udp_sessions.end() && sit->second) {
        sit->second->handle_datagram(j, from);
        return;
      }
      udp_ep_to_peer.erase(it);
    }

    // Route by claimed peer ID for handshake packets (endpoint may not be mapped yet).
    if ((type == "secure_hello" || type == "secure_hello_ack") && j.contains("id") && j["id"].is_string()) {
      const std::string pid = j["id"].get<std::string>();
      if (auto sit = udp_sessions.find(pid); sit != udp_sessions.end() && sit->second) {
        udp_ep_to_peer[epkey] = pid;
        sit->second->handle_datagram(j, from);
        return;
      }

      if (type == "secure_hello") {
        if (!isRoutablePeer(pid)) return;
        const std::string selfId = std::string(identity->public_id());
        auto session = std::make_shared<UdpPeerSession>(
            udp_socket, from, UdpPeerSession::Role::Acceptor, selfId, identity,
            [this](const std::string& pid) { return getSelfNameForPeer(pid); },
            [this] { return getSelfAvatarPng(); },
            [this](const std::string& x) { return isRoutablePeer(x); },
            stream_cipher_pref,
            std::string{},
            [this](const std::string& s) {
              if (!debug_logs_enabled()) return;
              postToQt([this, s] { emit q->logLine("[dbg] " + QString::fromStdString(s)); });
            });
        udp_sessions[pid] = session;
        udp_ep_to_peer[epkey] = pid;

        std::weak_ptr<UdpPeerSession> weak = session;
        session->start_accept_with_first(
            j, from,
            [this](const std::string& peer_id, const std::string& peer_name) {
              {
                std::lock_guard lk(m);
                if (!peer_name.empty()) peer_names[peer_id] = peer_name;
              }
              postToQt([this, peer_id] {
                emit q->logLine("peer connected (udp): " + QString::fromStdString(peer_id));
              });
              flushOutgoing(peer_id);
              flushControl(peer_id);
              postToQt([this, pid = QString::fromStdString(peer_id)] { onPeerReadyQt(pid); });
            },
            [this](const std::string& peer_id, const std::string& peer_name) {
              if (peer_name.empty()) return;
              {
                std::lock_guard lk(m);
                peer_names[peer_id] = peer_name;
              }
              postToQt([this, peer_id, peer_name] {
                emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
              });
            },
            [this](const std::string& peer_id, const std::vector<uint8_t>& bytes) {
              const QByteArray png(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
              postToQt([this, peer_id, png] {
                emit q->peerAvatarUpdated(QString::fromStdString(peer_id), png);
              });
            },
            [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
              std::string label = peer_name.empty() ? peer_id : peer_name;
              postToQt([this, peer_id, label, text] {
                emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                        QString::fromStdString(text), true);
              });
            },
            [this](const std::string& peer_id, json inner) {
              postToQt([this, pid = QString::fromStdString(peer_id), inner = std::move(inner)]() mutable {
                handleControlQt(pid, std::move(inner));
              });
            },
            [this](const std::string& peer_id, uint64_t seq, uint32_t, const std::vector<uint8_t>& opus) {
              const QByteArray bytes(reinterpret_cast<const char*>(opus.data()), static_cast<int>(opus.size()));
              postToQt([this, pid = QString::fromStdString(peer_id), seq, bytes]() mutable {
                handleVoiceFrameQt(pid, seq, bytes);
              });
            },
            [this](const std::string& peer_id, uint32_t, bool, uint32_t, const std::vector<uint8_t>& encoded) {
              const QByteArray bytes(reinterpret_cast<const char*>(encoded.data()), static_cast<int>(encoded.size()));
              postToQt([this, pid = QString::fromStdString(peer_id), bytes]() mutable {
                handleVideoFrameQt(pid, bytes);
              });
            },
            [this, pid, epkey, weak]() {
              auto s = weak.lock();
              if (!s) return;
              auto it = udp_sessions.find(pid);
              if (it != udp_sessions.end() && it->second == s) udp_sessions.erase(it);
              if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == pid) {
                udp_ep_to_peer.erase(mit);
              }
              postToQt([this, pid] { emit q->directPeerConnectionChanged(QString::fromStdString(pid), false); });
            });
        return;
      }
    }
  }

  void send_udp_to(const udp::endpoint& to, const json& j) {
    auto framed = common::frame_json_bytes(j);
    if (!framed) return;
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(*framed));
    udp_socket.async_send_to(boost::asio::buffer(*buf), to,
                             [buf](const boost::system::error_code&, std::size_t) {});
  }

  void resolve_udp_server(std::function<void()> on_ready = {}) {
    if (udp_resolving) return;
    udp_server_ready = false;
    if (server_host.empty() || server_port == 0) return;
    udp_resolving = true;
    udp_resolver.async_resolve(
        server_host,
        std::to_string(server_port),
        [this, on_ready = std::move(on_ready)](const boost::system::error_code& ec, udp::resolver::results_type res) {
          udp_resolving = false;
          if (ec) {
            postToQt([this, msg = QString("udp rendezvous resolve failed: %1").arg(QString::fromUtf8(ec.message()))] {
              emit q->logLine(msg);
            });
            return;
          }

          std::optional<udp::endpoint> chosen;
          for (const auto& r : res) {
            const auto ep = r.endpoint();
            if (ep.address().is_v4()) {
              chosen = ep;
              break;
            }
          }
          if (!chosen) {
            // We only open a v4 UDP socket, so an IPv6-only rendezvous host won't work for UDP punching.
            postToQt([this] { emit q->logLine("udp rendezvous resolved to IPv6 only; UDP socket is IPv4"); });
            return;
          }

          udp_server_ep = *chosen;
          udp_server_ready = true;
          postToQt([this, ep = QString::fromStdString(common::endpoint_to_string(udp_server_ep))] {
            emit q->logLine(QString("udp rendezvous endpoint: %1").arg(ep));
          });
          if (on_ready) on_ready();
        });
  }

  void schedule_udp_announce(bool immediate) {
    if (!identity) return;
    const auto delay = immediate ? std::chrono::seconds(0) : std::chrono::seconds(20);
    udp_announce_timer.expires_after(delay);
    udp_announce_timer.async_wait([this](const boost::system::error_code& ec) {
      if (ec) return;
      if (!udp_server_ready) {
        resolve_udp_server([this] { send_udp_announce_once(); });
      } else {
        send_udp_announce_once();
      }
      schedule_udp_announce(false);
    });
  }

  void send_udp_announce_once() {
    if (!udp_server_ready || !identity) return;
    const std::string id = std::string(identity->public_id());
    const auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
    const std::string msg = "p2p-chat-udp-announce|" + id + "|" + std::to_string(ts);
    const std::string sig = identity->sign_bytes_b64url(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size()));
    if (sig.empty()) return;
    json a;
    a["type"] = "udp_announce";
    a["id"] = id;
    a["ts"] = ts;
    a["sig"] = sig;
    send_udp_to(udp_server_ep, a);
  }

  void acceptLoop() {
    acceptor.async_accept([this](const boost::system::error_code& ec, tcp::socket socket) {
      if (ec) return;
      handleIncomingSocket(std::move(socket));
      acceptLoop();
    });
  }

  void handleIncomingSocket(tcp::socket socket) {
    auto sock = std::make_shared<tcp::socket>(std::move(socket));
    common::async_read_json(*sock, common::kMaxFrameSize, [this, sock](const boost::system::error_code& ec, json j) {
      if (ec) return;
      if (!j.contains("type") || !j["type"].is_string()) return;
      const std::string type = j["type"].get<std::string>();

      if (type == "probe") {
        if (!j.contains("challenge") || !j["challenge"].is_string()) return;
        const std::string challenge = j["challenge"].get<std::string>();
        json resp;
        resp["type"] = "probe_ok";
        resp["id"] = std::string(identity->public_id());
        resp["signature"] = identity->sign_challenge_b64url(challenge);
        common::async_write_json(*sock, resp, [sock](const boost::system::error_code&) {
          boost::system::error_code ignored;
          sock->shutdown(tcp::socket::shutdown_both, ignored);
          sock->close(ignored);
        });
        return;
      }

      if (type == "hello") {
        auto writer = std::make_shared<common::JsonWriteQueue<tcp::socket>>(*sock);
        json e;
        e["type"] = "error";
        e["message"] = "legacy protocol not supported; upgrade required";
        writer->send(std::move(e));
        boost::system::error_code ignored;
        sock->shutdown(tcp::socket::shutdown_both, ignored);
        sock->close(ignored);
        return;
      }

      if (type == "secure_hello") {
        startPeerAcceptWithFirst(std::move(*sock), std::move(j));
        return;
      }
    });
  }

  void startPeerAcceptWithFirst(tcp::socket socket, json first) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    auto session = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Acceptor, std::move(selfId), identity,
        [this](const std::string& pid) { return getSelfNameForPeer(pid); },
        [this] { return getSelfAvatarPng(); },
        [this](const std::string& pid) { return isRoutablePeer(pid); },
        stream_cipher_pref);
    std::weak_ptr<PeerSession> weak = session;
    session->start_accept_with_first(
        std::move(first),
        [this, weak](const std::string& peer_id, const std::string& peer_name) {
          if (auto s = weak.lock()) tcp_sessions[peer_id] = std::move(s);
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
          flushControl(peer_id);
          postToQt([this, pid = QString::fromStdString(peer_id)] { onPeerReadyQt(pid); });
        },
        [this](const std::string& peer_id, const std::string& peer_name) {
          if (peer_name.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id, peer_name] {
            emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
          });
        },
        [this](const std::string& peer_id, const std::vector<uint8_t>& bytes) {
          const QByteArray png(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
          postToQt([this, peer_id, png] {
            emit q->peerAvatarUpdated(QString::fromStdString(peer_id), png);
          });
        },
        [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
          std::string label = peer_name.empty() ? peer_id : peer_name;
          postToQt([this, peer_id, label, text] {
            emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this](const std::string& peer_id, json inner) {
          postToQt([this, pid = QString::fromStdString(peer_id), inner = std::move(inner)]() mutable {
            handleControlQt(pid, std::move(inner));
          });
        },
        [this, weak]() {
          auto s = weak.lock();
          if (!s) return;
          const std::string pid = std::string(s->peer_id());
          if (pid.empty()) return;
          auto it = tcp_sessions.find(pid);
          if (it != tcp_sessions.end() && it->second == s) tcp_sessions.erase(it);
          postToQt([this, pid] { emit q->directPeerConnectionChanged(QString::fromStdString(pid), false); });
        });
  }

  void connectToPeer(const std::string& peer_id, const std::string& ip, uint16_t port, bool silent) {
    if (tcp_sessions.find(peer_id) != tcp_sessions.end()) return;
    auto sock = std::make_shared<tcp::socket>(io);
    auto timer = std::make_shared<boost::asio::steady_timer>(io);
    timer->expires_after(kConnectTimeout);
    timer->async_wait([sock](const boost::system::error_code& ec) {
      if (ec) return;
      boost::system::error_code ignored;
      sock->close(ignored);
    });

    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(ip, ec);
    if (ec) return;
    tcp::endpoint ep(addr, port);

    sock->async_connect(ep, [this, sock, timer, peer_id, silent](const boost::system::error_code& ec2) {
      timer->cancel();
      if (ec2) {
        if (!silent) {
          postToQt([this, peer_id] {
            emit q->deliveryError(QString::fromStdString(peer_id), "connect failed");
          });
        }
        return;
      }
      startPeerInitiator(std::move(*sock), peer_id);
    });
  }

  void connectToPeerUdp(const std::string& peer_id,
                        const std::string& udp_ip,
                        uint16_t udp_port,
                        bool silent) {
    boost::system::error_code ec;
    const auto addr = boost::asio::ip::make_address(udp_ip, ec);
    if (ec) return;
    udp::endpoint ep(addr, udp_port);

    if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second) {
      auto old_session = it->second;
      if (old_session->peer_endpoint() == ep) return;
      old_session->close();
      if (auto cur = udp_sessions.find(peer_id); cur != udp_sessions.end() && cur->second == old_session) {
        udp_sessions.erase(cur);
      }
    }

    const std::string selfId = std::string(identity->public_id());
    const auto role = (selfId < peer_id) ? UdpPeerSession::Role::Initiator : UdpPeerSession::Role::Acceptor;

    auto udp_ready = std::make_shared<std::atomic<bool>>(false);
    auto session = std::make_shared<UdpPeerSession>(
        udp_socket,
        ep,
        role,
        selfId,
        identity,
        [this](const std::string& pid) { return getSelfNameForPeer(pid); },
        [this] { return getSelfAvatarPng(); },
        [this](const std::string& pid) { return isRoutablePeer(pid); },
        stream_cipher_pref,
        peer_id,
        [this](const std::string& s) {
          if (!debug_logs_enabled()) return;
          postToQt([this, s] { emit q->logLine("[dbg] " + QString::fromStdString(s)); });
        });

    udp_sessions[peer_id] = session;
    udp_ep_to_peer[common::endpoint_to_string(ep)] = peer_id;

    const std::string epkey = common::endpoint_to_string(ep);
    std::weak_ptr<UdpPeerSession> weak = session;
    session->start(
        [this, udp_ready](const std::string& pid, const std::string& pname) {
          udp_ready->store(true);
          {
            std::lock_guard lk(m);
            if (!pname.empty()) peer_names[pid] = pname;
          }
          postToQt([this, pid] { emit q->logLine("peer connected (udp): " + QString::fromStdString(pid)); });
          flushOutgoing(pid);
          flushControl(pid);
          postToQt([this, qpid = QString::fromStdString(pid)] { onPeerReadyQt(qpid); });
        },
        [this](const std::string& pid, const std::string& pname) {
          if (pname.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[pid] = pname;
          }
          postToQt([this, pid, pname] {
            emit q->peerNameUpdated(QString::fromStdString(pid), QString::fromStdString(pname));
          });
        },
        [this](const std::string& pid, const std::vector<uint8_t>& bytes) {
          const QByteArray png(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
          postToQt([this, pid, png] { emit q->peerAvatarUpdated(QString::fromStdString(pid), png); });
        },
        [this](const std::string& pid, const std::string& pname, const std::string& text) {
          std::string label = pname.empty() ? pid : pname;
          postToQt([this, pid, label, text] {
            emit q->messageReceived(QString::fromStdString(pid), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this](const std::string& pid, json inner) {
          postToQt([this, qpid = QString::fromStdString(pid), inner = std::move(inner)]() mutable {
            handleControlQt(qpid, std::move(inner));
          });
        },
        [this](const std::string& pid, uint64_t seq, uint32_t, const std::vector<uint8_t>& opus) {
          const QByteArray bytes(reinterpret_cast<const char*>(opus.data()), static_cast<int>(opus.size()));
          postToQt([this, qpid = QString::fromStdString(pid), seq, bytes]() mutable {
            handleVoiceFrameQt(qpid, seq, bytes);
          });
        },
        [this](const std::string& pid, uint32_t, bool, uint32_t, const std::vector<uint8_t>& encoded) {
          const QByteArray bytes(reinterpret_cast<const char*>(encoded.data()), static_cast<int>(encoded.size()));
          postToQt([this, qpid = QString::fromStdString(pid), bytes]() mutable {
            handleVideoFrameQt(qpid, bytes);
          });
        },
        [this, weak, udp_ready, peer_id, epkey, silent, role]() {
          const bool ok = udp_ready->load();
          auto s = weak.lock();
          if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second == s) udp_sessions.erase(it);
          if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == peer_id) {
            udp_ep_to_peer.erase(mit);
          }
          postToQt([this, peer_id] { emit q->directPeerConnectionChanged(QString::fromStdString(peer_id), false); });
          if (!ok && role == UdpPeerSession::Role::Initiator) udp_failed_fallback(peer_id, silent);
        });

    // Flush queued messages into the session (session will send once ready).
    flushOutgoing(peer_id);
  }

  void udp_failed_fallback(const std::string& peer_id, bool silent) {
    if (!silent) {
      postToQt([this, peer_id] {
        emit q->deliveryError(QString::fromStdString(peer_id), "delivery failed (udp session unavailable)");
      });
    }
  }

  void startPeerInitiator(tcp::socket socket, std::string expected_peer_id) {
    if (!rendezvous || rendezvous->id().empty()) return;
    auto selfId = std::string(rendezvous->id());
    const std::string peer_key = expected_peer_id;
    auto session = std::make_shared<PeerSession>(
        std::move(socket), PeerSession::Role::Initiator, std::move(selfId), identity,
        [this](const std::string& pid) { return getSelfNameForPeer(pid); },
        [this] { return getSelfAvatarPng(); },
        [this](const std::string& pid) { return isRoutablePeer(pid); },
        stream_cipher_pref,
        std::move(expected_peer_id));

    // Store by expected peer id so we don't attempt another connect while handshaking.
    tcp_sessions[peer_key] = session;
    std::weak_ptr<PeerSession> weak = session;
    session->start(
        [this, weak](const std::string& peer_id, const std::string& peer_name) {
          if (auto s = weak.lock()) tcp_sessions[peer_id] = std::move(s);
          {
            std::lock_guard lk(m);
            if (!peer_name.empty()) peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id] { emit q->logLine("peer connected: " + QString::fromStdString(peer_id)); });
          flushOutgoing(peer_id);
          flushControl(peer_id);
          postToQt([this, pid = QString::fromStdString(peer_id)] { onPeerReadyQt(pid); });
        },
        [this](const std::string& peer_id, const std::string& peer_name) {
          if (peer_name.empty()) return;
          {
            std::lock_guard lk(m);
            peer_names[peer_id] = peer_name;
          }
          postToQt([this, peer_id, peer_name] {
            emit q->peerNameUpdated(QString::fromStdString(peer_id), QString::fromStdString(peer_name));
          });
        },
        [this](const std::string& peer_id, const std::vector<uint8_t>& bytes) {
          const QByteArray png(reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()));
          postToQt([this, peer_id, png] {
            emit q->peerAvatarUpdated(QString::fromStdString(peer_id), png);
          });
        },
        [this](const std::string& peer_id, const std::string& peer_name, const std::string& text) {
          std::string label = peer_name.empty() ? peer_id : peer_name;
          postToQt([this, peer_id, label, text] {
            emit q->messageReceived(QString::fromStdString(peer_id), QString::fromStdString(label),
                                    QString::fromStdString(text), true);
          });
        },
        [this](const std::string& peer_id, json inner) {
          postToQt([this, pid = QString::fromStdString(peer_id), inner = std::move(inner)]() mutable {
            handleControlQt(pid, std::move(inner));
          });
        },
        [this, weak, peer_key]() {
          auto s = weak.lock();
          if (!s) return;
          const std::string pid = std::string(s->peer_id());
          auto it = tcp_sessions.find(peer_key);
          if (it != tcp_sessions.end() && it->second == s) tcp_sessions.erase(it);
          if (!pid.empty()) {
            postToQt([this, pid] { emit q->directPeerConnectionChanged(QString::fromStdString(pid), false); });
          }
        });
  }

  void attemptDelivery(const std::string& peer_id, bool silent) {
    if (!rendezvous) return;
    if (!isRoutablePeer(peer_id)) return;
    const auto now = std::chrono::steady_clock::now();
    if (auto it = last_connect_attempt.find(peer_id); it != last_connect_attempt.end()) {
      if (now - it->second < std::chrono::seconds(3)) return;
    }
    last_connect_attempt[peer_id] = now;

    rendezvous->send_lookup(peer_id, [this, silent](RendezvousClient::LookupResult r) {
      if (!r.ok) {
        postToQt([this, tid = r.target_id] { emit q->presenceUpdated(QString::fromStdString(tid), false); });
        if (!silent) {
          postToQt([this, tid = r.target_id] {
            emit q->deliveryError(QString::fromStdString(tid), "lookup failed (offline?)");
          });
        }
        return;
      }
      last_lookup[r.target_id] = r;
      postToQt([this, tid = r.target_id] { emit q->presenceUpdated(QString::fromStdString(tid), true); });
      if (r.udp_port != 0) {
        // UDP hole punching is the default (works even if both peers are NATed).
        const std::string udp_ip = r.udp_ip.empty() ? r.ip : r.udp_ip;
        connectToPeerUdp(r.target_id, udp_ip, r.udp_port, silent);
        return;
      }
      udp_failed_fallback(r.target_id, silent);
    });
  }

  void closePeerSessions(const std::string& peer_id) {
    if (auto it = udp_sessions.find(peer_id); it != udp_sessions.end() && it->second) {
      auto session = it->second;
      const auto epkey = common::endpoint_to_string(session->peer_endpoint());
      session->close();
      if (auto cur = udp_sessions.find(peer_id); cur != udp_sessions.end() && cur->second == session) {
        udp_sessions.erase(cur);
      }
      if (auto mit = udp_ep_to_peer.find(epkey); mit != udp_ep_to_peer.end() && mit->second == peer_id) {
        udp_ep_to_peer.erase(mit);
      }
    }
    if (auto it = tcp_sessions.find(peer_id); it != tcp_sessions.end() && it->second) {
      auto session = it->second;
      session->close();
      if (auto cur = tcp_sessions.find(peer_id); cur != tcp_sessions.end() && cur->second == session) {
        tcp_sessions.erase(cur);
      }
    }
    postToQt([this, peer_id] { emit q->directPeerConnectionChanged(QString::fromStdString(peer_id), false); });
  }

  void scheduleFriendConnect(bool immediate) {
    if (immediate) {
      if (friend_connect_running) return;
      friend_connect_running = true;
    }
    const auto delay = immediate ? std::chrono::seconds(0) : std::chrono::seconds(10);
    friend_connect_timer.expires_after(delay);
    friend_connect_timer.async_wait([this](const boost::system::error_code& ec) {
      if (ec) return;
      std::vector<std::string> peers;
      {
        std::lock_guard lk(m);
        peers.assign(accepted_friends.begin(), accepted_friends.end());
        for (const auto& id : server_members) {
          if (accepted_friends.find(id) != accepted_friends.end()) continue;
          peers.push_back(id);
        }
      }
      for (const auto& pid : peers) attemptDelivery(pid, /*silent*/ true);
      scheduleFriendConnect(false);
    });
  }
};

ChatBackend::ChatBackend(QObject* parent) : QObject(parent), impl_(new Impl()) {
  impl_->q = this;
}

ChatBackend::~ChatBackend() {
  stop();
  delete impl_;
}

void ChatBackend::start(const Options& opt) {
  stop();

  const QString keyPath = opt.keyPath.isEmpty() ? Profile::defaultKeyPath() : opt.keyPath;
  common::log("identity key: " + keyPath.toStdString());
  emit logLine(QString("identity key: %1").arg(keyPath));
  if (debug_logs_enabled()) {
    emit logLine("[dbg] runtime debug logging enabled");
  }
  try {
    impl_->identity =
        common::Identity::load_or_create(keyPath.toStdString(), opt.keyPassword.toStdString());
  } catch (const std::exception& e) {
    const QString msg = QString("identity load failed: %1").arg(e.what());
    common::log(msg.toStdString());
    emit logLine(msg);
    return;
  }
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = opt.selfName.toStdString();
  }
  impl_->stream_cipher_pref = kStreamCipher;

  // Bind acceptor.
  const uint16_t listenPort = opt.listenPort ? static_cast<uint16_t>(opt.listenPort)
                                             : common::choose_default_listen_port();
  impl_->listen_port = listenPort;
  impl_->bindAcceptor(listenPort);
  impl_->acceptLoop();
  impl_->bindUdp(listenPort);

  // UDP hole-punching mode only.

  RendezvousClient::Config cfg;
  cfg.server_host = opt.serverHost.toStdString();
  cfg.server_port = opt.serverPort;
  cfg.id = std::string(impl_->identity->public_id());
  cfg.sign_challenge = [id = impl_->identity](std::string_view c) { return id->sign_challenge_b64url(c); };

  impl_->server_host = cfg.server_host;
  impl_->server_port = cfg.server_port;
  impl_->schedule_udp_announce(/*immediate*/ true);

  impl_->rendezvous = std::make_shared<RendezvousClient>(impl_->io, std::move(cfg));
  impl_->rendezvous->start(
      [impl = impl_]() {
        const auto selfId = QString::fromStdString(std::string(impl->rendezvous->id()));
        const auto observedIp = QString::fromStdString(std::string(impl->rendezvous->observed_ip()));
        const auto udpPort = static_cast<quint16>(impl->rendezvous->udp_port());
        impl->postToQt([impl, selfId, observedIp, udpPort] {
          emit impl->q->registered(selfId, observedIp, udpPort);
        });
        impl->rendezvous->enable_polling(true);
        impl->scheduleFriendConnect(/*immediate*/ true);
      },
      [impl = impl_](const std::string& from_id) {
        const auto fromId = QString::fromStdString(from_id);
        impl->postToQt([impl, fromId] { emit impl->q->friendRequestReceived(fromId); });
      },
      [impl = impl_](const std::string& from_id) {
        const auto fromId = QString::fromStdString(from_id);
        impl->postToQt([impl, fromId] { emit impl->q->friendAccepted(fromId); });
      });

  impl_->work.emplace(boost::asio::make_work_guard(impl_->io));
  impl_->io_thread = std::thread([this] { impl_->io.run(); });
}

void ChatBackend::stop() {
  if (!impl_->work) return;
  impl_->work.reset();
  if (impl_->rendezvous) impl_->rendezvous->stop();
  boost::system::error_code ignored;
  impl_->acceptor.close(ignored);
  impl_->friend_connect_timer.cancel();
  impl_->udp_announce_timer.cancel();
  impl_->udp_socket.close(ignored);
  impl_->io.stop();
  if (impl_->io_thread.joinable()) impl_->io_thread.join();
  impl_->io.restart();
  impl_->rendezvous.reset();
  impl_->tcp_sessions.clear();
  impl_->udp_sessions.clear();
  impl_->udp_ep_to_peer.clear();
  impl_->last_lookup.clear();
  impl_->last_connect_attempt.clear();
  impl_->friend_connect_running = false;
}

void ChatBackend::setSelfName(const QString& name) {
  const auto nm = name.toStdString();
  {
    std::lock_guard lk(impl_->m);
    impl_->self_name = nm;
  }

  // Push updated name immediately to any active session (P2P).
  boost::asio::post(impl_->io, [impl = impl_, nm] {
    for (auto& [pid, s] : impl->tcp_sessions) {
      if (s && impl->isAccepted(pid)) s->send_name(nm);
    }
    for (auto& [pid, s] : impl->udp_sessions) {
      if (s && impl->isAccepted(pid)) s->send_name(nm);
    }
  });
}

void ChatBackend::setSelfAvatarPng(const QByteArray& pngBytes) {
  std::vector<uint8_t> bytes;
  if (pngBytes.size() > 0) bytes.resize(static_cast<std::size_t>(pngBytes.size()));
  if (!bytes.empty()) {
    std::memcpy(bytes.data(), pngBytes.constData(), bytes.size());
  }
  // Cap to keep UDP frames safe.
  if (bytes.size() > 48 * 1024) bytes.clear();

  {
    std::lock_guard lk(impl_->m);
    impl_->self_avatar_png = bytes;
  }

  boost::asio::post(impl_->io, [impl = impl_, bytes = std::move(bytes)]() mutable {
    for (auto& [_, s] : impl->tcp_sessions) {
      if (s) s->send_avatar(bytes);
    }
    for (auto& [_, s] : impl->udp_sessions) {
      if (s) s->send_avatar(bytes);
    }
  });
}

void ChatBackend::setFriendAccepted(const QString& peerId, bool accepted) {
  const auto pid = peerId.toStdString();
  impl_->setAccepted(pid, accepted);
  boost::asio::post(impl_->io, [impl = impl_, pid, accepted] {
    if (!accepted) {
      impl->closePeerSessions(pid);
      return;
    }
    impl->refreshIdentityForPeer(pid);
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::setServerMembers(const QStringList& peerIds) {
  std::unordered_set<std::string> peers;
  peers.reserve(static_cast<std::size_t>(peerIds.size()));
  for (const auto& id : peerIds) {
    if (id.isEmpty()) continue;
    peers.insert(id.toStdString());
  }
  impl_->setServerMembers(peers);
  boost::asio::post(impl_->io, [impl = impl_] {
    impl->scheduleFriendConnect(/*immediate*/ true);
  });
}

void ChatBackend::setPeerMuted(const QString& peerId, bool muted) {
  const auto pid = peerId.toStdString();
  std::lock_guard lk(impl_->m);
  if (muted) {
    impl_->muted_voice_peers.insert(pid);
  } else {
    impl_->muted_voice_peers.erase(pid);
  }
}

void ChatBackend::setPeerVideoWatch(const QString& peerId, bool watching) {
  if (peerId.isEmpty()) return;
  const auto pid = peerId.toStdString();
  const auto callPeer = impl_->callPeerId;
  const auto callId = (callPeer == peerId) ? impl_->callId.toStdString() : std::string();

#if defined(P2PCHAT_VIDEO)
  if (watching && callPeer == peerId) {
    impl_->requestVideoKeyframeQt(peerId);
  }
#endif

  boost::asio::post(impl_->io, [impl = impl_, pid, callId, watching] {
    json j;
    j["type"] = "video_watch";
    if (!callId.empty()) j["call_id"] = callId;
    j["watching"] = watching;
    impl->sendControlToPeer(pid, std::move(j));
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::setLocalVideoPreviewEnabled(bool enabled) {
  if (!impl_) return;
  const bool prev = impl_->localVideoPreviewEnabled.exchange(enabled, std::memory_order_relaxed);
  if (prev == enabled) return;
  if (!enabled && impl_->q) {
    emit impl_->q->localVideoFrame(QImage());
  }
}

void ChatBackend::setVoiceChannelPeers(const QStringList& peerIds, const VoiceSettings& settings) {
#if !defined(P2PCHAT_VOICE)
  (void)peerIds;
  (void)settings;
  return;
#else
  QSet<QString> peers;
  for (const auto& id : peerIds) {
    const auto trimmed = id.trimmed();
    if (!trimmed.isEmpty()) peers.insert(trimmed);
  }

  impl_->voiceChannelSettings = settings;
  impl_->voiceChannelPeers = peers;
  impl_->voiceChannelActive = !peers.isEmpty();

  boost::asio::post(impl_->io, [impl = impl_, peers] {
    for (const auto& peerId : peers) {
      const auto pid = peerId.toStdString();
      if (!impl->isRoutablePeer(pid)) continue;
      impl->attemptDelivery(pid, /*silent*/ true);
    }
  });

  impl_->startVoiceChannelQt();

#if defined(P2PCHAT_VIDEO)
  const bool enabled = settings.videoEnabled && !settings.videoDevicePath.trimmed().isEmpty();
  const std::string codec = resolve_network_video_codec(settings).toStdString();
  boost::asio::post(impl_->io, [impl = impl_, peers, enabled, codec] {
    for (const auto& peerId : peers) {
      const auto pid = peerId.toStdString();
      json j;
      j["type"] = "video_state";
      j["call_id"] = "__voice_channel__";
      j["enabled"] = enabled;
      j["video_codec"] = codec;
      impl->sendControlToPeer(pid, std::move(j));
      impl->attemptDelivery(pid, /*silent*/ true);
    }
  });
#endif
#endif
}

void ChatBackend::stopVoiceChannel() {
#if !defined(P2PCHAT_VOICE)
  return;
#else
  impl_->voiceChannelActive = false;
  impl_->voiceChannelPeers.clear();
  if (impl_->voice && impl_->voice->channelMode) {
    impl_->stopVoiceQt();
  }
#endif
}

void ChatBackend::sendFriendRequest(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    impl->rendezvous->send_friend_request(pid);
  });
}

void ChatBackend::acceptFriend(const QString& peerId) {
  const auto pid = peerId.toStdString();
  impl_->setAccepted(pid, true);
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    impl->rendezvous->send_friend_accept(pid);
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::sendSignedControl(const QString& peerId, const QString& kind, const QString& payloadJsonCompact) {
  const auto pid = peerId.toStdString();
  const auto k = kind.toStdString();
  const auto payload = payloadJsonCompact.toStdString();
  const bool isServerKind = (k.rfind("server_", 0) == 0);
  const bool permitted = impl_->isAccepted(pid) || (isServerKind && impl_->isServerMember(pid));
  if (!permitted) {
    emit deliveryError(peerId, "not authorized");
    return;
  }
  boost::asio::post(impl_->io, [impl = impl_, pid, k, payload] {
    if (!impl->identity) return;
    json payloadObj;
    try {
      payloadObj = json::parse(payload);
    } catch (...) {
      return;
    }
    if (!payloadObj.is_object()) return;
    const auto payloadDump = payloadObj.dump();
    const auto sig = impl->identity->sign_bytes_b64url(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(payloadDump.data()), payloadDump.size()));
    if (sig.empty()) return;

    json inner;
    inner["type"] = "signed_control";
    inner["kind"] = k;
    inner["from"] = std::string(impl->identity->public_id());
    inner["payload"] = std::move(payloadObj);
    inner["sig"] = sig;
    impl->sendControlToPeer(pid, std::move(inner));
  });
}

void ChatBackend::sendUnsignedControl(const QString& peerId, const QString& kind, const QString& payloadJsonCompact) {
  const auto pid = peerId.toStdString();
  const auto k = kind.toStdString();
  const auto payload = payloadJsonCompact.toStdString();
  const bool isServerKind = (k.rfind("server_", 0) == 0);
  const bool permitted = impl_->isAccepted(pid) || (isServerKind && impl_->isServerMember(pid));
  if (!permitted) {
    emit deliveryError(peerId, "not authorized");
    return;
  }
  boost::asio::post(impl_->io, [impl = impl_, pid, k, payload] {
    if (!impl->identity) return;
    json payloadObj;
    try {
      payloadObj = json::parse(payload);
    } catch (...) {
      return;
    }
    if (!payloadObj.is_object()) return;

    json inner;
    inner["type"] = "unsigned_control";
    inner["kind"] = k;
    inner["from"] = std::string(impl->identity->public_id());
    inner["payload"] = std::move(payloadObj);
    impl->sendControlToPeer(pid, std::move(inner));
  });
}

void ChatBackend::sendMessage(const QString& peerId, const QString& text) {
  const auto pid = peerId.toStdString();
  if (!impl_->isAccepted(pid)) {
    emit deliveryError(peerId, "not friends");
    return;
  }
  impl_->queueOutgoing(pid, text.toStdString());
  emit messageReceived(peerId, peerId, text, false);

  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    if (impl->udp_sessions.find(pid) != impl->udp_sessions.end()) {
      impl->flushOutgoing(pid);
      return;
    }
    impl->attemptDelivery(pid, /*silent*/ false);
  });
}

void ChatBackend::disconnectPeer(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    impl->closePeerSessions(pid);
  });
}

void ChatBackend::warmConnect(const QString& peerId) {
  const auto pid = peerId.toStdString();
  boost::asio::post(impl_->io, [impl = impl_, pid] {
    if (!impl->rendezvous) return;
    if (!impl->isAccepted(pid)) return;
    impl->attemptDelivery(pid, /*silent*/ true);
  });
}

void ChatBackend::startCall(const QString& peerId, const VoiceSettings& settings) {
#if !defined(P2PCHAT_VOICE)
  emit deliveryError(peerId, "voice unavailable (built without QtMultimedia/Opus)");
  emit callEnded(peerId, "voice unavailable");
  (void)settings;
  return;
#else
  if (running_as_root()) {
    emit deliveryError(peerId, "voice unavailable when running as root");
    emit callEnded(peerId, "voice unavailable (running as root)");
    (void)settings;
    return;
  }
#if !defined(_WIN32)
  if (!pipewireSpaSupportPresent()) {
    emit deliveryError(peerId, "voice unavailable (missing PipeWire SPA support)");
    emit callEnded(peerId, "voice unavailable (missing PipeWire SPA support)");
    (void)settings;
    return;
  }
#endif
  const auto pid = peerId.toStdString();
  if (!impl_->isAccepted(pid)) {
    emit deliveryError(peerId, "not friends");
    emit callEnded(peerId, "not friends");
    return;
  }
  if (!impl_->callPeerId.isEmpty()) {
    emit callEnded(peerId, "busy");
    return;
  }

  impl_->callPeerId = peerId;
  impl_->callId = QString::fromStdString(common::generate_id(24));
  impl_->callOutgoing = true;
  impl_->callLocalAccepted = true;
  impl_->callRemoteAccepted = false;
  impl_->callRemoteVideoEnabled = false;
  impl_->callRemoteWatchingVideo = true;
  impl_->callVideoCodec = resolve_network_video_codec(settings);
  impl_->callRemoteVideoCodec = "h264";
  impl_->callSettings = settings;
  impl_->callFrameMs = (settings.frameMs == 10) ? 10 : 20;
  impl_->callChannels = (settings.channels == 2) ? 2 : 1;
  impl_->callBitrate = std::clamp(settings.bitrate, 8000, 128000);

  emit callStateChanged(peerId, "calling");
  if (debug_logs_enabled()) {
    emit logLine("[dbg] call start outgoing peer=" + peerId + " call_id=" + impl_->callId +
                 " frameMs=" + QString::number(impl_->callFrameMs) +
                 " channels=" + QString::number(impl_->callChannels) +
                 " bitrate=" + QString::number(impl_->callBitrate));
  }

  const auto call_id = impl_->callId.toStdString();
  const int frameMs = impl_->callFrameMs;
  const int channels = impl_->callChannels;
  const int bitrate = impl_->callBitrate;
  const bool videoEnabled = impl_->callSettings.videoEnabled;
  const std::string videoCodec = impl_->callVideoCodec.toStdString();
  const int videoWidth = std::max(16, impl_->callSettings.videoWidth);
  const int videoHeight = std::max(16, impl_->callSettings.videoHeight);
  const int videoFpsNum = std::max(1, impl_->callSettings.videoFpsNum);
  const int videoFpsDen = std::max(1, impl_->callSettings.videoFpsDen);
  const int videoBitrateKbps = std::clamp(impl_->callSettings.videoBitrateKbps, 100, 20000);
  boost::asio::post(impl_->io, [impl = impl_,
                                pid,
                                call_id,
                                frameMs,
                                channels,
                                bitrate,
                                videoEnabled,
                                videoCodec,
                                videoWidth,
                                videoHeight,
                                videoFpsNum,
                                videoFpsDen,
                                videoBitrateKbps] {
    json offer;
    offer["type"] = "call_offer";
    offer["call_id"] = call_id;
    offer["sr"] = 48000;
    offer["ch"] = channels;
    offer["frame_ms"] = frameMs;
    offer["bitrate"] = bitrate;
    offer["video_enabled"] = videoEnabled;
    offer["video_codec"] = videoCodec;
    offer["video_width"] = videoWidth;
    offer["video_height"] = videoHeight;
    offer["video_fps_num"] = videoFpsNum;
    offer["video_fps_den"] = videoFpsDen;
    offer["video_bitrate_kbps"] = videoBitrateKbps;
    impl->sendControlToPeer(pid, std::move(offer));
    impl->attemptDelivery(pid, /*silent*/ false);
  });
#endif
}

void ChatBackend::answerCall(const QString& peerId, bool accept, const VoiceSettings& settings) {
  if (impl_->callPeerId != peerId) return;
  if (impl_->callId.isEmpty()) return;

  const auto pid = peerId.toStdString();
  const auto call_id = impl_->callId.toStdString();

  if (!accept) {
    boost::asio::post(impl_->io, [impl = impl_, pid, call_id] {
      json ans;
      ans["type"] = "call_answer";
      ans["call_id"] = call_id;
      ans["accept"] = false;
      ans["reason"] = "declined";
      impl->sendControlToPeer(pid, std::move(ans));
    });
    impl_->endCallQt("declined", /*notifyPeer*/ false);
    return;
  }

#if !defined(P2PCHAT_VOICE)
  emit deliveryError(peerId, "voice unavailable (built without QtMultimedia/Opus)");
  impl_->endCallQt("voice unavailable", /*notifyPeer*/ false);
  (void)settings;
  return;
#else
  if (running_as_root()) {
    emit deliveryError(peerId, "voice unavailable when running as root");
    impl_->endCallQt("voice unavailable (running as root)", /*notifyPeer*/ false);
    (void)settings;
    return;
  }
#if !defined(_WIN32)
  if (!pipewireSpaSupportPresent()) {
    emit deliveryError(peerId, "voice unavailable (missing PipeWire SPA support)");
    impl_->endCallQt("voice unavailable (missing PipeWire SPA support)", /*notifyPeer*/ false);
    (void)settings;
    return;
  }
#endif
  impl_->callSettings = settings;
  // Keep the frame size negotiated by the incoming call_offer for this call.
  const int frameMs = impl_->callFrameMs;
  const int localChannels = (settings.channels == 2) ? 2 : 1;
  const int negotiatedChannels = std::min(impl_->callChannels, localChannels);
  impl_->callChannels = (negotiatedChannels == 2) ? 2 : 1;
  impl_->callBitrate = std::clamp(settings.bitrate, 8000, 128000);
  impl_->callLocalAccepted = true;
  impl_->callVideoCodec = resolve_network_video_codec(settings);

  emit callStateChanged(peerId, "connecting");
  if (debug_logs_enabled()) {
    emit logLine("[dbg] call answer accept peer=" + peerId + " call_id=" + impl_->callId +
                 " frameMs=" + QString::number(impl_->callFrameMs) +
                 " channels=" + QString::number(impl_->callChannels) +
                 " bitrate=" + QString::number(impl_->callBitrate));
  }

  const int channels = impl_->callChannels;
  const int bitrate = impl_->callBitrate;
  const bool videoEnabled = impl_->callSettings.videoEnabled;
  const std::string videoCodec = impl_->callVideoCodec.toStdString();
  const int videoWidth = std::max(16, impl_->callSettings.videoWidth);
  const int videoHeight = std::max(16, impl_->callSettings.videoHeight);
  const int videoFpsNum = std::max(1, impl_->callSettings.videoFpsNum);
  const int videoFpsDen = std::max(1, impl_->callSettings.videoFpsDen);
  const int videoBitrateKbps = std::clamp(impl_->callSettings.videoBitrateKbps, 100, 20000);
  boost::asio::post(impl_->io, [impl = impl_,
                                pid,
                                call_id,
                                frameMs,
                                channels,
                                bitrate,
                                videoEnabled,
                                videoCodec,
                                videoWidth,
                                videoHeight,
                                videoFpsNum,
                                videoFpsDen,
                                videoBitrateKbps] {
    json ans;
    ans["type"] = "call_answer";
    ans["call_id"] = call_id;
    ans["accept"] = true;
    ans["sr"] = 48000;
    ans["ch"] = channels;
    ans["frame_ms"] = frameMs;
    ans["bitrate"] = bitrate;
    ans["video_enabled"] = videoEnabled;
    ans["video_codec"] = videoCodec;
    ans["video_width"] = videoWidth;
    ans["video_height"] = videoHeight;
    ans["video_fps_num"] = videoFpsNum;
    ans["video_fps_den"] = videoFpsDen;
    ans["video_bitrate_kbps"] = videoBitrateKbps;
    impl->sendControlToPeer(pid, std::move(ans));
    impl->attemptDelivery(pid, /*silent*/ true);
  });
  impl_->maybeStartVoiceQt();
#endif
}

void ChatBackend::endCall(const QString& peerId) {
  if (impl_->callPeerId != peerId) return;
  impl_->endCallQt("hangup", /*notifyPeer*/ true);
}

void ChatBackend::updateVoiceSettings(const VoiceSettings& settings) {
  // Store for the current call (if any). For future calls, MainWindow passes settings explicitly.
  const auto prev = impl_->callSettings;
  impl_->callSettings = settings;
  if (impl_->voiceChannelActive) {
    impl_->voiceChannelSettings = settings;
  }

#if defined(P2PCHAT_VOICE)
  if (!impl_->voice) return;

  // Volumes should apply live.
  if (impl_->voice->source) {
    impl_->voice->source->setVolume(std::clamp(settings.micVolume, 0, 100) / 100.0);
  }
  if (impl_->voice->sink) {
    impl_->voice->sink->setVolume(std::clamp(settings.speakerVolume, 0, 100) / 100.0);
  }

  // Bitrate can apply live (encoder only).
  const int newBitrate = std::clamp(settings.bitrate, 8000, 128000);
  if (impl_->callBitrate != newBitrate && impl_->voice->enc) {
    opus_encoder_ctl(impl_->voice->enc, OPUS_SET_BITRATE(newBitrate));
    impl_->callBitrate = newBitrate;
    emit logLine("Voice bitrate updated");
  }

  // Frame size changes affect capture chunking/playout timing; keep it simple for now.
  const int newFrameMs = (settings.frameMs == 10) ? 10 : 20;
  if (impl_->callFrameMs != newFrameMs) {
    emit logLine("Voice frame size change applies next call");
  }
  const int newChannels = (settings.channels == 2) ? 2 : 1;
  if (impl_->callChannels != newChannels) {
    emit logLine("Voice channel mode change applies next call");
  }

  auto findByHex = [](const QList<QAudioDevice>& devices, const QString& hexId) -> QAudioDevice {
    if (is_none_audio_device(hexId)) return QAudioDevice();
    if (hexId.isEmpty()) return QAudioDevice();
    for (const auto& d : devices) {
      if (QString::fromLatin1(d.id().toHex()) == hexId) return d;
    }
    return QAudioDevice();
  };

  QAudioFormat fmt;
  fmt.setSampleRate(impl_->voice->sampleRate);
  fmt.setChannelCount(impl_->voice->channels);
  fmt.setSampleFormat(QAudioFormat::Int16);
  const int frameSamples = impl_->voice->sampleRate * impl_->voice->frameMs / 1000;

  // Device changes: attempt live restart of the Qt audio objects.
  if (settings.outputDeviceIdHex != prev.outputDeviceIdHex) {
    if (impl_->voice->sink) {
      impl_->voice->sink->stop();
      impl_->voice->sink->deleteLater();
      impl_->voice->sink = nullptr;
    }
    if (is_none_audio_device(settings.outputDeviceIdHex)) {
      emit logLine("Output device disabled");
    } else {
      auto outDev = findByHex(QMediaDevices::audioOutputs(), settings.outputDeviceIdHex);
      if (outDev.isNull()) outDev = QMediaDevices::defaultAudioOutput();
      if (outDev.isNull()) {
        emit logLine("Failed to switch output device (none available)");
      } else {
        impl_->voice->sink = new QAudioSink(outDev, fmt, this);
        impl_->voice->sink->setBufferSize(frameSamples * impl_->voice->channels * static_cast<int>(sizeof(opus_int16)) * 4);
        impl_->voice->sink->setVolume(std::clamp(settings.speakerVolume, 0, 100) / 100.0);
        if (impl_->voice->sinkDev) impl_->voice->sink->start(impl_->voice->sinkDev.data());
        emit logLine("Output device updated");
      }
    }
  }

  if (settings.inputDeviceIdHex != prev.inputDeviceIdHex) {
    if (impl_->voice->source) {
      impl_->voice->source->stop();
      impl_->voice->source->deleteLater();
      impl_->voice->source = nullptr;
    }
    impl_->voice->sourceDev = nullptr;
    impl_->voice->captureBuf.clear();
    if (is_none_audio_device(settings.inputDeviceIdHex)) {
      emit logLine("Input device disabled");
    } else {
      auto inDev = findByHex(QMediaDevices::audioInputs(), settings.inputDeviceIdHex);
      if (inDev.isNull()) inDev = QMediaDevices::defaultAudioInput();
      if (inDev.isNull()) {
        emit logLine("Failed to switch input device (none available)");
      } else {
        impl_->voice->source = new QAudioSource(inDev, fmt, this);
        impl_->voice->source->setBufferSize(frameSamples * impl_->voice->channels * static_cast<int>(sizeof(opus_int16)) * 4);
        impl_->voice->source->setVolume(std::clamp(settings.micVolume, 0, 100) / 100.0);
        impl_->voice->sourceDev = impl_->voice->source->start();
        if (impl_->voice->sourceDev) {
          QObject::connect(impl_->voice->sourceDev.data(), &QIODevice::readyRead, this, [impl = impl_, frameSamples] {
            if (!impl->voice) return;
            if (!impl->voice->sourceDev) return;
            const QByteArray got = impl->voice->sourceDev->readAll();
            impl->voice->capBytes += static_cast<uint64_t>(got.size());
            impl->voice->captureBuf.append(got);
            const int frameBytes = frameSamples * impl->voice->channels * static_cast<int>(sizeof(opus_int16));
            while (impl->voice && impl->voice->captureBuf.size() >= frameBytes) {
              const QByteArray pcm = impl->voice->captureBuf.left(frameBytes);
              impl->voice->captureBuf.remove(0, frameBytes);

              std::array<unsigned char, 1500> out{};
              const int n = opus_encode(impl->voice->enc,
                                        reinterpret_cast<const opus_int16*>(pcm.constData()),
                                        frameSamples,
                                        out.data(),
                                        static_cast<opus_int32>(out.size()));
              if (n <= 0) continue;
              if (debug_logs_enabled()) impl->voice->encFrames++;
              std::vector<uint8_t> pkt(out.data(), out.data() + n);
              const QStringList peers = impl->voice->channelMode ? impl->voice->txPeers.values() : QStringList{impl->voice->peerId};
              boost::asio::post(impl->io, [impl, peers, pkt = std::move(pkt)]() mutable {
                for (const auto& peerId : peers) {
                  auto it = impl->udp_sessions.find(peerId.toStdString());
                  if (it == impl->udp_sessions.end() || !it->second) continue;
                  it->second->send_voice_frame(std::vector<uint8_t>(pkt.begin(), pkt.end()));
                }
              });
            }
          });
        }
        emit logLine("Input device updated");
      }
    }
  }

#if defined(P2PCHAT_VIDEO)
  const bool videoChanged =
      (settings.videoEnabled != prev.videoEnabled) ||
      (settings.videoDevicePath != prev.videoDevicePath) ||
      (settings.videoFourcc != prev.videoFourcc) ||
      (settings.videoWidth != prev.videoWidth) ||
      (settings.videoHeight != prev.videoHeight) ||
      (settings.videoFpsNum != prev.videoFpsNum) ||
      (settings.videoFpsDen != prev.videoFpsDen) ||
      (settings.videoCodec != prev.videoCodec) ||
      (normalize_video_provider(settings.videoProvider) != normalize_video_provider(prev.videoProvider)) ||
      (settings.videoBitrateKbps != prev.videoBitrateKbps);
  if (videoChanged && impl_->voice && impl_->voice->channelMode) {
    impl_->maybeStartVideoQt();
#if defined(P2PCHAT_VIDEO)
    const bool enabled = settings.videoEnabled && !settings.videoDevicePath.trimmed().isEmpty();
    const std::string codec = resolve_network_video_codec(settings).toStdString();
    const QStringList peers = impl_->voice->txPeers.values();
    boost::asio::post(impl_->io, [impl = impl_, peers, enabled, codec] {
      for (const auto& peerId : peers) {
        const auto pid = peerId.toStdString();
        json j;
        j["type"] = "video_state";
        j["call_id"] = "__voice_channel__";
        j["enabled"] = enabled;
        j["video_codec"] = codec;
        impl->sendControlToPeer(pid, std::move(j));
      }
    });
#endif
    emit logLine(settings.videoEnabled ? "Video settings applied" : "Video sharing disabled (receive-only)");
  }
  if (videoChanged && !impl_->callPeerId.isEmpty() && impl_->callLocalAccepted && impl_->callRemoteAccepted) {
    impl_->maybeStartVideoQt();
    const auto pid = impl_->callPeerId.toStdString();
    const auto call_id = impl_->callId.toStdString();
    const bool enabled = impl_->callSettings.videoEnabled;
    const std::string codec = impl_->callVideoCodec.toStdString();
    boost::asio::post(impl_->io, [impl = impl_, pid, call_id, enabled, codec] {
      json j;
      j["type"] = "video_state";
      j["call_id"] = call_id;
      j["enabled"] = enabled;
      j["video_codec"] = codec;
      impl->sendControlToPeer(pid, std::move(j));
    });
    emit logLine(settings.videoEnabled ? "Video settings applied" : "Video sharing disabled (receive-only)");
  }
#endif
#else
  (void)prev;
  (void)settings;
#endif
}
