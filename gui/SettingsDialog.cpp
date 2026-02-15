#include "gui/SettingsDialog.hpp"

#include "src/video/v4l2_caps.h"
#include "src/video/v4l2_capture.h"
#include "src/video/video_codec.h"

#include <QComboBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSlider>
#include <QSpinBox>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QSignalBlocker>

#include <atomic>
#include <mutex>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#if defined(P2PCHAT_VOICE)
#include <QMediaDevices>
#include <QAudioDevice>
#include <QFileInfo>
#include <QDir>
#endif

namespace {
constexpr int kRoleDeviceId = Qt::UserRole + 50;
constexpr auto kNoneAudioDeviceId = "none";
constexpr int kRoleVideoDevicePath = Qt::UserRole + 100;
constexpr int kRoleVideoFourcc = Qt::UserRole + 101;
constexpr int kRoleVideoW = Qt::UserRole + 102;
constexpr int kRoleVideoH = Qt::UserRole + 103;
constexpr int kRoleVideoFpsNum = Qt::UserRole + 104;
constexpr int kRoleVideoFpsDen = Qt::UserRole + 105;

QString deviceIdHex(const QByteArray& id) {
  return QString::fromLatin1(id.toHex());
}

bool running_as_root() {
#if defined(_WIN32)
  return false;
#else
  return ::geteuid() == 0;
#endif
}

uint32_t fourccFromText(const QString& s) {
  const auto b = s.toLatin1();
  if (b.size() < 4) return 0;
  return static_cast<uint32_t>(static_cast<uint8_t>(b[0])) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(b[3])) << 24);
}

QString codecDescription(const QString& key) {
  const auto v = key.trimmed().toLower();
  (void)v;
  return "H.264 re-encodes camera frames to H.264 for network transport.\n"
         "Best default compatibility and quality/bitrate efficiency across peers.\n"
         "When the selected pixel format already outputs H.264, passthrough is used automatically (preferred).";
}

#if defined(P2PCHAT_VOICE) && !defined(_WIN32)
bool pipewireSpaSupportPresent() {
  const QString libA = "/usr/lib/spa-0.2/support/libspa-support.so";
  const QString libB = "/usr/lib64/spa-0.2/support/libspa-support.so";
  const QString libC = "/lib/spa-0.2/support/libspa-support.so";
  const QString libD = "/lib64/spa-0.2/support/libspa-support.so";
  return QFileInfo::exists(libA) || QFileInfo::exists(libB) || QFileInfo::exists(libC) || QFileInfo::exists(libD);
}
#endif
} // namespace

class SettingsDialog::PreviewState {
public:
  std::unique_ptr<video::V4L2Capture> cap;
  std::atomic<bool> running{false};
  std::mutex m;
  QImage latest;
};

SettingsDialog::~SettingsDialog() = default;

SettingsDialog::SettingsDialog(const Profile::AudioSettings& initial,
                               const Profile::VideoSettings& video_initial,
                               const Profile::ScreenSettings& screen_initial,
                               bool share_identity_non_friends,
                               QWidget* parent)
    : QDialog(parent), initial_(initial), videoInitial_(video_initial), screenInitial_(screen_initial) {
  setWindowTitle("Settings");
  setMinimumWidth(500);

  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);
  auto* tabs = new QTabWidget(this);

  auto* audioTab = new QWidget(tabs);
  auto* audioRoot = new QVBoxLayout(audioTab);
  audioRoot->setContentsMargins(8, 8, 8, 8);

#if !defined(P2PCHAT_VOICE)
  unavailableLabel_ = new QLabel(
      "Voice calls are unavailable in this build.\n\n"
      "Rebuild with Qt6 Multimedia + Opus to enable voice calls.",
      audioTab);
  unavailableLabel_->setWordWrap(true);
  audioRoot->addWidget(unavailableLabel_);
#else
  deviceWarningLabel_ = new QLabel(audioTab);
  deviceWarningLabel_->setWordWrap(true);
  deviceWarningLabel_->setStyleSheet("color:#c33; font-weight:600;");
  deviceWarningLabel_->setVisible(false);
  audioRoot->addWidget(deviceWarningLabel_);

  auto* form = new QFormLayout();

  inputDevice_ = new QComboBox(audioTab);
  outputDevice_ = new QComboBox(audioTab);

  micVol_ = new QSlider(Qt::Horizontal, audioTab);
  micVol_->setRange(0, 100);
  micVol_->setValue(initial_.micVolume);

  spkVol_ = new QSlider(Qt::Horizontal, audioTab);
  spkVol_->setRange(0, 100);
  spkVol_->setValue(initial_.speakerVolume);

  bitrate_ = new QSpinBox(audioTab);
  bitrate_->setRange(8000, 128000);
  bitrate_->setSingleStep(1000);
  bitrate_->setValue(initial_.bitrate);
  bitrate_->setSuffix(" bps");

  frameMs_ = new QComboBox(audioTab);
  frameMs_->addItem("10 ms", 10);
  frameMs_->addItem("20 ms", 20);
  channels_ = new QComboBox(audioTab);
  channels_->addItem("Mono", 1);
  channels_->addItem("Stereo", 2);

  form->addRow("Input device:", inputDevice_);
  form->addRow("Output device:", outputDevice_);
  form->addRow("Mic volume:", micVol_);
  form->addRow("Speaker volume:", spkVol_);
  form->addRow("Bitrate:", bitrate_);
  form->addRow("Frame size:", frameMs_);
  form->addRow("Channels:", channels_);

  audioRoot->addLayout(form);

  rebuildDevices();

  // Restore frame selection.
  const int wantFrame = (initial_.frameMs == 10) ? 10 : 20;
  for (int i = 0; i < frameMs_->count(); ++i) {
    if (frameMs_->itemData(i).toInt() == wantFrame) {
      frameMs_->setCurrentIndex(i);
      break;
    }
  }
  const int wantChannels = (initial_.channels == 2) ? 2 : 1;
  for (int i = 0; i < channels_->count(); ++i) {
    if (channels_->itemData(i).toInt() == wantChannels) {
      channels_->setCurrentIndex(i);
      break;
    }
  }
#endif
  tabs->addTab(audioTab, "Audio");

  auto* videoTab = new QWidget(tabs);
  auto* videoRoot = new QVBoxLayout(videoTab);
  videoRoot->setContentsMargins(8, 8, 8, 8);

  auto* vform = new QFormLayout();
  videoDevice_ = new QComboBox(videoTab);
  videoFormat_ = new QComboBox(videoTab);
  videoSize_ = new QComboBox(videoTab);
  videoFps_ = new QComboBox(videoTab);
  videoCodec_ = new QComboBox(videoTab);
  videoCodec_->setToolTip(codecDescription("h264"));
  videoBitrate_ = new QSpinBox(videoTab);
  videoBitrate_->setRange(100, 20000);
  videoBitrate_->setSuffix(" kbps");
  videoBitrate_->setValue(videoInitial_.bitrateKbps);

  vform->addRow("Camera device:", videoDevice_);
  vform->addRow("Pixel format:", videoFormat_);
  vform->addRow("Resolution:", videoSize_);
  vform->addRow("FPS:", videoFps_);
  vform->addRow("Network codec:", videoCodec_);
  vform->addRow("Bitrate:", videoBitrate_);
  videoRoot->addLayout(vform);

  previewLabel_ = new QLabel("Preview stopped", videoTab);
  previewLabel_->setMinimumSize(420, 240);
  previewLabel_->setAlignment(Qt::AlignCenter);
  previewLabel_->setStyleSheet("border:1px solid palette(mid);");
  videoRoot->addWidget(previewLabel_, 1);

  previewBtn_ = new QPushButton("Start Preview", videoTab);
  videoRoot->addWidget(previewBtn_, 0, Qt::AlignLeft);
  connect(previewBtn_, &QPushButton::clicked, this, [this] {
    if (preview_ && preview_->running.load()) {
      stopPreview();
    } else {
      startPreview();
    }
  });

  connect(videoDevice_, &QComboBox::currentIndexChanged, this, [this] {
    stopPreview();
    rebuildVideoCodecs();
    rebuildVideoFormats();
  });
  connect(videoCodec_, &QComboBox::currentIndexChanged, this, [this] {
    stopPreview();
    if (videoCodec_) {
      videoCodec_->setToolTip(codecDescription(videoCodec_->currentData().toString()));
    }
    rebuildVideoFormats();
  });
  connect(videoFormat_, &QComboBox::currentIndexChanged, this, [this] {
    stopPreview();
    rebuildVideoSizes();
  });
  connect(videoSize_, &QComboBox::currentIndexChanged, this, [this] {
    stopPreview();
    rebuildVideoFps();
  });

  rebuildVideoDevices();
  rebuildVideoCodecs();
  tabs->addTab(videoTab, "Webcam");

  auto* screenTab = new QWidget(tabs);
  auto* screenRoot = new QVBoxLayout(screenTab);
  screenRoot->setContentsMargins(8, 8, 8, 8);
  auto* sform = new QFormLayout();
  screenResolution_ = new QComboBox(screenTab);
  screenFps_ = new QComboBox(screenTab);
  screenBitrate_ = new QSpinBox(screenTab);
  screenBitrate_->setRange(100, 20000);
  screenBitrate_->setSuffix(" kbps");
  screenBitrate_->setValue(screenInitial_.bitrateKbps);

  auto addRes = [this](const QString& label, int w, int h) {
    if (!screenResolution_) return;
    screenResolution_->addItem(label);
    const int idx = screenResolution_->count() - 1;
    screenResolution_->setItemData(idx, w, kRoleVideoW);
    screenResolution_->setItemData(idx, h, kRoleVideoH);
  };
  addRes("Native (display resolution)", 0, 0);
  addRes("3840x2160", 3840, 2160);
  addRes("2560x1440", 2560, 1440);
  addRes("1920x1080", 1920, 1080);
  addRes("1600x900", 1600, 900);
  addRes("1366x768", 1366, 768);
  addRes("1280x720", 1280, 720);
  addRes("1024x576", 1024, 576);

  auto addFps = [this](int fps) {
    if (!screenFps_ || fps <= 0) return;
    screenFps_->addItem(QString::number(fps) + " fps");
    const int idx = screenFps_->count() - 1;
    screenFps_->setItemData(idx, 1, kRoleVideoFpsNum);
    screenFps_->setItemData(idx, fps, kRoleVideoFpsDen);
  };
  addFps(5);
  addFps(10);
  addFps(15);
  addFps(20);
  addFps(30);
  addFps(60);

  int resPick = 0;
  for (int i = 0; i < screenResolution_->count(); ++i) {
    const int w = screenResolution_->itemData(i, kRoleVideoW).toInt();
    const int h = screenResolution_->itemData(i, kRoleVideoH).toInt();
    if (w == screenInitial_.width && h == screenInitial_.height) {
      resPick = i;
      break;
    }
  }
  screenResolution_->setCurrentIndex(resPick);

  int fpsPick = 0;
  for (int i = 0; i < screenFps_->count(); ++i) {
    const int num = screenFps_->itemData(i, kRoleVideoFpsNum).toInt();
    const int den = screenFps_->itemData(i, kRoleVideoFpsDen).toInt();
    if (num == screenInitial_.fpsNum && den == screenInitial_.fpsDen) {
      fpsPick = i;
      break;
    }
  }
  screenFps_->setCurrentIndex(fpsPick);

  sform->addRow("Resolution:", screenResolution_);
  sform->addRow("FPS:", screenFps_);
  sform->addRow("Bitrate:", screenBitrate_);
  screenRoot->addLayout(sform);
  screenRoot->addStretch(1);
  tabs->addTab(screenTab, "Screen");

  auto* privacyTab = new QWidget(tabs);
  auto* privacyRoot = new QVBoxLayout(privacyTab);
  privacyRoot->setContentsMargins(8, 8, 8, 8);
  shareIdentityCheck_ = new QCheckBox("Allow non-friends in servers to see my username and profile picture", privacyTab);
  shareIdentityCheck_->setChecked(share_identity_non_friends);
  privacyRoot->addWidget(shareIdentityCheck_);
  privacyRoot->addStretch(1);
  tabs->addTab(privacyTab, "Privacy");

  root->addWidget(tabs);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  connect(this, &QDialog::finished, this, [this](int) { stopPreview(); });
  root->addWidget(buttons);
}

void SettingsDialog::rebuildDevices() {
#if !defined(P2PCHAT_VOICE)
  return;
#else
  // QtMultimedia’s Linux audio backends (PipeWire/PulseAudio) expect a per-user runtime dir and usually
  // crash/abort when started as root (common when using setuid `ip netns exec ...`).
  if (running_as_root()) {
    if (deviceWarningLabel_) {
      deviceWarningLabel_->setText(
          "Audio device enumeration is disabled because this program is running as root.\n"
          "Run the GUI as your normal user (do not launch it via a setuid `ip`).");
      deviceWarningLabel_->setVisible(true);
    }
    if (inputDevice_) {
      inputDevice_->clear();
      inputDevice_->addItem("Unavailable (running as root)", QString());
      inputDevice_->setEnabled(false);
    }
    if (outputDevice_) {
      outputDevice_->clear();
      outputDevice_->addItem("Unavailable (running as root)", QString());
      outputDevice_->setEnabled(false);
    }
    return;
  }

#if !defined(_WIN32)
  // Some minimal systems have libpipewire installed without the SPA support plugin directory.
  // QtMultimedia can abort when PipeWire initialization fails. Avoid touching QMediaDevices in that case.
  if (!pipewireSpaSupportPresent()) {
    if (deviceWarningLabel_) {
      deviceWarningLabel_->setText(
          "Audio device enumeration is unavailable because PipeWire SPA support is missing.\n"
          "Install the PipeWire SPA plugins (e.g. spa-plugins / pipewire) and restart your session.");
      deviceWarningLabel_->setVisible(true);
    }
    if (inputDevice_) {
      inputDevice_->clear();
      inputDevice_->addItem("Unavailable (missing PipeWire SPA support)", QString());
      inputDevice_->setEnabled(false);
    }
    if (outputDevice_) {
      outputDevice_->clear();
      outputDevice_->addItem("Unavailable (missing PipeWire SPA support)", QString());
      outputDevice_->setEnabled(false);
    }
    return;
  }
#endif

  if (deviceWarningLabel_) deviceWarningLabel_->setVisible(false);

  inputDevice_->clear();
  outputDevice_->clear();
  inputDevice_->addItem("None (disabled)", QString::fromLatin1(kNoneAudioDeviceId));
  outputDevice_->addItem("None (disabled)", QString::fromLatin1(kNoneAudioDeviceId));

  const auto ins = QMediaDevices::audioInputs();
  const auto outs = QMediaDevices::audioOutputs();

  for (const auto& d : ins) {
    inputDevice_->addItem(d.description(), deviceIdHex(d.id()));
  }
  for (const auto& d : outs) {
    outputDevice_->addItem(d.description(), deviceIdHex(d.id()));
  }

  auto selectByIdHex = [](QComboBox* box, const QString& want) {
    if (!box) return;
    if (want.isEmpty()) return;
    for (int i = 0; i < box->count(); ++i) {
      if (box->itemData(i).toString() == want) {
        box->setCurrentIndex(i);
        return;
      }
    }
  };

  selectByIdHex(inputDevice_, initial_.inputDeviceIdHex);
  selectByIdHex(outputDevice_, initial_.outputDeviceIdHex);
  if (initial_.inputDeviceIdHex.isEmpty()) {
    const auto def = QMediaDevices::defaultAudioInput();
    const auto defHex = deviceIdHex(def.id());
    selectByIdHex(inputDevice_, defHex);
  }
  if (initial_.outputDeviceIdHex.isEmpty()) {
    const auto def = QMediaDevices::defaultAudioOutput();
    const auto defHex = deviceIdHex(def.id());
    selectByIdHex(outputDevice_, defHex);
  }
#endif
}

void SettingsDialog::rebuildVideoDevices() {
  if (!videoDevice_) return;
  videoDevice_->clear();
  const auto devs = video::listVideoDevices();
  for (const auto& d : devs) {
    videoDevice_->addItem(QString("%1 (%2)").arg(d.path, d.name), d.path);
  }

  int pick = -1;
  if (!videoInitial_.devicePath.isEmpty()) {
    for (int i = 0; i < videoDevice_->count(); ++i) {
      if (videoDevice_->itemData(i).toString() == videoInitial_.devicePath) {
        pick = i;
        break;
      }
    }
  }
  if (pick < 0 && videoDevice_->count() > 0) pick = 0;
  if (pick >= 0) videoDevice_->setCurrentIndex(pick);
  rebuildVideoCodecs();
  rebuildVideoFormats();
}

void SettingsDialog::rebuildVideoCodecs() {
  if (!videoCodec_ || !videoDevice_) return;
  const QSignalBlocker block(videoCodec_);
  const QString wanted = "h264";

  videoCodec_->clear();
  videoCodec_->addItem("H264", "h264");
  videoCodec_->setItemData(videoCodec_->count() - 1, codecDescription("h264"), Qt::ToolTipRole);

  int pick = 0;
  for (int i = 0; i < videoCodec_->count(); ++i) {
    if (videoCodec_->itemData(i).toString().trimmed().toLower() == wanted) {
      pick = i;
      break;
    }
  }
  videoCodec_->setCurrentIndex(pick);
  videoCodec_->setToolTip(videoCodec_->itemData(pick, Qt::ToolTipRole).toString());
}

void SettingsDialog::rebuildVideoFormats() {
  if (!videoFormat_ || !videoDevice_ || !videoCodec_) return;
  const QString previousFourcc = videoFormat_->currentData().toString();
  videoFormat_->clear();
  const auto path = videoDevice_->currentData().toString();
  const auto selectedCodec = videoCodec_->currentData().toString().trimmed().toLower();
  const auto selectedNetworkCodec = video::codecFromString(selectedCodec);
  if (path.isEmpty()) {
    rebuildVideoSizes();
    return;
  }
  const auto caps = video::queryDeviceCaps(path);
  bool addedSupported = false;
  for (const auto& fmt : caps.formats) {
    if (!video::isInputFourccSupported(fmt.fourcc)) continue;
    const auto fmtCodec = video::codecFromInputFourcc(fmt.fourcc);
    QString label = QString("%1 (%2)").arg(fmt.fourccStr, fmt.description);
    if (fmtCodec.has_value()) {
      label += QString(" [direct %1]").arg(video::codecToString(fmtCodec.value()).toUpper());
      if (video::isPassthroughCompatible(fmt.fourcc, selectedNetworkCodec)) {
        label += " (preferred)";
      }
    }
    videoFormat_->addItem(label, fmt.fourccStr);
    videoFormat_->setItemData(videoFormat_->count() - 1, static_cast<quint32>(fmt.fourcc), kRoleVideoFourcc);
    addedSupported = true;
  }
  if (!addedSupported) {
    for (const auto& fmt : caps.formats) {
      videoFormat_->addItem(QString("%1 (%2, unsupported)").arg(fmt.fourccStr, fmt.description), fmt.fourccStr);
      videoFormat_->setItemData(videoFormat_->count() - 1, static_cast<quint32>(fmt.fourcc), kRoleVideoFourcc);
    }
  }

  int pick = -1;
  if (!previousFourcc.isEmpty()) {
    for (int i = 0; i < videoFormat_->count(); ++i) {
      if (videoFormat_->itemData(i).toString().compare(previousFourcc, Qt::CaseInsensitive) == 0) {
        pick = i;
        break;
      }
    }
  }
  if (pick < 0 && !videoInitial_.cameraFourcc.isEmpty()) {
    for (int i = 0; i < videoFormat_->count(); ++i) {
      if (videoFormat_->itemData(i).toString().compare(videoInitial_.cameraFourcc, Qt::CaseInsensitive) == 0) {
        pick = i;
        break;
      }
    }
  }
  if (pick < 0) {
    for (int i = 0; i < videoFormat_->count(); ++i) {
      const uint32_t fourcc = static_cast<uint32_t>(videoFormat_->itemData(i, kRoleVideoFourcc).toUInt());
      if (video::isPassthroughCompatible(fourcc, selectedNetworkCodec)) {
        pick = i;
        break;
      }
    }
  }
  if (pick < 0 && videoFormat_->count() > 0) pick = 0;
  if (pick >= 0) videoFormat_->setCurrentIndex(pick);
  rebuildVideoSizes();
}

void SettingsDialog::rebuildVideoSizes() {
  if (!videoSize_ || !videoDevice_ || !videoFormat_) return;
  videoSize_->clear();
  const auto path = videoDevice_->currentData().toString();
  const auto fourcc = videoFormat_->currentData().toString();
  if (path.isEmpty() || fourcc.isEmpty()) {
    rebuildVideoFps();
    return;
  }
  const auto caps = video::queryDeviceCaps(path);
  for (const auto& fmt : caps.formats) {
    if (fmt.fourccStr.compare(fourcc, Qt::CaseInsensitive) != 0) continue;
    for (const auto& sz : fmt.sizes) {
      const QString label = QString("%1x%2").arg(sz.width).arg(sz.height);
      videoSize_->addItem(label);
      const int idx = videoSize_->count() - 1;
      videoSize_->setItemData(idx, static_cast<int>(sz.width), kRoleVideoW);
      videoSize_->setItemData(idx, static_cast<int>(sz.height), kRoleVideoH);
    }
    break;
  }

  int pick = -1;
  for (int i = 0; i < videoSize_->count(); ++i) {
    const int w = videoSize_->itemData(i, kRoleVideoW).toInt();
    const int h = videoSize_->itemData(i, kRoleVideoH).toInt();
    if (w == videoInitial_.width && h == videoInitial_.height) {
      pick = i;
      break;
    }
  }
  if (pick < 0 && videoSize_->count() > 0) pick = 0;
  if (pick >= 0) videoSize_->setCurrentIndex(pick);
  rebuildVideoFps();
}

void SettingsDialog::rebuildVideoFps() {
  if (!videoFps_ || !videoDevice_ || !videoFormat_ || !videoSize_) return;
  videoFps_->clear();
  const auto path = videoDevice_->currentData().toString();
  const auto fourcc = videoFormat_->currentData().toString();
  const int w = videoSize_->currentData(kRoleVideoW).toInt();
  const int h = videoSize_->currentData(kRoleVideoH).toInt();
  if (path.isEmpty() || fourcc.isEmpty() || w <= 0 || h <= 0) return;

  const auto caps = video::queryDeviceCaps(path);
  for (const auto& fmt : caps.formats) {
    if (fmt.fourccStr.compare(fourcc, Qt::CaseInsensitive) != 0) continue;
    for (const auto& sz : fmt.sizes) {
      if (static_cast<int>(sz.width) != w || static_cast<int>(sz.height) != h) continue;
      for (const auto& fps : sz.fps) {
        const QString label = QString::number(fps.value(), 'f', 2) + " fps";
        videoFps_->addItem(label);
        const int idx = videoFps_->count() - 1;
        videoFps_->setItemData(idx, static_cast<int>(fps.num), kRoleVideoFpsNum);
        videoFps_->setItemData(idx, static_cast<int>(fps.den), kRoleVideoFpsDen);
      }
      break;
    }
    break;
  }

  int pick = -1;
  for (int i = 0; i < videoFps_->count(); ++i) {
    const int num = videoFps_->itemData(i, kRoleVideoFpsNum).toInt();
    const int den = videoFps_->itemData(i, kRoleVideoFpsDen).toInt();
    if (num == videoInitial_.fpsNum && den == videoInitial_.fpsDen) {
      pick = i;
      break;
    }
  }
  if (pick < 0 && videoFps_->count() > 0) pick = 0;
  if (pick >= 0) videoFps_->setCurrentIndex(pick);
}

void SettingsDialog::setPreviewImage(const QImage& img) {
  if (!previewLabel_) return;
  if (img.isNull()) {
    previewLabel_->setText("Preview unavailable");
    return;
  }
  previewLabel_->setPixmap(QPixmap::fromImage(img).scaled(previewLabel_->size(),
                                                          Qt::KeepAspectRatio,
                                                          Qt::SmoothTransformation));
}

void SettingsDialog::startPreview() {
  if (!videoDevice_ || !videoFormat_ || !videoSize_ || !videoFps_ || !previewBtn_) return;
  stopPreview();

  const auto path = videoDevice_->currentData().toString();
  const auto fourccStr = videoFormat_->currentData().toString();
  const int w = videoSize_->currentData(kRoleVideoW).toInt();
  const int h = videoSize_->currentData(kRoleVideoH).toInt();
  const int fpsNum = videoFps_->currentData(kRoleVideoFpsNum).toInt();
  const int fpsDen = videoFps_->currentData(kRoleVideoFpsDen).toInt();
  if (path.isEmpty() || fourccStr.size() < 4 || w <= 0 || h <= 0) return;

  uint32_t fourcc = fourccFromText(fourccStr);

  preview_ = std::make_unique<PreviewState>();
  preview_->cap = std::make_unique<video::V4L2Capture>();
  video::CaptureConfig cfg;
  cfg.devicePath = path;
  cfg.fourcc = fourcc;
  cfg.width = static_cast<uint32_t>(w);
  cfg.height = static_cast<uint32_t>(h);
  cfg.fpsNum = static_cast<uint32_t>(fpsNum <= 0 ? 1 : fpsNum);
  cfg.fpsDen = static_cast<uint32_t>(fpsDen <= 0 ? 30 : fpsDen);

  const bool ok = preview_->cap->start(
      cfg,
      [this](const video::RawFrame& rf) {
        video::I420Frame i420;
        QString err;
        if (!video::convertRawFrameToI420(rf, &i420, &err)) {
          QMetaObject::invokeMethod(this,
                                    [this, err] {
                                      if (previewLabel_) previewLabel_->setText("Preview conversion failed: " + err);
                                    },
                                    Qt::QueuedConnection);
          return;
        }
        QImage img = video::i420ToQImage(i420);
        if (img.isNull()) {
          QMetaObject::invokeMethod(this,
                                    [this] {
                                      if (previewLabel_) previewLabel_->setText("Preview conversion produced empty image");
                                    },
                                    Qt::QueuedConnection);
          return;
        }
        if (!preview_) return;
        std::lock_guard lk(preview_->m);
        preview_->latest = std::move(img);
      },
      [this](const QString& err) {
        QMetaObject::invokeMethod(this,
                                  [this, err] {
                                    if (previewLabel_) previewLabel_->setText("Preview error: " + err);
                                  },
                                  Qt::QueuedConnection);
      });
  if (!ok) {
    preview_.reset();
    if (previewLabel_) previewLabel_->setText("Preview failed to start");
    return;
  }
  preview_->running = true;
  previewBtn_->setText("Stop Preview");

  if (!previewUiTimer_) {
    previewUiTimer_ = new QTimer(this);
    previewUiTimer_->setInterval(33);
    connect(previewUiTimer_, &QTimer::timeout, this, [this] {
      if (!preview_ || !preview_->running.load()) return;
      QImage img;
      {
        std::lock_guard lk(preview_->m);
        img = preview_->latest;
      }
      if (!img.isNull()) setPreviewImage(img);
    });
  }
  previewUiTimer_->start();
}

void SettingsDialog::stopPreview() {
  if (previewUiTimer_) previewUiTimer_->stop();
  if (preview_) {
    preview_->running = false;
    if (preview_->cap) preview_->cap->stop();
    preview_.reset();
  }
  if (previewBtn_) previewBtn_->setText("Start Preview");
  if (previewLabel_) previewLabel_->setText("Preview stopped");
}

Profile::AudioSettings SettingsDialog::settings() const {
  Profile::AudioSettings s = initial_;
#if !defined(P2PCHAT_VOICE)
  return s;
#else
  if (inputDevice_) s.inputDeviceIdHex = inputDevice_->currentData().toString();
  if (outputDevice_) s.outputDeviceIdHex = outputDevice_->currentData().toString();
  if (micVol_) s.micVolume = micVol_->value();
  if (spkVol_) s.speakerVolume = spkVol_->value();
  if (bitrate_) s.bitrate = bitrate_->value();
  if (frameMs_) s.frameMs = frameMs_->currentData().toInt();
  if (channels_) s.channels = channels_->currentData().toInt();
  if (s.frameMs != 10 && s.frameMs != 20) s.frameMs = 20;
  if (s.channels != 1 && s.channels != 2) s.channels = 1;
  return s;
#endif
}

Profile::VideoSettings SettingsDialog::videoSettings() const {
  Profile::VideoSettings s = videoInitial_;
  if (videoDevice_) s.devicePath = videoDevice_->currentData().toString();
  if (videoFormat_) s.cameraFourcc = videoFormat_->currentData().toString();
  if (videoSize_) {
    bool okW = false;
    const int width = videoSize_->currentData(kRoleVideoW).toInt(&okW);
    if (okW) s.width = width;
    bool okH = false;
    const int height = videoSize_->currentData(kRoleVideoH).toInt(&okH);
    if (okH) s.height = height;
  }
  if (videoFps_) {
    bool okNum = false;
    const int fpsNum = videoFps_->currentData(kRoleVideoFpsNum).toInt(&okNum);
    if (okNum) s.fpsNum = fpsNum;
    bool okDen = false;
    const int fpsDen = videoFps_->currentData(kRoleVideoFpsDen).toInt(&okDen);
    if (okDen) s.fpsDen = fpsDen;
  }
  if (videoCodec_) s.codec = videoCodec_->currentData().toString();
  if (videoBitrate_) s.bitrateKbps = videoBitrate_->value();
  if (s.width < 16) s.width = 16;
  if (s.height < 16) s.height = 16;
  if (s.fpsNum <= 0) s.fpsNum = 1;
  if (s.fpsDen <= 0) s.fpsDen = 30;
  s.codec = "h264";
  return s;
}

Profile::ScreenSettings SettingsDialog::screenSettings() const {
  Profile::ScreenSettings s = screenInitial_;
  if (screenResolution_) {
    bool okW = false;
    const int width = screenResolution_->currentData(kRoleVideoW).toInt(&okW);
    if (okW) s.width = width;
    bool okH = false;
    const int height = screenResolution_->currentData(kRoleVideoH).toInt(&okH);
    if (okH) s.height = height;
    if (s.width < 0) s.width = 0;
    if (s.height < 0) s.height = 0;
    if (s.width == 0 || s.height == 0) {
      s.width = 0;
      s.height = 0;
    }
  }
  if (screenFps_) {
    bool okNum = false;
    const int fpsNum = screenFps_->currentData(kRoleVideoFpsNum).toInt(&okNum);
    if (okNum) s.fpsNum = fpsNum;
    bool okDen = false;
    const int fpsDen = screenFps_->currentData(kRoleVideoFpsDen).toInt(&okDen);
    if (okDen) s.fpsDen = fpsDen;
  }
  if (screenBitrate_) s.bitrateKbps = screenBitrate_->value();
  if (s.fpsNum <= 0) s.fpsNum = 1;
  if (s.fpsDen <= 0) s.fpsDen = 15;
  if (s.bitrateKbps < 100) s.bitrateKbps = 100;
  if (s.bitrateKbps > 20000) s.bitrateKbps = 20000;
  return s;
}

bool SettingsDialog::shareIdentityWithNonFriends() const {
  return shareIdentityCheck_ ? shareIdentityCheck_->isChecked() : false;
}

bool SettingsDialog::edit(Profile::AudioSettings* inOut,
                          Profile::VideoSettings* video_in_out,
                          Profile::ScreenSettings* screen_in_out,
                          bool* share_identity_non_friends,
                          QWidget* parent) {
  if (!inOut || !video_in_out || !screen_in_out || !share_identity_non_friends) return false;
  SettingsDialog dlg(*inOut, *video_in_out, *screen_in_out, *share_identity_non_friends, parent);
  if (dlg.exec() != QDialog::Accepted) return false;
  *inOut = dlg.settings();
  *video_in_out = dlg.videoSettings();
  *screen_in_out = dlg.screenSettings();
  *share_identity_non_friends = dlg.shareIdentityWithNonFriends();
  return true;
}
