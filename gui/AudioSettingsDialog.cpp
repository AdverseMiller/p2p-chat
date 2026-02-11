#include "gui/AudioSettingsDialog.hpp"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSlider>
#include <QSpinBox>
#include <QVBoxLayout>

#include <unistd.h>

#if defined(P2PCHAT_VOICE)
#include <QMediaDevices>
#include <QAudioDevice>
#include <QFileInfo>
#include <QDir>
#endif

namespace {
constexpr int kRoleDeviceId = Qt::UserRole + 50;

QString deviceIdHex(const QByteArray& id) {
  return QString::fromLatin1(id.toHex());
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

AudioSettingsDialog::AudioSettingsDialog(const Profile::AudioSettings& initial, QWidget* parent)
    : QDialog(parent), initial_(initial) {
  setWindowTitle("Audio Settings");
  setMinimumWidth(420);

  auto* root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);

#if !defined(P2PCHAT_VOICE)
  unavailableLabel_ = new QLabel(
      "Voice calls are unavailable in this build.\n\n"
      "Rebuild with Qt6 Multimedia + Opus to enable voice calls.",
      this);
  unavailableLabel_->setWordWrap(true);
  root->addWidget(unavailableLabel_);
#else
  deviceWarningLabel_ = new QLabel(this);
  deviceWarningLabel_->setWordWrap(true);
  deviceWarningLabel_->setStyleSheet("color:#c33; font-weight:600;");
  deviceWarningLabel_->setVisible(false);
  root->addWidget(deviceWarningLabel_);

  auto* form = new QFormLayout();

  inputDevice_ = new QComboBox(this);
  outputDevice_ = new QComboBox(this);

  micVol_ = new QSlider(Qt::Horizontal, this);
  micVol_->setRange(0, 100);
  micVol_->setValue(initial_.micVolume);

  spkVol_ = new QSlider(Qt::Horizontal, this);
  spkVol_->setRange(0, 100);
  spkVol_->setValue(initial_.speakerVolume);

  bitrate_ = new QSpinBox(this);
  bitrate_->setRange(8000, 128000);
  bitrate_->setSingleStep(1000);
  bitrate_->setValue(initial_.bitrate);
  bitrate_->setSuffix(" bps");

  frameMs_ = new QComboBox(this);
  frameMs_->addItem("10 ms", 10);
  frameMs_->addItem("20 ms", 20);

  form->addRow("Input device:", inputDevice_);
  form->addRow("Output device:", outputDevice_);
  form->addRow("Mic volume:", micVol_);
  form->addRow("Speaker volume:", spkVol_);
  form->addRow("Bitrate:", bitrate_);
  form->addRow("Frame size:", frameMs_);

  root->addLayout(form);

  rebuildDevices();

  // Restore frame selection.
  const int wantFrame = (initial_.frameMs == 10) ? 10 : 20;
  for (int i = 0; i < frameMs_->count(); ++i) {
    if (frameMs_->itemData(i).toInt() == wantFrame) {
      frameMs_->setCurrentIndex(i);
      break;
    }
  }
#endif

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  root->addWidget(buttons);
}

void AudioSettingsDialog::rebuildDevices() {
#if !defined(P2PCHAT_VOICE)
  return;
#else
  // QtMultimedia’s Linux audio backends (PipeWire/PulseAudio) expect a per-user runtime dir and usually
  // crash/abort when started as root (common when using setuid `ip netns exec ...`).
  if (::geteuid() == 0) {
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
#endif
}

Profile::AudioSettings AudioSettingsDialog::settings() const {
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
  if (s.frameMs != 10 && s.frameMs != 20) s.frameMs = 20;
  return s;
#endif
}

bool AudioSettingsDialog::edit(Profile::AudioSettings* inOut, QWidget* parent) {
  if (!inOut) return false;
  AudioSettingsDialog dlg(*inOut, parent);
  if (dlg.exec() != QDialog::Accepted) return false;
  *inOut = dlg.settings();
  return true;
}
