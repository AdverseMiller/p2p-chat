#pragma once

#include "gui/Profile.hpp"

#include <QDialog>
#include <QImage>
#include <memory>

class QComboBox;
class QSlider;
class QSpinBox;
class QLabel;
class QCheckBox;
class QPushButton;
class QTimer;

class SettingsDialog final : public QDialog {
  Q_OBJECT
public:
  explicit SettingsDialog(const Profile::AudioSettings& initial,
                          const Profile::VideoSettings& video_initial,
                          bool share_identity_non_friends,
                          QWidget* parent = nullptr);
  ~SettingsDialog() override;

  Profile::AudioSettings settings() const;
  Profile::VideoSettings videoSettings() const;
  bool shareIdentityWithNonFriends() const;

  static bool edit(Profile::AudioSettings* inOut,
                   Profile::VideoSettings* video_in_out,
                   bool* share_identity_non_friends,
                   QWidget* parent = nullptr);

private:
  void rebuildDevices();
  void rebuildVideoDevices();
  void rebuildVideoFormats();
  void rebuildVideoSizes();
  void rebuildVideoFps();
  void startPreview();
  void stopPreview();
  void setPreviewImage(const QImage& img);

  Profile::AudioSettings initial_;
  Profile::VideoSettings videoInitial_;

  QLabel* unavailableLabel_ = nullptr;
  QLabel* deviceWarningLabel_ = nullptr;
  QComboBox* inputDevice_ = nullptr;
  QComboBox* outputDevice_ = nullptr;
  QSlider* micVol_ = nullptr;
  QSlider* spkVol_ = nullptr;
  QSpinBox* bitrate_ = nullptr;
  QComboBox* frameMs_ = nullptr;
  QCheckBox* shareIdentityCheck_ = nullptr;

  // Video tab
  QComboBox* videoDevice_ = nullptr;
  QComboBox* videoFormat_ = nullptr;
  QComboBox* videoSize_ = nullptr;
  QComboBox* videoFps_ = nullptr;
  QComboBox* videoCodec_ = nullptr;
  QSpinBox* videoBitrate_ = nullptr;
  QLabel* previewLabel_ = nullptr;
  QPushButton* previewBtn_ = nullptr;
  QTimer* previewUiTimer_ = nullptr;

  class PreviewState;
  std::unique_ptr<PreviewState> preview_;
};
