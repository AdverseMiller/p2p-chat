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
                          const Profile::ScreenSettings& screen_initial,
                          bool share_identity_non_friends,
                          bool signed_only_server_messages,
                          QWidget* parent = nullptr);
  ~SettingsDialog() override;

  Profile::AudioSettings settings() const;
  Profile::VideoSettings videoSettings() const;
  Profile::ScreenSettings screenSettings() const;
  bool shareIdentityWithNonFriends() const;
  bool signedOnlyServerMessages() const;

  static bool edit(Profile::AudioSettings* inOut,
                   Profile::VideoSettings* video_in_out,
                   Profile::ScreenSettings* screen_in_out,
                   bool* share_identity_non_friends,
                   bool* signed_only_server_messages,
                   QWidget* parent = nullptr);

private:
  void rebuildDevices();
  void rebuildVideoDevices();
  void rebuildVideoCodecs();
  void rebuildVideoFormats();
  void rebuildVideoSizes();
  void rebuildVideoFps();
  void startPreview();
  void stopPreview();
  void setPreviewImage(const QImage& img);

  Profile::AudioSettings initial_;
  Profile::VideoSettings videoInitial_;
  Profile::ScreenSettings screenInitial_;

  QLabel* unavailableLabel_ = nullptr;
  QLabel* deviceWarningLabel_ = nullptr;
  QComboBox* inputDevice_ = nullptr;
  QComboBox* outputDevice_ = nullptr;
  QSlider* micVol_ = nullptr;
  QSlider* spkVol_ = nullptr;
  QSpinBox* bitrate_ = nullptr;
  QComboBox* frameMs_ = nullptr;
  QComboBox* channels_ = nullptr;
  QCheckBox* shareIdentityCheck_ = nullptr;
  QCheckBox* signedOnlyServerMessagesCheck_ = nullptr;

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

  // Screen tab
  QComboBox* screenResolution_ = nullptr;
  QComboBox* screenFps_ = nullptr;
  QSpinBox* screenBitrate_ = nullptr;

  class PreviewState;
  std::unique_ptr<PreviewState> preview_;
};
