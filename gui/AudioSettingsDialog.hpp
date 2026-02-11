#pragma once

#include "gui/Profile.hpp"

#include <QDialog>

class QComboBox;
class QSlider;
class QSpinBox;
class QLabel;

class AudioSettingsDialog final : public QDialog {
  Q_OBJECT
public:
  explicit AudioSettingsDialog(const Profile::AudioSettings& initial, QWidget* parent = nullptr);

  Profile::AudioSettings settings() const;

  static bool edit(Profile::AudioSettings* inOut, QWidget* parent = nullptr);

private:
  void rebuildDevices();

  Profile::AudioSettings initial_;

  QLabel* unavailableLabel_ = nullptr;
  QLabel* deviceWarningLabel_ = nullptr;
  QComboBox* inputDevice_ = nullptr;
  QComboBox* outputDevice_ = nullptr;
  QSlider* micVol_ = nullptr;
  QSlider* spkVol_ = nullptr;
  QSpinBox* bitrate_ = nullptr;
  QComboBox* frameMs_ = nullptr;
};
