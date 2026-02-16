#include "gui/MainWindow.hpp"
#include "gui/SettingsDialog.hpp"
#include "common/identity.hpp"
#include "common/json.hpp"

#include <QAction>
#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QListView>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPainter>
#include <QPainterPath>
#include <QStyledItemDelegate>
#include <QStyle>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPalette>
#include <QColor>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSizePolicy>
#include <QStatusBar>
#include <QStyleFactory>
#include <QStackedWidget>
#include <QSplitter>
#include <QScreen>
#include <QSignalBlocker>
#include <QTabWidget>
#include <QTextBrowser>
#include <QTimer>
#include <QToolButton>
#include <QUrl>
#include <QUrlQuery>
#include <QStandardPaths>
#include <QUuid>
#include <QVBoxLayout>

#include <iostream>
#include <algorithm>
#include <cmath>
#include <ctime>
#include <functional>

namespace {
constexpr int kRolePeerId = Qt::UserRole;
constexpr int kRolePresenceState = Qt::UserRole + 1;
constexpr int kRoleServerItemType = Qt::UserRole + 10;
constexpr int kRoleServerId = Qt::UserRole + 11;
constexpr int kRoleServerChannelId = Qt::UserRole + 12;
constexpr int kRoleServerChannelVoice = Qt::UserRole + 13;
constexpr int kRoleIndentPx = Qt::UserRole + 14;
constexpr int kRoleVoiceLive = Qt::UserRole + 15;
constexpr int kRoleWatchOverlay = Qt::UserRole + 16;
constexpr int kRoleDmCallAvatar = Qt::UserRole + 17;

constexpr int kServerHeaderItem = 1;
constexpr int kServerChannelItem = 2;
constexpr int kServerVoiceMemberItem = 3;

constexpr int kPresenceOffline = 0;
constexpr int kPresenceRendezvous = 1;
constexpr int kPresenceDirect = 2;

class ClickableLabel final : public QLabel {
public:
  using QLabel::QLabel;
  std::function<void()> onClick;

protected:
  void mousePressEvent(QMouseEvent* ev) override {
    if (onClick) onClick();
    QLabel::mousePressEvent(ev);
  }
};

class PresenceDotDelegate final : public QStyledItemDelegate {
public:
  explicit PresenceDotDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

  void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override {
    QStyleOptionViewItem opt(option);
    initStyleOption(&opt, index);

    const bool selected = (opt.state & QStyle::State_Selected);
    const int presence = index.data(kRolePresenceState).toInt();

    const bool isVoiceMember = index.data(kRoleServerItemType).toInt() == kServerVoiceMemberItem;
    const bool isLiveSharing = isVoiceMember && index.data(kRoleVoiceLive).toBool();
    const bool hasPresence = index.data(kRolePresenceState).isValid();
    const int dot = (isVoiceMember || !hasPresence) ? 0 : 10;
    const int margin = 8;
    const int indentPx = index.data(kRoleIndentPx).toInt();

    const bool hasIcon = !opt.icon.isNull();
    const int itemType = index.data(kRoleServerItemType).toInt();
    const int icon = hasIcon && opt.decorationSize.isValid()
                         ? std::min(opt.decorationSize.width(), opt.decorationSize.height())
                         : (hasIcon ? 24 : 0);
    QRect iconRect = opt.rect;
    iconRect.setLeft(opt.rect.left() + margin + indentPx);
    iconRect.setRight(iconRect.left() + icon);
    iconRect.setTop(opt.rect.center().y() - icon / 2);
    iconRect.setBottom(iconRect.top() + icon);

    QRect dotRect = opt.rect;
    dotRect.setLeft(dotRect.right() - margin - dot);
    dotRect.setRight(dotRect.left() + dot);
    dotRect.setTop(opt.rect.center().y() - dot / 2);
    dotRect.setBottom(dotRect.top() + dot);

    const int textLeft = margin + indentPx + (hasIcon ? (icon + margin) : 0);
    int rightPad = margin + (dot > 0 ? dot + margin : 0);
    QRect liveRect;
    QString liveText;
    QFont liveFont = opt.font;
    if (isLiveSharing) {
      liveText = "LIVE";
      liveFont.setBold(true);
      liveFont.setPointSize(std::max(8, opt.font.pointSize() - 1));
      const QFontMetrics lfm(liveFont);
      const int liveH = std::max(14, std::min(18, opt.rect.height() - 8));
      const int liveW = std::max(34, lfm.horizontalAdvance(liveText) + 12);
      liveRect = QRect(opt.rect.right() - margin - liveW + 1,
                       opt.rect.center().y() - (liveH / 2),
                       liveW,
                       liveH);
      rightPad += liveW + margin;
    }
    QRect textRect = opt.rect.adjusted(textLeft, 0, -rightPad, 0);

    // Draw background/selection without text.
    QStyleOptionViewItem bg(opt);
    bg.text.clear();
    bg.icon = QIcon();
    const auto* w = opt.widget;
    QStyle* style = w ? w->style() : QApplication::style();
    style->drawControl(QStyle::CE_ItemViewItem, &bg, painter, w);

    painter->save();
    if (hasIcon) {
      if (itemType == kServerChannelItem) {
        QPixmap pm = opt.icon.pixmap(iconRect.size(), selected ? QIcon::Selected : QIcon::Normal, QIcon::Off);
        if (!pm.isNull()) {
          QImage img = pm.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
          QPainter ip(&img);
          ip.setCompositionMode(QPainter::CompositionMode_SourceIn);
          ip.fillRect(img.rect(), opt.palette.color(selected ? QPalette::HighlightedText : QPalette::Text));
          ip.end();
          painter->drawImage(iconRect.topLeft(), img);
        }
      } else {
        opt.icon.paint(painter, iconRect, Qt::AlignCenter, selected ? QIcon::Selected : QIcon::Normal);
      }
    }

    painter->setFont(opt.font);
    painter->setPen(opt.palette.color(selected ? QPalette::HighlightedText : QPalette::Text));
    const QFontMetrics fm(opt.font);
    const auto elided = fm.elidedText(opt.text, Qt::ElideRight, textRect.width());
    painter->drawText(textRect, Qt::AlignVCenter | Qt::AlignLeft, elided);

    if (dot > 0) {
      painter->setRenderHint(QPainter::Antialiasing, true);
      QColor c(120, 120, 120);
      if (presence == kPresenceRendezvous) c = QColor(225, 190, 0);
      if (presence == kPresenceDirect) c = QColor(0, 200, 80);
      painter->setBrush(c);
      painter->setPen(Qt::NoPen);
      painter->drawEllipse(dotRect);
    }
    if (isLiveSharing && !liveRect.isEmpty()) {
      painter->setRenderHint(QPainter::Antialiasing, true);
      painter->setPen(Qt::NoPen);
      painter->setBrush(QColor(237, 66, 69));
      painter->drawRoundedRect(liveRect, 7, 7);
      painter->setFont(liveFont);
      painter->setPen(Qt::white);
      painter->drawText(liveRect, Qt::AlignCenter, liveText);
    }
    painter->restore();
  }
};

QColor colorFromId(const QString& id) {
  // Deterministic color from the peer id.
  uint32_t h = 2166136261u;
  for (const auto ch : id) {
    h ^= static_cast<uint32_t>(ch.unicode());
    h *= 16777619u;
  }
  const int r = 40 + static_cast<int>(h & 0x7F);
  const int g = 40 + static_cast<int>((h >> 8) & 0x7F);
  const int b = 40 + static_cast<int>((h >> 16) & 0x7F);
  return QColor(r, g, b);
}

QPixmap placeholderAvatar(const QString& seed, int size) {
  QPixmap pm(size, size);
  pm.fill(Qt::transparent);
  QPainter p(&pm);
  p.setRenderHint(QPainter::Antialiasing, true);
  p.setPen(Qt::NoPen);
  p.setBrush(colorFromId(seed));
  p.drawEllipse(QRectF(0, 0, size, size));

  QFont f = p.font();
  f.setBold(true);
  f.setPointSize(std::max(10, size / 3));
  p.setFont(f);
  p.setPen(Qt::white);
  const QString letter = seed.isEmpty() ? "?" : seed.left(1).toUpper();
  p.drawText(QRect(0, 0, size, size), Qt::AlignCenter, letter);
  return pm;
}

QPixmap loadAvatarOrPlaceholder(const QString& seed, const QString& path, int size) {
  if (!path.isEmpty() && QFileInfo::exists(path)) {
    QPixmap pm(path);
    if (!pm.isNull()) return pm.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  }
  return placeholderAvatar(seed, size);
}

QColor dominantColorFromAvatar(const QPixmap& avatar, const QString& fallbackSeed) {
  if (avatar.isNull()) return colorFromId(fallbackSeed);
  QImage img = avatar.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
  if (img.isNull()) return colorFromId(fallbackSeed);
  img = img.scaled(QSize(40, 40), Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  if (img.isNull()) return colorFromId(fallbackSeed);

  quint64 rSum = 0;
  quint64 gSum = 0;
  quint64 bSum = 0;
  quint64 wSum = 0;
  for (int y = 0; y < img.height(); ++y) {
    const auto* line = reinterpret_cast<const QRgb*>(img.scanLine(y));
    for (int x = 0; x < img.width(); ++x) {
      const QColor c = QColor::fromRgba(line[x]);
      const int a = c.alpha();
      if (a < 16) continue;
      rSum += static_cast<quint64>(c.red()) * static_cast<quint64>(a);
      gSum += static_cast<quint64>(c.green()) * static_cast<quint64>(a);
      bSum += static_cast<quint64>(c.blue()) * static_cast<quint64>(a);
      wSum += static_cast<quint64>(a);
    }
  }
  if (wSum == 0) return colorFromId(fallbackSeed);

  QColor out(static_cast<int>(rSum / wSum), static_cast<int>(gSum / wSum), static_cast<int>(bSum / wSum));
  int h = 0;
  int s = 0;
  int l = 0;
  int a = 255;
  out.getHsl(&h, &s, &l, &a);
  s = std::clamp(s + 18, 50, 220);
  l = std::clamp(l - 20, 45, 150);
  return QColor::fromHsl(h < 0 ? 0 : h, s, l, 255);
}

QPixmap roundAvatarPixmap(const QPixmap& avatar, int size) {
  if (size < 8) size = 8;
  QPixmap src = avatar;
  if (src.isNull()) return {};
  src = src.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  QPixmap out(size, size);
  out.fill(Qt::transparent);

  QPainter p(&out);
  p.setRenderHint(QPainter::Antialiasing, true);
  QPainterPath clip;
  clip.addEllipse(QRectF(0.5, 0.5, size - 1.0, size - 1.0));
  p.setClipPath(clip);
  p.drawPixmap(0, 0, src);
  return out;
}

QPixmap dmCallAvatarTile(const QString& seed, const QString& avatarPath, QSize size, bool self) {
  if (size.width() < 40) size.setWidth(40);
  if (size.height() < 40) size.setHeight(40);
  QPixmap pm(size);
  pm.fill(Qt::transparent);

  const int avatarSize = std::max(48, std::min(size.width(), size.height()) - 16);
  const QPixmap rawAvatar = loadAvatarOrPlaceholder(seed, avatarPath, avatarSize);
  const QPixmap avatar = roundAvatarPixmap(rawAvatar, avatarSize);
  const QRect avatarRect((size.width() - avatar.width()) / 2,
                         (size.height() - avatar.height()) / 2,
                         avatar.width(),
                         avatar.height());

  QPainter p(&pm);
  p.setRenderHint(QPainter::Antialiasing, true);
  p.drawPixmap(avatarRect, avatar);
  p.setBrush(Qt::NoBrush);
  p.setPen(self ? QColor(62, 130, 247, 220) : QColor(255, 255, 255, 70));
  p.drawEllipse(avatarRect.adjusted(0, 0, -1, -1));
  return pm;
}

QIcon iconFromSvg(const char* svgText, const QString& colorHex = {}) {
  if (!svgText) return {};
  QByteArray data(svgText);
  if (!colorHex.trimmed().isEmpty()) {
    data.replace("currentColor", colorHex.trimmed().toUtf8());
  }
  QPixmap pm;
  if (!pm.loadFromData(data, "SVG")) return {};
  return QIcon(pm);
}

QIcon discordMicIcon(bool muted, bool dark) {
  static const char* kMicOnSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(12 8.5)"><path fill="currentColor" d="M-4,-1.4600000381469727 C-4,-3.6689999103546143 -2.2090001106262207,-5.460000038146973 0,-5.460000038146973 C2.2090001106262207,-5.460000038146973 4,-3.6689999103546143 4,-1.4600000381469727 C4,-1.4600000381469727 4,2.5 4,2.5 C4,4.709000110626221 2.2090001106262207,6.5 0,6.5 C-2.2090001106262207,6.5 -4,4.709000110626221 -4,2.5 C-4,2.5 -4,-1.4600000381469727 -4,-1.4600000381469727z"/></g>
  <g transform="translate(12 14)"><path d="M-7,-3 C-7,0.8659999966621399 -3.865999937057495,4 0,4 C3.865999937057495,4 7,0.8659999966621399 7,-3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></g>
  <g transform="translate(12 20)"><path fill="currentColor" d="M-1,-2 C-1,-2.2760000228881836 -0.7760000228881836,-2.5 -0.5,-2.5 C-0.5,-2.5 0.5,-2.5 0.5,-2.5 C0.7760000228881836,-2.5 1,-2.2760000228881836 1,-2 C1,-2 1,2 1,2 C1,2.2760000228881836 0.7760000228881836,2.5 0.5,2.5 C0.5,2.5 -0.5,2.5 -0.5,2.5 C-0.7760000228881836,2.5 -1,2.2760000228881836 -1,2 C-1,2 -1,-2 -1,-2z"/></g>
  <g transform="translate(12 22)"><path fill="currentColor" d="M3,-1 C3.552000045776367,-1 4,-0.5519999861717224 4,0 C4,0.5519999861717224 3.552000045776367,1 3,1 C3,1 -3,1 -3,1 C-3.552000045776367,1 -4,0.5519999861717224 -4,0 C-4,-0.5519999861717224 -3.552000045776367,-1 -3,-1 C-3,-1 3,-1 3,-1z"/></g>
  </svg>)SVG";
  static const char* kMicOffSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(12 8.5)"><path fill="currentColor" d="M-4,-1.4600000381469727 C-4,-3.6689999103546143 -2.2090001106262207,-5.460000038146973 0,-5.460000038146973 C2.2090001106262207,-5.460000038146973 4,-3.6689999103546143 4,-1.4600000381469727 C4,-1.4600000381469727 4,2.5 4,2.5 C4,4.709000110626221 2.2090001106262207,6.5 0,6.5 C-2.2090001106262207,6.5 -4,4.709000110626221 -4,2.5 C-4,2.5 -4,-1.4600000381469727 -4,-1.4600000381469727z"/></g>
  <g transform="translate(12 14)"><path d="M-7,-3 C-7,0.8659999966621399 -3.865999937057495,4 0,4 C3.865999937057495,4 7,0.8659999966621399 7,-3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></g>
  <g transform="translate(12 20)"><path fill="currentColor" d="M-1,-2 C-1,-2.2760000228881836 -0.7760000228881836,-2.5 -0.5,-2.5 C-0.5,-2.5 0.5,-2.5 0.5,-2.5 C0.7760000228881836,-2.5 1,-2.2760000228881836 1,-2 C1,-2 1,2 1,2 C1,2.2760000228881836 0.7760000228881836,2.5 0.5,2.5 C0.5,2.5 -0.5,2.5 -0.5,2.5 C-0.7760000228881836,2.5 -1,2.2760000228881836 -1,2 C-1,2 -1,-2 -1,-2z"/></g>
  <g transform="translate(12 22)"><path fill="currentColor" d="M3,-1 C3.552000045776367,-1 4,-0.5519999861717224 4,0 C4,0.5519999861717224 3.552000045776367,1 3,1 C3,1 -3,1 -3,1 C-3.552000045776367,1 -4,0.5519999861717224 -4,0 C-4,-0.5519999861717224 -3.552000045776367,-1 -3,-1 C-3,-1 3,-1 3,-1z"/></g>
  <g transform="translate(12 12)"><path d="M-10,10 L10,-10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></g>
  </svg>)SVG";
  static const QIcon onDark = iconFromSvg(kMicOnSvg, "#f2f3f5");
  static const QIcon onLight = iconFromSvg(kMicOnSvg, "#1d232f");
  static const QIcon offDark = iconFromSvg(kMicOffSvg, "#f2f3f5");
  static const QIcon offLight = iconFromSvg(kMicOffSvg, "#1d232f");
  const QIcon& on = dark ? onDark : onLight;
  const QIcon& off = dark ? offDark : offLight;
  return muted ? off : on;
}

QIcon discordCameraIcon(bool offState, bool dark, bool activeOverlay = false) {
  static const char* kCamOnSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(9.5 12)"><path fill="currentColor" d="M-5.5,-8 C-5.5,-8 -1.253999948501587,-8 -1.253999948501587,-8 C-1.253999948501587,-8 5.5,-8 5.5,-8 C7.1570000648498535,-8 8.5,-6.6570000648498535 8.5,-5 C8.5,-5 8.5,5 8.5,5 C8.5,6.6570000648498535 7.1570000648498535,8 5.5,8 C5.5,8 0.13199999928474426,8 0.13199999928474426,8 C0.13199999928474426,8 -5.5,8 -5.5,8 C-7.1570000648498535,8 -8.5,6.6570000648498535 -8.5,5 C-8.5,5 -8.5,-5 -8.5,-5 C-8.5,-6.6570000648498535 -7.1570000648498535,-8 -5.5,-8z"/></g>
  <g transform="translate(20.5 12)"><path fill="currentColor" d="M-2.5,-2.881999969482422 C-2.5,-3.260999917984009 -2.2860000133514404,-3.6070001125335693 -1.9470000267028809,-3.7760000228881836 C-1.9470000267028809,-3.7760000228881836 1.0529999732971191,-5.276000022888184 1.0529999732971191,-5.276000022888184 C1.718000054359436,-5.609000205993652 2.5,-5.125 2.5,-4.381999969482422 C2.5,-4.381999969482422 2.5,4.381999969482422 2.5,4.381999969482422 C2.5,5.125 1.718000054359436,5.609000205993652 1.0529999732971191,5.276000022888184 C1.0529999732971191,5.276000022888184 -1.9470000267028809,3.7760000228881836 -1.9470000267028809,3.7760000228881836 C-2.2860000133514404,3.6070001125335693 -2.5,3.260999917984009 -2.5,2.881999969482422 C-2.5,2.881999969482422 -3.1675777435302734,-0.012422150000929832 -3.1675777435302734,-0.012422150000929832 C-3.1675777435302734,-0.012422150000929832 -2.5,-2.881999969482422 -2.5,-2.881999969482422z"/></g>
  </svg>)SVG";
  static const char* kCamOffSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(9.5 12)"><path fill="currentColor" d="M-5.5,-8 C-5.5,-8 -1.253999948501587,-8 -1.253999948501587,-8 C-1.253999948501587,-8 5.5,-8 5.5,-8 C7.1570000648498535,-8 8.5,-6.6570000648498535 8.5,-5 C8.5,-5 8.5,5 8.5,5 C8.5,6.6570000648498535 7.1570000648498535,8 5.5,8 C5.5,8 0.13199999928474426,8 0.13199999928474426,8 C0.13199999928474426,8 -5.5,8 -5.5,8 C-7.1570000648498535,8 -8.5,6.6570000648498535 -8.5,5 C-8.5,5 -8.5,-5 -8.5,-5 C-8.5,-6.6570000648498535 -7.1570000648498535,-8 -5.5,-8z"/></g>
  <g transform="translate(20.5 12)"><path fill="currentColor" d="M-2.5,-2.881999969482422 C-2.5,-3.260999917984009 -2.2860000133514404,-3.6070001125335693 -1.9470000267028809,-3.7760000228881836 C-1.9470000267028809,-3.7760000228881836 1.0529999732971191,-5.276000022888184 1.0529999732971191,-5.276000022888184 C1.718000054359436,-5.609000205993652 2.5,-5.125 2.5,-4.381999969482422 C2.5,-4.381999969482422 2.5,4.381999969482422 2.5,4.381999969482422 C2.5,5.125 1.718000054359436,5.609000205993652 1.0529999732971191,5.276000022888184 C1.0529999732971191,5.276000022888184 -1.9470000267028809,3.7760000228881836 -1.9470000267028809,3.7760000228881836 C-2.2860000133514404,3.6070001125335693 -2.5,3.260999917984009 -2.5,2.881999969482422 C-2.5,2.881999969482422 -3.1675777435302734,-0.012422150000929832 -3.1675777435302734,-0.012422150000929832 C-3.1675777435302734,-0.012422150000929832 -2.5,-2.881999969482422 -2.5,-2.881999969482422z"/></g>
  <g transform="translate(12 12)"><path d="M-10,10 L10,-10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></g>
  </svg>)SVG";
  static const QIcon onDark = iconFromSvg(kCamOnSvg, "#f2f3f5");
  static const QIcon onLight = iconFromSvg(kCamOnSvg, "#1d232f");
  static const QIcon offDark = iconFromSvg(kCamOffSvg, "#f2f3f5");
  static const QIcon offLight = iconFromSvg(kCamOffSvg, "#1d232f");
  static const QIcon onAccent = iconFromSvg(kCamOnSvg, "#57f287");
  const QIcon& on = activeOverlay ? onAccent : (dark ? onDark : onLight);
  const QIcon& off = dark ? offDark : offLight;
  return offState ? off : on;
}

QIcon discordScreenIcon(bool dark, bool activeOverlay = false) {
  static const char* kScreenSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(12 12)"><path fill="currentColor" d="M-10,-7 C-10,-8.656999588012695 -8.656999588012695,-10 -7,-10 C-7,-10 7,-10 7,-10 C8.656999588012695,-10 10,-8.656999588012695 10,-7 C10,-7 10,1 10,1 C10,2.6570000648498535 8.656999588012695,4 7,4 C7,4 -7,4 -7,4 C-8.656999588012695,4 -10,2.6570000648498535 -10,1 C-10,1 -10,-7 -10,-7z"/></g>
  <g transform="translate(12 12)"><path fill="currentColor" d="M1,7.5 C1,7.776000022888184 1.2239999771118164,8 1.5,8 C1.5,8 3,8 3,8 C3.552000045776367,8 4,8.447999954223633 4,9 C4,9.552000045776367 3.552000045776367,10 3,10 C3,10 -3,10 -3,10 C-3.552000045776367,10 -4,9.552000045776367 -4,9 C-4,8.447999954223633 -3.552000045776367,8 -3,8 C-3,8 -1.5,8 -1.5,8 C-1.2239999771118164,8 -1,7.776000022888184 -1,7.5 C-1,7.5 -1,5.5 -1,5.5 C-1,5.223999977111816 -0.7760000228881836,5 -0.5,5 C-0.5,5 0.5,5 0.5,5 C0.7760000228881836,5 1,5.223999977111816 1,5.5 C1,5.5 1,7.5 1,7.5z"/></g>
  <g transform="translate(12 12)"><path fill="currentColor" d="M6,-4 C6,-4.264999866485596 5.894999980926514,-4.519000053405762 5.706999778747559,-4.706999778747559 C5.706999778747559,-4.706999778747559 2.7070000171661377,-7.706999778747559 2.7070000171661377,-7.706999778747559 C2.315999984741211,-8.097999572753906 1.684000015258789,-8.097999572753906 1.2929999828338623,-7.706999778747559 C0.9020000100135803,-7.315999984741211 0.9020000100135803,-6.684000015258789 1.2929999828338623,-6.293000221252441 C1.2929999828338623,-6.293000221252441 2.5859999656677246,-5 2.5859999656677246,-5 C2.5859999656677246,-5 1,-5 1,-5 C-2.313999891281128,-5 -5,-2.313999891281128 -5,1 C-5,1.5520000457763672 -4.552000045776367,2 -4,2 C-3.447999954223633,2 -3,1.5520000457763672 -3,1 C-3,-1.2089999914169312 -1.2089999914169312,-3 1,-3 C1,-3 2.5859999656677246,-3 2.5859999656677246,-3 C2.5859999656677246,-3 1.2929999828338623,-1.7070000171661377 1.2929999828338623,-1.7070000171661377 C0.9020000100135803,-1.315999984741211 0.9020000100135803,-0.6840000152587891 1.2929999828338623,-0.2930000126361847 C1.684000015258789,0.09799999743700027 2.315999984741211,0.09799999743700027 2.7070000171661377,-0.2930000126361847 C2.7070000171661377,-0.2930000126361847 5.706999778747559,-3.2929999828338623 5.706999778747559,-3.2929999828338623 C5.894999980926514,-3.4809999465942383 6,-3.734999895095825 6,-4z"/></g>
  </svg>)SVG";
  static const QIcon darkIcon = iconFromSvg(kScreenSvg, "#f2f3f5");
  static const QIcon lightIcon = iconFromSvg(kScreenSvg, "#1d232f");
  static const QIcon accentIcon = iconFromSvg(kScreenSvg, "#57f287");
  const QIcon& icon = activeOverlay ? accentIcon : (dark ? darkIcon : lightIcon);
  return icon;
}

QIcon discordHangupIcon(bool dark) {
  static const char* kHangupSvg = R"SVG(<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none">
  <g transform="translate(12 12.61)"><path fill="currentColor" d="M9.335000038146973,-1.8179999589920044 C4.184999942779541,-6.9670000076293945 -4.164000034332275,-6.9670000076293945 -9.312999725341797,-1.8179999589920044 C-11.690999984741211,0.5609999895095825 -11.35099983215332,3.6040000915527344 -9.555999755859375,5.39900016784668 C-9.300999641418457,5.6539998054504395 -8.909000396728516,5.7129998207092285 -8.59000015258789,5.544000148773193 C-8.59000015258789,5.544000148773193 -4.269999980926514,3.256999969482422 -4.269999980926514,3.256999969482422 C-3.871000051498413,3.0460000038146973 -3.683000087738037,2.5769999027252197 -3.8259999752044678,2.1489999294281006 C-3.8259999752044678,2.1489999294281006 -4.558000087738037,-0.04600000008940697 -4.558000087738037,-0.04600000008940697 C-1.8250000476837158,-1.9980000257492065 1.8459999561309814,-1.9980000257492065 4.578999996185303,-0.04600000008940697 C4.578999996185303,-0.04600000008940697 3.815000057220459,2.757999897003174 3.815000057220459,2.757999897003174 C3.693000078201294,3.2070000171661377 3.9240000247955322,3.677000045776367 4.354000091552734,3.8540000915527344 C4.354000091552734,3.8540000915527344 8.63599967956543,5.617000102996826 8.63599967956543,5.617000102996826 C8.946000099182129,5.744999885559082 9.303000450134277,5.672999858856201 9.539999961853027,5.435999870300293 C11.331999778747559,3.6440000534057617 11.708999633789062,0.5559999942779541 9.335000038146973,-1.8179999589920044z"/></g>
  </svg>)SVG";
  static const QIcon darkIcon = iconFromSvg(kHangupSvg, "#f2f3f5");
  static const QIcon lightIcon = iconFromSvg(kHangupSvg, "#1d232f");
  const QIcon& icon = dark ? darkIcon : lightIcon;
  return icon;
}

QString callControlsStyleSheet(bool dark) {
  if (dark) {
    return QStringLiteral(
        "QWidget#callControlsBar { background: transparent; border: none; }"
        "QPushButton#callMicButton, QPushButton#callCamButton, QPushButton#callShareButton {"
        "  border-radius: 9px; padding: 0; background: #2f3136; color: #f2f3f5; border: 1px solid #3e4147;"
        "}"
        "QPushButton#callMicButton:checked {"
        "  background: #da4e5a; border-color: #ef6a73; color: #ffffff;"
        "}"
        "QPushButton#callCamButton:checked, QPushButton#callShareButton:checked {"
        "  background: #3ba55d; border-color: #43b86a; color: #ffffff;"
        "}"
        "QToolButton#callMicCaretButton, QToolButton#callCamCaretButton {"
        "  border-radius: 9px; padding: 0; background: #2f3136; color: #f2f3f5; border: 1px solid #3e4147;"
        "}"
        "QToolButton#callMicCaretButton[danger=\"true\"] {"
        "  background: #da4e5a; border-color: #ef6a73; color: #ffffff;"
        "}"
        "QPushButton#callHangupButton {"
        "  border-radius: 9px; padding: 0; background: #d84f5a; color: #ffffff; border: 1px solid #e0616d;"
        "}"
        "QPushButton#callHangupButton:hover { background: #e0616d; }");
  }
  return QStringLiteral(
      "QWidget#callControlsBar { background: transparent; border: none; }"
      "QPushButton#callMicButton, QPushButton#callCamButton, QPushButton#callShareButton {"
      "  border-radius: 9px; padding: 0; background: #eef1f7; color: #1d232f; border: 1px solid #c8d1e1;"
      "}"
      "QPushButton#callMicButton:checked {"
      "  background: #da4e5a; color: #ffffff; border-color: #c94550;"
      "}"
      "QPushButton#callCamButton:checked, QPushButton#callShareButton:checked {"
      "  background: #3ba55d; color: #ffffff; border-color: #43b86a;"
      "}"
      "QToolButton#callMicCaretButton, QToolButton#callCamCaretButton {"
      "  border-radius: 9px; padding: 0; background: #eef1f7; color: #1d232f; border: 1px solid #c8d1e1;"
      "}"
      "QToolButton#callMicCaretButton[danger=\"true\"] {"
      "  background: #da4e5a; color: #ffffff; border-color: #c94550;"
      "}"
      "QPushButton#callHangupButton {"
      "  border-radius: 9px; padding: 0; background: #df4f56; color: #ffffff; border: 1px solid #c74248;"
      "}"
      "QPushButton#callHangupButton:hover { background: #cb4048; }");
}

QPixmap videoPlaceholderCard(const QString& seed, const QString& name, const QString& avatarPath, QSize size) {
  if (size.width() < 40) size.setWidth(40);
  if (size.height() < 40) size.setHeight(40);
  QPixmap pm(size);
  pm.fill(Qt::transparent);

  QPainter p(&pm);
  p.setRenderHint(QPainter::Antialiasing, true);
  const QRect r = pm.rect().adjusted(1, 1, -1, -1);
  const QPixmap rawAvatar = loadAvatarOrPlaceholder(seed, avatarPath, 128);
  const QColor bg = dominantColorFromAvatar(rawAvatar, seed);
  const QColor bgDark = bg.darker(145);
  const QColor bgLight = bg.lighter(118);
  QLinearGradient grad(r.topLeft(), r.bottomRight());
  grad.setColorAt(0.0, bgLight);
  grad.setColorAt(1.0, bgDark);
  p.setPen(QColor(255, 255, 255, 24));
  p.setBrush(grad);
  p.drawRoundedRect(r, 8, 8);

  QLinearGradient dimGrad(QPointF(0, r.top()), QPointF(0, r.bottom()));
  dimGrad.setColorAt(0.0, QColor(0, 0, 0, 28));
  dimGrad.setColorAt(1.0, QColor(0, 0, 0, 92));
  p.setPen(Qt::NoPen);
  p.setBrush(dimGrad);
  p.drawRoundedRect(r, 8, 8);

  const int avatarSize = std::min(size.width(), size.height()) / 3;
  const int finalAvatarSize = std::max(48, avatarSize);
  const QPixmap avatar = roundAvatarPixmap(rawAvatar, finalAvatarSize);
  const QRect avatarRect((size.width() - avatar.width()) / 2,
                         std::max(10, size.height() / 2 - avatar.height() / 2 - 10),
                         avatar.width(),
                         avatar.height());
  p.drawPixmap(avatarRect, avatar);

  QFont f = p.font();
  f.setBold(true);
  f.setPointSize(std::max(9, std::min(14, size.width() / 28)));
  p.setFont(f);
  p.setPen(QColor(245, 245, 245));
  const QString text = name.isEmpty() ? "No video" : name;
  const QRect textRect(10, avatarRect.bottom() + 8, size.width() - 20, size.height() - avatarRect.bottom() - 14);
  p.drawText(textRect, Qt::AlignHCenter | Qt::AlignTop, text);
  return pm;
}

QPixmap scaledCover(const QImage& img, QSize target) {
  if (img.isNull()) return {};
  if (target.width() < 2 || target.height() < 2) return QPixmap::fromImage(img);
  QPixmap scaled = QPixmap::fromImage(img).scaled(target, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
  const int x = std::max(0, (scaled.width() - target.width()) / 2);
  const int y = std::max(0, (scaled.height() - target.height()) / 2);
  return scaled.copy(x, y, target.width(), target.height());
}

QPixmap roundedCover(const QImage& img, QSize target, int radius = 8) {
  QPixmap covered = scaledCover(img, target);
  if (covered.isNull()) return {};
  QPixmap out(target);
  out.fill(Qt::transparent);
  QPainter p(&out);
  p.setRenderHint(QPainter::Antialiasing, true);
  QPainterPath clip;
  clip.addRoundedRect(QRectF(0.5, 0.5, target.width() - 1.0, target.height() - 1.0), radius, radius);
  p.setClipPath(clip);
  p.drawPixmap(0, 0, covered);
  p.setClipping(false);
  p.setPen(QColor(90, 90, 90, 180));
  p.setBrush(Qt::NoBrush);
  p.drawRoundedRect(QRectF(0.5, 0.5, target.width() - 1.0, target.height() - 1.0), radius, radius);
  return out;
}

QPixmap roundedContain(const QImage& img, QSize target, int radius = 8) {
  if (img.isNull() || target.width() < 2 || target.height() < 2) return {};
  QPixmap out(target);
  out.fill(Qt::transparent);
  QPainter p(&out);
  p.setRenderHint(QPainter::Antialiasing, true);

  QPainterPath clip;
  clip.addRoundedRect(QRectF(0.5, 0.5, target.width() - 1.0, target.height() - 1.0), radius, radius);
  p.setClipPath(clip);
  p.fillRect(out.rect(), QColor(10, 10, 10));

  QPixmap scaled = QPixmap::fromImage(img).scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation);
  const int x = (target.width() - scaled.width()) / 2;
  const int y = (target.height() - scaled.height()) / 2;
  p.drawPixmap(x, y, scaled);

  p.setClipping(false);
  p.setPen(QColor(90, 90, 90, 180));
  p.setBrush(Qt::NoBrush);
  p.drawRoundedRect(QRectF(0.5, 0.5, target.width() - 1.0, target.height() - 1.0), radius, radius);
  return out;
}

QPixmap withWatchStreamOverlay(const QPixmap& base) {
  if (base.isNull()) return {};
  QPixmap out = base.copy();
  QPainter p(&out);
  p.setRenderHint(QPainter::Antialiasing, true);

  const QRectF card(1.0, 1.0, out.width() - 2.0, out.height() - 2.0);
  QPainterPath clip;
  clip.addRoundedRect(card, 8, 8);
  p.setClipPath(clip);
  p.fillRect(out.rect(), QColor(0, 0, 0, 95));
  p.setClipping(false);

  const QString label = "Watch Stream";
  QFont font = p.font();
  font.setBold(true);
  font.setPointSize(std::max(9, std::min(13, out.width() / 24)));
  p.setFont(font);
  QFontMetrics fm(font);

  const int btnH = std::max(32, std::min(42, out.height() / 5));
  const int btnW = std::max(138, std::min(out.width() - 24, fm.horizontalAdvance(label) + 44));
  const QRect btnRect((out.width() - btnW) / 2, (out.height() - btnH) / 2, btnW, btnH);

  p.setPen(QColor(220, 220, 220, 70));
  p.setBrush(QColor(44, 47, 51, 235));
  p.drawRoundedRect(btnRect, 10, 10);
  p.setPen(QColor(245, 245, 245));
  p.drawText(btnRect, Qt::AlignCenter, label);
  return out;
}

QString chooseDisplayForShare(QWidget* parent, const QString& currentDisplayName) {
  const auto screens = QGuiApplication::screens();
  if (screens.isEmpty()) return {};

  QDialog dlg(parent);
  dlg.setWindowTitle("Choose display to share");
  dlg.resize(760, 460);

  auto* root = new QVBoxLayout(&dlg);
  auto* label = new QLabel("Select a display:", &dlg);
  root->addWidget(label);

  auto* list = new QListWidget(&dlg);
  list->setViewMode(QListView::IconMode);
  list->setResizeMode(QListView::Adjust);
  list->setMovement(QListView::Static);
  list->setWrapping(true);
  list->setWordWrap(true);
  list->setSpacing(10);
  list->setIconSize(QSize(280, 158));
  list->setGridSize(QSize(300, 196));
  list->setSelectionMode(QAbstractItemView::SingleSelection);
  root->addWidget(list, 1);

  for (auto* screen : screens) {
    if (!screen) continue;
    const QRect g = screen->geometry();
    const QString title = QString("%1 (%2x%3)")
                              .arg(screen->name().isEmpty() ? QStringLiteral("Display") : screen->name())
                              .arg(g.width())
                              .arg(g.height());
    QPixmap shot = screen->grabWindow(0);
    if (shot.isNull()) {
      shot = QPixmap(280, 158);
      shot.fill(QColor(30, 30, 30));
      QPainter p(&shot);
      p.setPen(QColor(220, 220, 220));
      p.drawText(shot.rect(), Qt::AlignCenter, title);
    }
    const QPixmap preview = roundedCover(shot.toImage(), QSize(280, 158), 8);
    auto* item = new QListWidgetItem(QIcon(preview), title);
    item->setData(Qt::UserRole, screen->name());
    list->addItem(item);
  }

  if (list->count() == 0) return {};

  int pick = -1;
  if (!currentDisplayName.trimmed().isEmpty()) {
    for (int i = 0; i < list->count(); ++i) {
      if (list->item(i)->data(Qt::UserRole).toString() == currentDisplayName) {
        pick = i;
        break;
      }
    }
  }
  if (pick < 0) pick = 0;
  list->setCurrentRow(pick);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
  root->addWidget(buttons);
  QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  QObject::connect(list, &QListWidget::itemDoubleClicked, &dlg, [&dlg](QListWidgetItem*) { dlg.accept(); });

  if (dlg.exec() != QDialog::Accepted) return {};
  if (!list->currentItem()) return {};
  return list->currentItem()->data(Qt::UserRole).toString();
}

QString renderLine(const QString& stamp, const QString& who, const QString& text) {
  static const QRegularExpression kUrlRe(R"((https?://[^\s<>"']+))", QRegularExpression::CaseInsensitiveOption);

  auto escapePlain = [](const QString& s) -> QString {
    QString out = s.toHtmlEscaped();
    out.replace('\n', "<br/>");
    return out;
  };

  auto formatMessage = [&](const QString& raw) -> QString {
    QString html;
    int pos = 0;
    auto it = kUrlRe.globalMatch(raw);
    while (it.hasNext()) {
      const auto m = it.next();
      const int start = m.capturedStart(1);
      const int end = m.capturedEnd(1);
      if (start < pos) continue;
      html += escapePlain(raw.mid(pos, start - pos));

      const QString urlText = m.captured(1);
      const QString safeUrl = urlText.toHtmlEscaped();
      const QUrl url(urlText);
      const QString path = url.path().toLower();
      const bool isHttp = url.isValid() && (url.scheme() == "http" || url.scheme() == "https");
      const bool isGif = isHttp && path.endsWith(".gif");

      if (isGif) {
        html += QString("<a href=\"%1\">%1</a><br/>"
                        "<img src=\"%1\" style=\"max-width:320px; max-height:320px; border-radius:6px;\"/>")
                    .arg(safeUrl);
      } else {
        html += QString("<a href=\"%1\">%1</a>").arg(safeUrl);
      }
      pos = end;
    }
    html += escapePlain(raw.mid(pos));
    return html;
  };

  return QString("[%1] <b>%2</b>: %3").arg(stamp, who.toHtmlEscaped(), formatMessage(text));
}

QString renderServerLine(const QString& stamp,
                         const QString& who,
                         const QString& text,
                         bool unknownUser,
                         bool verified) {
  static const QRegularExpression kUrlRe(R"((https?://[^\s<>"']+))", QRegularExpression::CaseInsensitiveOption);
  auto escapePlain = [](const QString& s) -> QString {
    QString out = s.toHtmlEscaped();
    out.replace('\n', "<br/>");
    return out;
  };
  auto formatMessage = [&](const QString& raw) -> QString {
    QString html;
    int pos = 0;
    auto it = kUrlRe.globalMatch(raw);
    while (it.hasNext()) {
      const auto m = it.next();
      const int start = m.capturedStart(1);
      const int end = m.capturedEnd(1);
      if (start < pos) continue;
      html += escapePlain(raw.mid(pos, start - pos));

      const QString urlText = m.captured(1);
      const QString safeUrl = urlText.toHtmlEscaped();
      const QUrl url(urlText);
      const QString path = url.path().toLower();
      const bool isHttp = url.isValid() && (url.scheme() == "http" || url.scheme() == "https");
      const bool isGif = isHttp && path.endsWith(".gif");

      if (isGif) {
        html += QString("<a href=\"%1\">%1</a><br/>"
                        "<img src=\"%1\" style=\"max-width:320px; max-height:320px; border-radius:6px;\"/>")
                    .arg(safeUrl);
      } else {
        html += QString("<a href=\"%1\">%1</a>").arg(safeUrl);
      }
      pos = end;
    }
    html += escapePlain(raw.mid(pos));
    return html;
  };

  QString whoHtml = unknownUser ? QString("<i>%1</i>").arg(who.toHtmlEscaped())
                                : QString("<b>%1</b>").arg(who.toHtmlEscaped());
  const QString marker = verified ? "&#10003;" : "&#9888;";
  const QString markerColor = verified ? "#2e7d32" : "#d18a00";
  return QString("[%1] <span style=\"color:%2;\">%3</span> %4: %5")
      .arg(stamp, markerColor, marker, whoHtml, formatMessage(text));
}

QString makeStamp(int hh, int mm) {
  if (hh < 0) hh = 0;
  if (hh > 23) hh = 23;
  if (mm < 0) mm = 0;
  if (mm > 59) mm = 59;

  char out[6];
  out[0] = static_cast<char>('0' + (hh / 10));
  out[1] = static_cast<char>('0' + (hh % 10));
  out[2] = ':';
  out[3] = static_cast<char>('0' + (mm / 10));
  out[4] = static_cast<char>('0' + (mm % 10));
  out[5] = '\0';
  return QString::fromLatin1(out, 5);
}

QString nowStamp() {
  const std::time_t now = std::time(nullptr);
  if (now <= 0) return makeStamp(0, 0);
  std::tm tm {};
#if defined(_WIN32)
  if (localtime_s(&tm, &now) != 0) return makeStamp(0, 0);
#else
  if (!localtime_r(&now, &tm)) return makeStamp(0, 0);
#endif
  return makeStamp(tm.tm_hour, tm.tm_min);
}

QString stampFromUtcMs(qint64 tsMs) {
  if (tsMs <= 0) return nowStamp();
  // Guard against corrupted/out-of-range timestamps: some Qt timezone conversions can misbehave on extreme values.
  constexpr qint64 kMin = 946684800000LL;   // 2000-01-01T00:00:00Z
  constexpr qint64 kMax = 4102444800000LL;  // 2100-01-01T00:00:00Z
  if (tsMs < kMin || tsMs > kMax) return nowStamp();

  // Avoid Qt timezone/date conversions entirely (we've observed crashes in some environments).
  // Render a simple UTC HH:MM from epoch milliseconds.
  const qint64 totalSecs = tsMs / 1000;
  const qint64 daySecs = totalSecs % 86400;
  const int hh = static_cast<int>(daySecs / 3600);
  const int mm = static_cast<int>((daySecs % 3600) / 60);
  return makeStamp(hh, mm);
}

QString friendDisplay(const Profile::FriendEntry& e) {
  if (!e.alias.isEmpty()) return e.alias;
  if (!e.name.isEmpty()) return e.name;
  return e.id.left(14) + "...";
}

QString statusTag(Profile::FriendStatus s) {
  switch (s) {
    case Profile::FriendStatus::OutgoingPending:
      return " (pending)";
    case Profile::FriendStatus::IncomingPending:
      return " (request)";
    default:
      return "";
  }
}

ChatBackend::VoiceSettings voiceSettingsFromProfile(const Profile::AudioSettings& a,
                                                    const Profile::VideoSettings& vcfg,
                                                    const Profile::ScreenSettings& scfg,
                                                    bool micMuted,
                                                    bool webcamEnabled,
                                                    bool screenShareEnabled,
                                                    const QString& screenDisplayName) {
  ChatBackend::VoiceSettings v;
  v.inputDeviceIdHex = a.inputDeviceIdHex;
  v.outputDeviceIdHex = a.outputDeviceIdHex;
  v.micVolume = micMuted ? 0 : a.micVolume;
  v.speakerVolume = a.speakerVolume;
  v.bitrate = a.bitrate;
  v.frameMs = a.frameMs;
  v.channels = (a.channels == 2) ? 2 : 1;
  if (screenShareEnabled && !screenDisplayName.trimmed().isEmpty()) {
    int screenW = scfg.width;
    int screenH = scfg.height;
    if (screenW <= 0 || screenH <= 0) {
      QScreen* chosen = nullptr;
      for (auto* screen : QGuiApplication::screens()) {
        if (!screen) continue;
        if (screen->name() == screenDisplayName.trimmed()) {
          chosen = screen;
          break;
        }
      }
      if (!chosen) chosen = QGuiApplication::primaryScreen();
      if (chosen) {
        const QRect g = chosen->geometry();
        screenW = g.width();
        screenH = g.height();
      }
    }
    if (screenW <= 0) screenW = 1280;
    if (screenH <= 0) screenH = 720;
    v.videoDevicePath = QString("screen://%1").arg(screenDisplayName.trimmed());
    v.videoFourcc = "RGB3";
    v.videoWidth = screenW;
    v.videoHeight = screenH;
    v.videoFpsNum = scfg.fpsNum;
    v.videoFpsDen = scfg.fpsDen;
    v.videoCodec = scfg.codec.trimmed().toLower();
    if (v.videoCodec == "h265") v.videoCodec = "hevc";
    if (v.videoCodec != "h264" && v.videoCodec != "hevc") v.videoCodec = "h264";
    v.videoBitrateKbps = scfg.bitrateKbps;
    v.videoEnabled = true;
  } else {
    v.videoDevicePath = vcfg.devicePath;
    v.videoFourcc = vcfg.cameraFourcc;
    v.videoWidth = vcfg.width;
    v.videoHeight = vcfg.height;
    v.videoFpsNum = vcfg.fpsNum;
    v.videoFpsDen = vcfg.fpsDen;
    v.videoCodec = vcfg.codec;
    v.videoBitrateKbps = vcfg.bitrateKbps;
    v.videoEnabled = webcamEnabled && !vcfg.devicePath.isEmpty();
  }
  return v;
}

QString makeServerObjectId() {
  return QUuid::createUuid().toString(QUuid::WithoutBraces);
}

qint64 nowUtcMs() {
  return QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
}

QByteArray compactJsonBytes(const QJsonObject& o) {
  return QJsonDocument(o).toJson(QJsonDocument::Compact);
}

QString compactJsonString(const QJsonObject& o) {
  return QString::fromUtf8(compactJsonBytes(o));
}

QJsonArray channelsToJson(const QVector<Profile::ServerChannel>& channels) {
  QJsonArray arr;
  for (const auto& c : channels) {
    QJsonObject o;
    o["id"] = c.id;
    o["name"] = c.name;
    o["voice"] = c.voice;
    arr.push_back(o);
  }
  return arr;
}

QIcon channelTypeIcon(bool voice) {
  const QString fileName = voice ? "voice.svg" : "text.svg";
  const QString resourcePath = QString(":/icons/%1").arg(fileName);
  QIcon resourceIcon(resourcePath);
  if (!resourceIcon.isNull()) return resourceIcon;

  const QStringList candidates = {
      QDir::current().absoluteFilePath(fileName),
      QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(fileName),
      QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QString("../%1").arg(fileName)),
  };
  for (const auto& path : candidates) {
    if (!QFileInfo::exists(path)) continue;
    QIcon icon(path);
    if (!icon.isNull()) return icon;
  }
  return QApplication::style()->standardIcon(voice ? QStyle::SP_MediaVolume : QStyle::SP_FileIcon);
}

QVector<Profile::ServerChannel> channelsFromJson(const QJsonArray& arr) {
  QVector<Profile::ServerChannel> out;
  for (const auto& v : arr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    Profile::ServerChannel c;
    c.id = o.value("id").toString();
    c.name = o.value("name").toString();
    c.voice = o.value("voice").toBool(false);
    if (!c.id.isEmpty()) out.push_back(c);
  }
  return out;
}

QJsonArray membersToJson(const QVector<Profile::ServerMember>& members) {
  QJsonArray arr;
  for (const auto& m : members) {
    QJsonObject o;
    o["id"] = m.id;
    o["name"] = m.name;
    arr.push_back(o);
  }
  return arr;
}

QJsonArray membersToJsonIdsOnly(const QVector<Profile::ServerMember>& members) {
  QJsonArray arr;
  for (const auto& m : members) {
    QJsonObject o;
    o["id"] = m.id;
    o["name"] = "";
    arr.push_back(o);
  }
  return arr;
}

QVector<Profile::ServerMember> membersFromJson(const QJsonArray& arr) {
  QVector<Profile::ServerMember> out;
  for (const auto& v : arr) {
    if (!v.isObject()) continue;
    const auto o = v.toObject();
    Profile::ServerMember m;
    m.id = o.value("id").toString();
    m.name = o.value("name").toString();
    if (!m.id.isEmpty()) out.push_back(m);
  }
  return out;
}

int findMemberIndex(const QVector<Profile::ServerMember>& members, const QString& id) {
  for (int i = 0; i < members.size(); ++i) {
    if (members[i].id == id) return i;
  }
  return -1;
}

bool verifyCanonicalJsonSignature(const QString& signerId, const QString& payloadJsonCompact, const QString& sig) {
  std::string canonical;
  try {
    const auto j = common::json::parse(payloadJsonCompact.toStdString());
    canonical = j.dump();
  } catch (...) {
    return false;
  }
  return common::Identity::verify_bytes_b64url(
      signerId.toStdString(),
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()),
      sig.toStdString());
}
} // namespace

MainWindow::MainWindow(QString keyPassword, QWidget* parent)
    : QMainWindow(parent), keyPassword_(std::move(keyPassword)) {
  buildUi();
  loadProfile();
  webcamEnabled_ = false;
  applyTheme(profile_.darkMode);
  refreshSelfProfileWidget();

  connect(&backend_, &ChatBackend::registered, this,
          [this](QString selfId, QString observedIp, quint16 udpPort) {
            selfId_ = selfId;
            if (myIdEdit_) myIdEdit_->setText(selfId_);
            setWindowTitle(QString("p2p_chat_gui - %1").arg(selfId.left(12)));
            statusBar()->showMessage(QString("Observed: %1  UDP port: %2")
                                         .arg(observedIp)
                                         .arg(udpPort),
                                     10000);
            refreshSelfProfileWidget();
          });

  connect(&backend_, &ChatBackend::logLine, this, [](const QString& line) {
    std::cout << line.toStdString() << std::endl;
  });

  connect(&backend_, &ChatBackend::friendRequestReceived, this,
          [this](QString fromId) {
            auto* fe = profile_.findFriend(fromId);
            Profile::FriendEntry e;
            if (fe) e = *fe;
            e.id = fromId;
            e.status = Profile::FriendStatus::IncomingPending;
            profile_.upsertFriend(e);
            saveProfile();
            rebuildFriendList();
            rebuildFriendsTab();

            statusBar()->showMessage(QString("Friend request from %1").arg(fromId.left(12)), 8000);
          });

  connect(&backend_, &ChatBackend::friendAccepted, this, [this](QString peerId) {
    auto* f = profile_.findFriend(peerId);
    if (!f) {
      Profile::FriendEntry e;
      e.id = peerId;
      e.status = Profile::FriendStatus::Accepted;
      profile_.upsertFriend(e);
    } else {
      f->status = Profile::FriendStatus::Accepted;
    }
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    backend_.setFriendAccepted(peerId, true);
    // Best-effort: now that both sides are "friends", establish a P2P session to learn the peer name.
    backend_.warmConnect(peerId);
  });

  connect(&backend_, &ChatBackend::messageReceived, this,
          [this](QString peerId, QString displayName, QString text, bool incoming) {
            appendMessage(peerId, displayName, text, incoming);
          });

  connect(&backend_,
          &ChatBackend::signedControlReceived,
          this,
          [this](QString peerId, QString kind, QString payloadJsonCompact, QString signature, QString fromId) {
            if (fromId != peerId) return;
            handleSignedControl(peerId, kind, payloadJsonCompact, signature, fromId);
          });
  connect(&backend_,
          &ChatBackend::unsignedControlReceived,
          this,
          [this](QString peerId, QString kind, QString payloadJsonCompact, QString fromId) {
            if (fromId != peerId) return;
            handleUnsignedControl(peerId, kind, payloadJsonCompact, fromId);
          });

  connect(&backend_, &ChatBackend::peerNameUpdated, this, [this](QString peerId, QString name) {
    if (name.isEmpty()) return;
    auto* f = profile_.findFriend(peerId);
    if (!f || f->status == Profile::FriendStatus::None) return;
    if (f->name == name) return;
    f->name = name;
    saveProfile();
    rebuildFriendList();
    refreshHeader();
  });

  connect(&backend_, &ChatBackend::deliveryError, this, [this](QString peerId, QString msg) {
    statusBar()->showMessage(QString("Delivery to %1 failed: %2").arg(peerId.left(12), msg), 8000);
  });

  connect(&backend_, &ChatBackend::incomingCall, this, [this](QString peerId) {
    activeCallPeer_ = peerId;
    activeCallState_ = "incoming";
    refreshCallButton();
    const bool inVoiceChannel = !joinedServerVoiceKey_.isEmpty();
    if (inVoiceChannel) {
      backend_.answerCall(peerId,
                          true,
                          voiceSettingsFromProfile(profile_.audio,
                                                   profile_.video,
                                                   profile_.screen,
                                                   localMicMuted_,
                                                   webcamEnabled_,
                                                   screenShareEnabled_,
                                                   screenShareDisplayName_));
      activeCallState_ = "connecting";
      refreshCallButton();
      statusBar()->showMessage("Voice channel call connected", 2500);
      return;
    }
    const auto* f = profile_.findFriend(peerId);
    const auto who = f ? friendDisplay(*f) : peerId.left(14) + "...";
    auto ret = QMessageBox::question(this, "Incoming call", QString("%1 is calling you. Accept?").arg(who));
    const bool accept = (ret == QMessageBox::Yes);
    backend_.answerCall(peerId,
                        accept,
                        voiceSettingsFromProfile(profile_.audio,
                                                 profile_.video,
                                                 profile_.screen,
                                                 localMicMuted_,
                                                 webcamEnabled_,
                                                 screenShareEnabled_,
                                                 screenShareDisplayName_));
    if (!accept) {
      activeCallPeer_.clear();
      activeCallState_.clear();
      refreshCallButton();
    }
  });

  connect(&backend_, &ChatBackend::callStateChanged, this, [this](QString peerId, QString state) {
    activeCallPeer_ = peerId;
    activeCallState_ = state;
    if (!peerId.isEmpty()) {
      backend_.setPeerVideoWatch(peerId, isWatchingPeerVideo(peerId));
    }
    refreshCallButton();
    refreshVideoPanel();
  });

  connect(&backend_, &ChatBackend::callEnded, this, [this](QString peerId, QString reason) {
    const bool hadRemoteLive = remoteVideoFrames_.contains(peerId);
    remoteVideoAvailable_[peerId] = false;
    remoteVideoFrames_.remove(peerId);
    if (remoteVideoPeerId_ == peerId) remoteVideoPeerId_.clear();
    remoteVideoActive_ = !remoteVideoFrames_.isEmpty();
    if (hadRemoteLive) rebuildServerList();
    if (activeCallPeer_ == peerId) {
      activeCallPeer_.clear();
      activeCallState_.clear();
      refreshCallButton();
      refreshVideoPanel();
    }
    statusBar()->showMessage(QString("Call with %1 ended: %2").arg(peerId.left(12), reason), 8000);
    maybeSyncVoiceCallForJoinedChannel();
  });

  connect(&backend_, &ChatBackend::localVideoFrame, this, [this](QImage frame) {
    const bool wasLocalLive = localVideoActive_;
    if (frame.isNull()) {
      localVideoActive_ = false;
      localVideoFrame_ = QImage();
      if (wasLocalLive != localVideoActive_) rebuildServerList();
      refreshVideoPanel();
      return;
    }
    localVideoActive_ = true;
    localVideoFrame_ = frame;
    if (wasLocalLive != localVideoActive_) rebuildServerList();
    refreshVideoPanel();
  });
  connect(&backend_, &ChatBackend::remoteVideoFrame, this, [this](QString peerId, QImage frame) {
    if (!activeCallPeer_.isEmpty() && peerId != activeCallPeer_) return;
    if (!isWatchingPeerVideo(peerId)) return;
    const bool wasRemoteLive = remoteVideoFrames_.contains(peerId) && !remoteVideoFrames_.value(peerId).isNull();
    remoteVideoPeerId_ = peerId;
    if (frame.isNull()) {
      remoteVideoFrames_.remove(peerId);
      remoteVideoActive_ = !remoteVideoFrames_.isEmpty();
      if (wasRemoteLive) rebuildServerList();
      refreshVideoPanel();
      return;
    }
    remoteVideoActive_ = true;
    remoteVideoFrames_[peerId] = frame;
    if (!wasRemoteLive) rebuildServerList();
    refreshVideoPanel();
  });
  connect(&backend_, &ChatBackend::remoteVideoAvailabilityChanged, this, [this](QString peerId, bool available) {
    if (peerId.isEmpty()) return;
    remoteVideoAvailable_[peerId] = available;
    if (!available) {
      remoteVideoFrames_.remove(peerId);
      if (remoteVideoPeerId_ == peerId) remoteVideoPeerId_.clear();
      remoteVideoActive_ = !remoteVideoFrames_.isEmpty();
      if (expandedVideoPeerId_ == peerId) expandedVideoPeerId_.clear();
    }
    rebuildServerList();
    refreshVideoPanel();
  });

  connect(&backend_, &ChatBackend::peerAvatarUpdated, this, [this](QString peerId, QByteArray pngBytes) {
    if (pngBytes.isEmpty()) return;
    QImage img;
    if (!img.loadFromData(pngBytes, "PNG")) return;
    const auto path = Profile::peerAvatarFile(peerId);
    QDir().mkpath(QFileInfo(path).absolutePath());
    (void)img.save(path, "PNG");

    auto* f = profile_.findFriend(peerId);
    if (f && f->avatarPath != path) {
      f->avatarPath = path;
      saveProfile();
    }
    rebuildFriendList();
    refreshServerMembersPane();
    refreshHeader();
  });

  connect(&backend_, &ChatBackend::presenceUpdated, this, [this](QString peerId, bool online) {
    rendezvousOnline_[peerId] = online;
    if (!online) {
      directOnline_[peerId] = false;
      remoteVideoAvailable_[peerId] = false;
      remoteVideoFrames_.remove(peerId);
      if (remoteVideoPeerId_ == peerId) remoteVideoPeerId_.clear();
      remoteVideoActive_ = !remoteVideoFrames_.isEmpty();
      for (auto it = voiceOccupantsByChannel_.begin(); it != voiceOccupantsByChannel_.end(); ++it) {
        it.value().remove(peerId);
      }
    }
    refreshFriendPresenceRow(peerId);
    rebuildServerList();
    refreshServerMembersPane();
    maybeSyncVoiceCallForJoinedChannel();
    if (online) announceJoinedVoicePresence();
    if (peerId == selectedPeerId_) refreshCallButton();
  });

  connect(&backend_, &ChatBackend::directPeerConnectionChanged, this, [this](QString peerId, bool connected) {
    directOnline_[peerId] = connected;
    if (connected) rendezvousOnline_[peerId] = true;
    refreshFriendPresenceRow(peerId);
    rebuildServerList();
    refreshServerMembersPane();
    maybeSyncVoiceCallForJoinedChannel();
    if (connected) announceJoinedVoicePresence();
    if (peerId == selectedPeerId_) refreshCallButton();
  });

  voicePresenceTimer_ = new QTimer(this);
  voicePresenceTimer_->setInterval(5000);
  connect(voicePresenceTimer_, &QTimer::timeout, this, [this] { announceJoinedVoicePresence(); });
  voicePresenceTimer_->start();

  // Start backend.
  ChatBackend::Options opt;
  opt.serverHost = profile_.serverHost;
  opt.serverPort = profile_.serverPort;
  opt.keyPath = profile_.keyPath;
  opt.keyPassword = keyPassword_;
  opt.selfName = profile_.selfName;
  opt.listenPort = profile_.listenPort;
  backend_.start(opt);

  // Load and announce our avatar to peers (P2P only; not via rendezvous).
  if (!profile_.selfAvatarPath.isEmpty() && QFileInfo::exists(profile_.selfAvatarPath)) {
    QImage img(profile_.selfAvatarPath);
    if (!img.isNull()) {
      const QImage wire = img.scaled(96, 96, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QByteArray out;
      QBuffer buf(&out);
      buf.open(QIODevice::WriteOnly);
      (void)wire.save(&buf, "PNG");
      backend_.setSelfAvatarPng(out);
    }
  }

  // Push accepted friends to backend gate.
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::Accepted) backend_.setFriendAccepted(f.id, true);
  }
  for (const auto& id : mutedVoicePeerIds_) {
    if (id.isEmpty()) continue;
    backend_.setPeerMuted(id, true);
  }
  syncBackendServerMembers();

  rebuildFriendList();
  rebuildFriendsTab();
  rebuildServerList();
  refreshHeader();
  refreshCallButton();
}

MainWindow::~MainWindow() {
  saveProfile();
  backend_.stop();
}

void MainWindow::resizeEvent(QResizeEvent* event) {
  QMainWindow::resizeEvent(event);
  refreshVideoPanel();
}

void MainWindow::buildUi() {
  auto* optionsMenu = menuBar()->addMenu("Options");

  auto* addFriend = new QAction("Add Friend...", this);
  connect(addFriend, &QAction::triggered, this, [this] { addFriendDialog(); });
  optionsMenu->addAction(addFriend);

  auto* setName = new QAction("Set Name...", this);
  connect(setName, &QAction::triggered, this, [this] {
    bool ok = false;
    const auto name = QInputDialog::getText(this, "Set name", "Name:", QLineEdit::Normal, profile_.selfName, &ok)
                          .trimmed();
    if (!ok) return;
    if (name.size() > 32) {
      QMessageBox::warning(this, "Invalid name", "Name must be at most 32 characters.");
      return;
    }
    profile_.selfName = name;
    backend_.setSelfName(name);
    saveProfile();
    refreshSelfProfileWidget();
    statusBar()->showMessage("Name updated", 6000);
  });
  optionsMenu->addAction(setName);

  auto* settings = new QAction("Settings...", this);
  connect(settings, &QAction::triggered, this, [this] {
    if (SettingsDialog::edit(&profile_.audio,
                             &profile_.video,
                             &profile_.screen,
                             &profile_.shareIdentityWithNonFriendsInServers,
                             &profile_.signedOnlyServerMessages,
                             this)) {
      if (profile_.video.devicePath.trimmed().isEmpty()) webcamEnabled_ = false;
      backend_.updateVoiceSettings(voiceSettingsFromProfile(profile_.audio,
                                                            profile_.video,
                                                            profile_.screen,
                                                            localMicMuted_,
                                                            webcamEnabled_,
                                                            screenShareEnabled_,
                                                            screenShareDisplayName_));
      saveProfile();
      rebuildServerList();
      refreshServerMembersPane();
      refreshCallButton();
      statusBar()->showMessage("Settings updated", 4000);
    }
  });
  optionsMenu->addAction(settings);

  auto* darkMode = new QAction("Dark Mode", this);
  darkMode->setCheckable(true);
  optionsMenu->addAction(darkMode);
  optionsMenu->addSeparator();

  auto* quit = new QAction("Quit", this);
  connect(quit, &QAction::triggered, qApp, &QApplication::quit);
  optionsMenu->addAction(quit);

  auto* splitter = new QSplitter(this);

  leftTabs_ = new QTabWidget(splitter);
  leftTabs_->setMinimumWidth(240);
  leftTabs_->setMaximumWidth(300);

  // Chats tab (list + self profile widget)
  auto* chatsTab = new QWidget(leftTabs_);
  auto* chatsLayout = new QVBoxLayout(chatsTab);
  chatsLayout->setContentsMargins(0, 0, 0, 0);
  chatsLayout->setSpacing(0);

  friendList_ = new QListWidget(chatsTab);
  friendList_->setItemDelegate(new PresenceDotDelegate(friendList_));
  friendList_->setIconSize(QSize(28, 28));
  friendList_->setSpacing(2);
  chatsLayout->addWidget(friendList_, 1);

  auto* selfPanel = new QWidget(chatsTab);
  auto* selfLayout = new QHBoxLayout(selfPanel);
  selfLayout->setContentsMargins(10, 8, 10, 8);
  selfLayout->setSpacing(10);

  myAvatarLabel_ = new ClickableLabel(selfPanel);
  myAvatarLabel_->setFixedSize(48, 48);
  myAvatarLabel_->setCursor(Qt::PointingHandCursor);
  myAvatarLabel_->setToolTip("Click to change profile picture");
  myAvatarLabel_->setScaledContents(true);

  myNameLabel_ = new QLabel(selfPanel);
  myNameLabel_->setStyleSheet("font-weight:600;");

  selfLayout->addWidget(myAvatarLabel_, 0);
  selfLayout->addWidget(myNameLabel_, 1);
  chatsLayout->addWidget(selfPanel, 0);

  leftTabs_->addTab(chatsTab, "Chats");

  // Friends tab
  auto* friendsTab = new QWidget(leftTabs_);
  auto* friendsLayout = new QVBoxLayout(friendsTab);
  friendsLayout->setContentsMargins(8, 8, 8, 8);

  auto* idLabel = new QLabel("Your ID (share this):", friendsTab);
  friendsLayout->addWidget(idLabel);

  auto* idRow = new QWidget(friendsTab);
  auto* idRowLayout = new QHBoxLayout(idRow);
  idRowLayout->setContentsMargins(0, 0, 0, 0);
  myIdEdit_ = new QLineEdit(idRow);
  myIdEdit_->setReadOnly(true);
  myIdEdit_->setPlaceholderText("Connecting…");
  copyIdBtn_ = new QPushButton("Copy", idRow);
  idRowLayout->addWidget(myIdEdit_, 1);
  idRowLayout->addWidget(copyIdBtn_);
  friendsLayout->addWidget(idRow);

  connect(copyIdBtn_, &QPushButton::clicked, this, [this] {
    if (!myIdEdit_) return;
    QGuiApplication::clipboard()->setText(myIdEdit_->text());
    statusBar()->showMessage("Copied ID to clipboard", 3000);
  });

  friendsLayout->addSpacing(10);

  auto* addLabel = new QLabel("Send friend request:", friendsTab);
  friendsLayout->addWidget(addLabel);

  addIdEdit_ = new QLineEdit(friendsTab);
  addIdEdit_->setPlaceholderText("Friend ID");
  friendsLayout->addWidget(addIdEdit_);

  sendReqBtn_ = new QPushButton("Send Request", friendsTab);
  friendsLayout->addWidget(sendReqBtn_);
  connect(sendReqBtn_, &QPushButton::clicked, this, [this] {
    const auto id = addIdEdit_->text().trimmed();
    if (id.isEmpty()) return;
    Profile::FriendEntry e;
    auto* ex = profile_.findFriend(id);
    if (ex) e = *ex;
    e.id = id;
    if (e.status == Profile::FriendStatus::None) e.status = Profile::FriendStatus::OutgoingPending;
    profile_.upsertFriend(e);
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    backend_.sendFriendRequest(id);
    statusBar()->showMessage("Friend request sent", 5000);
  });

  friendsLayout->addSpacing(10);

  auto* reqLabel = new QLabel("Incoming requests:", friendsTab);
  friendsLayout->addWidget(reqLabel);
  requestsList_ = new QListWidget(friendsTab);
  friendsLayout->addWidget(requestsList_, 1);

  auto* reqBtns = new QWidget(friendsTab);
  auto* reqBtnsLayout = new QHBoxLayout(reqBtns);
  reqBtnsLayout->setContentsMargins(0, 0, 0, 0);
  acceptBtn_ = new QPushButton("Accept", reqBtns);
  rejectBtn_ = new QPushButton("Reject", reqBtns);
  reqBtnsLayout->addWidget(acceptBtn_);
  reqBtnsLayout->addWidget(rejectBtn_);
  friendsLayout->addWidget(reqBtns);

  connect(acceptBtn_, &QPushButton::clicked, this, [this] {
    if (!requestsList_ || !requestsList_->currentItem()) return;
    const auto id = requestsList_->currentItem()->data(Qt::UserRole).toString();
    auto* f = profile_.findFriend(id);
    if (!f) return;
    f->status = Profile::FriendStatus::Accepted;
    saveProfile();
    backend_.acceptFriend(id);
    backend_.setFriendAccepted(id, true);
    rebuildFriendList();
    rebuildFriendsTab();
    statusBar()->showMessage("Friend accepted", 5000);
  });
  connect(rejectBtn_, &QPushButton::clicked, this, [this] {
    if (!requestsList_ || !requestsList_->currentItem()) return;
    const auto id = requestsList_->currentItem()->data(Qt::UserRole).toString();
    for (int i = 0; i < profile_.friends.size(); ++i) {
      if (profile_.friends[i].id == id) {
        profile_.friends.removeAt(i);
        break;
      }
    }
    backend_.setFriendAccepted(id, false);
    saveProfile();
    rebuildFriendList();
    rebuildFriendsTab();
    statusBar()->showMessage("Request rejected", 5000);
  });

  leftTabs_->addTab(friendsTab, "Friends");

  // Servers tab
  auto* serversTab = new QWidget(leftTabs_);
  auto* serversLayout = new QVBoxLayout(serversTab);
  serversLayout->setContentsMargins(8, 8, 8, 8);
  serversLayout->setSpacing(8);

  serverList_ = new QListWidget(serversTab);
  serverList_->setItemDelegate(new PresenceDotDelegate(serverList_));
  serverList_->setIconSize(QSize(18, 18));
  serverList_->setSpacing(1);
  serverList_->setSelectionMode(QAbstractItemView::SingleSelection);
  serverList_->setContextMenuPolicy(Qt::CustomContextMenu);
  serversLayout->addWidget(serverList_, 1);

  auto* addServerBtn = new QPushButton("Create Server", serversTab);
  connect(addServerBtn, &QPushButton::clicked, this, [this] { addServerDialog(); });
  serversLayout->addWidget(addServerBtn, 0);

  serverInvitesBtn_ = new QPushButton("Pending Invites (0)", serversTab);
  connect(serverInvitesBtn_, &QPushButton::clicked, this, [this] { reviewPendingServerInvites(); });
  serversLayout->addWidget(serverInvitesBtn_, 0);

  auto* clearInvitesBtn = new QPushButton("Clear Pending Invites", serversTab);
  connect(clearInvitesBtn, &QPushButton::clicked, this, [this] {
    if (profile_.pendingServerInvites.isEmpty()) return;
    const auto ret = QMessageBox::question(
        this,
        "Clear pending invites",
        QString("Remove all %1 pending invites?").arg(profile_.pendingServerInvites.size()));
    if (ret != QMessageBox::Yes) return;
    profile_.pendingServerInvites.clear();
    saveProfile();
    rebuildServerList();
  });
  serversLayout->addWidget(clearInvitesBtn, 0);

  leftTabs_->addTab(serversTab, "Servers");
  connect(leftTabs_, &QTabWidget::currentChanged, this, [this, chatsTab](int idx) {
    if (!leftTabs_ || !chatsTab) return;
    if (leftTabs_->widget(idx) != chatsTab) return;
    if (!joinedServerVoiceKey_.isEmpty()) return;
    if (activeCallPeer_.isEmpty() || activeCallState_.isEmpty()) return;
    if (selectedPeerId_ == activeCallPeer_ && selectedServerId_.isEmpty()) return;

    selectFriend(activeCallPeer_);
    if (friendList_) {
      for (int i = 0; i < friendList_->count(); ++i) {
        if (!friendList_->item(i)) continue;
        if (friendList_->item(i)->data(kRolePeerId).toString() == activeCallPeer_) {
          friendList_->setCurrentRow(i);
          break;
        }
      }
    }
  });

  auto* right = new QWidget(splitter);
  auto* rightLayout = new QVBoxLayout(right);
  rightLayout->setContentsMargins(8, 8, 8, 8);

  auto* headerRow = new QWidget(right);
  auto* headerRowLayout = new QHBoxLayout(headerRow);
  headerRowLayout->setContentsMargins(0, 0, 0, 0);
  headerRowLayout->setSpacing(10);

  headerLabel_ = new QLabel("No chat selected", headerRow);
  headerLabel_->setStyleSheet("font-weight:600; font-size:14px;");
  headerRowLayout->addWidget(headerLabel_, 1);

  callBtn_ = new QPushButton("Call", headerRow);
  callBtn_->setEnabled(false);
  headerRowLayout->addWidget(callBtn_, 0, Qt::AlignRight);

  exitExpandedBtn_ = new QPushButton("Back to Grid", headerRow);
  exitExpandedBtn_->setVisible(false);
  headerRowLayout->addWidget(exitExpandedBtn_, 0, Qt::AlignRight);

  rightLayout->addWidget(headerRow);

  callControlsBar_ = new QWidget(right);
  callControlsBar_->setObjectName("callControlsBar");
  auto* callControlsLayout = new QHBoxLayout(callControlsBar_);
  callControlsLayout->setContentsMargins(0, 0, 0, 0);
  callControlsLayout->setSpacing(0);
  callControlsLayout->addStretch(1);

  micBtn_ = new QPushButton(callControlsBar_);
  micBtn_->setCheckable(true);
  micBtn_->setChecked(false);
  micBtn_->setToolTip("Mute microphone");
  micBtn_->setObjectName("callMicButton");
  micBtn_->setIcon(discordMicIcon(false, profile_.darkMode));
  micBtn_->setIconSize(QSize(18, 18));
  micBtn_->setText({});
  micBtn_->setFixedSize(42, 32);
  callControlsLayout->addWidget(micBtn_);

  micMoreBtn_ = new QToolButton(callControlsBar_);
  micMoreBtn_->setText("▾");
  micMoreBtn_->setToolTip("Microphone options");
  micMoreBtn_->setPopupMode(QToolButton::InstantPopup);
  auto* micMenu = new QMenu(micMoreBtn_);
  micMenu->addAction("Audio Settings…", this, [settings] { settings->trigger(); });
  micMoreBtn_->setMenu(micMenu);
  micMoreBtn_->setObjectName("callMicCaretButton");
  micMoreBtn_->setProperty("danger", false);
  micMoreBtn_->setFixedSize(20, 32);
  callControlsLayout->addWidget(micMoreBtn_);

  webcamBtn_ = new QPushButton(callControlsBar_);
  webcamBtn_->setCheckable(true);
  webcamBtn_->setChecked(false);
  webcamBtn_->setEnabled(false);
  webcamBtn_->setToolTip("Toggle webcam");
  webcamBtn_->setObjectName("callCamButton");
  webcamBtn_->setIcon(discordCameraIcon(true, profile_.darkMode, false));
  webcamBtn_->setIconSize(QSize(18, 18));
  webcamBtn_->setText({});
  webcamBtn_->setFixedSize(42, 32);
  callControlsLayout->addSpacing(8);
  callControlsLayout->addWidget(webcamBtn_);

  camMoreBtn_ = new QToolButton(callControlsBar_);
  camMoreBtn_->setText("▾");
  camMoreBtn_->setToolTip("Camera options");
  camMoreBtn_->setPopupMode(QToolButton::InstantPopup);
  auto* camMenu = new QMenu(camMoreBtn_);
  camMenu->addAction("Video Settings…", this, [settings] { settings->trigger(); });
  camMenu->addAction("Toggle Screen Share", this, [this] {
    if (!screenShareBtn_ || !screenShareBtn_->isEnabled()) return;
    screenShareBtn_->toggle();
  });
  camMoreBtn_->setMenu(camMenu);
  camMoreBtn_->setObjectName("callCamCaretButton");
  camMoreBtn_->setFixedSize(20, 32);
  callControlsLayout->addWidget(camMoreBtn_);

  // Hidden backing toggle used by call controls/context menus for screen sharing.
  screenShareBtn_ = new QPushButton(callControlsBar_);
  screenShareBtn_->setCheckable(true);
  screenShareBtn_->setChecked(false);
  screenShareBtn_->setEnabled(false);
  screenShareBtn_->setToolTip("Toggle screen share");
  screenShareBtn_->setObjectName("callShareButton");
  screenShareBtn_->setIcon(discordScreenIcon(profile_.darkMode, false));
  screenShareBtn_->setIconSize(QSize(18, 18));
  screenShareBtn_->setText({});
  screenShareBtn_->setFixedSize(42, 32);
  callControlsLayout->addSpacing(8);
  callControlsLayout->addWidget(screenShareBtn_);

  disconnectBtn_ = new QPushButton(callControlsBar_);
  disconnectBtn_->setObjectName("callHangupButton");
  disconnectBtn_->setToolTip("Leave call");
  disconnectBtn_->setIcon(discordHangupIcon(profile_.darkMode));
  disconnectBtn_->setIconSize(QSize(18, 18));
  disconnectBtn_->setText({});
  disconnectBtn_->setFixedSize(46, 32);
  callControlsLayout->addSpacing(8);
  callControlsLayout->addWidget(disconnectBtn_);

  callControlsLayout->addStretch(1);
  callControlsBar_->setFixedHeight(36);
  callControlsBar_->setStyleSheet(callControlsStyleSheet(profile_.darkMode));
  callControlsBar_->setVisible(false);

  auto* contentSplit = new QSplitter(Qt::Horizontal, right);
  auto* chatPane = new QWidget(contentSplit);
  auto* chatPaneLayout = new QVBoxLayout(chatPane);
  chatPaneLayout->setContentsMargins(0, 0, 0, 0);
  chatPaneLayout->setSpacing(0);

  videoPanel_ = new QWidget(chatPane);
  auto* videoLayout = new QVBoxLayout(videoPanel_);
  videoLayout->setContentsMargins(0, 0, 0, 0);
  videoLayout->setSpacing(0);
  videoTiles_ = new QListWidget(videoPanel_);
  videoTiles_->setObjectName("videoTiles");
  videoTiles_->setViewMode(QListView::IconMode);
  videoTiles_->setFlow(QListView::LeftToRight);
  videoTiles_->setResizeMode(QListView::Adjust);
  videoTiles_->setMovement(QListView::Static);
  videoTiles_->setWrapping(true);
  videoTiles_->setWordWrap(true);
  videoTiles_->setSelectionMode(QAbstractItemView::NoSelection);
  videoTiles_->setSelectionRectVisible(false);
  videoTiles_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  videoTiles_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
  videoTiles_->setSpacing(10);
  videoTiles_->setIconSize(QSize(320, 180));
  videoTiles_->setGridSize(QSize(340, 212));
  videoTiles_->setUniformItemSizes(true);
  videoTiles_->setContextMenuPolicy(Qt::CustomContextMenu);
  videoTiles_->setFrameShape(QFrame::NoFrame);
  videoTiles_->setFrameStyle(QFrame::NoFrame);
  videoTiles_->setLineWidth(0);
  videoTiles_->setMidLineWidth(0);
  videoTiles_->setFocusPolicy(Qt::NoFocus);
  videoTiles_->viewport()->setAutoFillBackground(false);
  videoTiles_->setMinimumHeight(220);
  videoTiles_->setStyleSheet({});
  videoLayout->addWidget(videoTiles_, 1);

  dmAvatarRow_ = new QWidget(videoPanel_);
  dmAvatarRow_->setVisible(false);
  dmAvatarRow_->setStyleSheet("background: transparent; border: none;");
  dmAvatarLayout_ = new QHBoxLayout(dmAvatarRow_);
  dmAvatarLayout_->setContentsMargins(0, 0, 0, 0);
  dmAvatarLayout_->setSpacing(16);
  videoLayout->addWidget(dmAvatarRow_, 0, Qt::AlignHCenter);

  callControlsBar_->setParent(videoPanel_);
  videoLayout->addWidget(callControlsBar_, 0, Qt::AlignHCenter);
  videoPanel_->setVisible(false);
  chatPaneLayout->addWidget(videoPanel_, 0);

  chatStack_ = new QStackedWidget(chatPane);

  chatView_ = new QTextBrowser(chatStack_);
  chatView_->setOpenExternalLinks(false);
  chatView_->setOpenLinks(false);
  chatView_->document()->setDefaultStyleSheet("a { color: inherit; text-decoration: none; }");
  chatStack_->addWidget(chatView_);

  voiceGallery_ = new QListWidget(chatStack_);
  voiceGallery_->setViewMode(QListView::IconMode);
  voiceGallery_->setResizeMode(QListView::Adjust);
  voiceGallery_->setMovement(QListView::Static);
  voiceGallery_->setIconSize(QSize(72, 72));
  voiceGallery_->setSpacing(12);
  voiceGallery_->setWordWrap(true);
  voiceGallery_->setSelectionMode(QAbstractItemView::NoSelection);
  chatStack_->addWidget(voiceGallery_);
  chatStack_->setCurrentWidget(chatView_);

  chatPaneLayout->addWidget(chatStack_, /*stretch*/ 1);
  contentSplit->addWidget(chatPane);

  serverMembersList_ = new QListWidget(contentSplit);
  serverMembersList_->setItemDelegate(new PresenceDotDelegate(serverMembersList_));
  serverMembersList_->setIconSize(QSize(22, 22));
  serverMembersList_->setMinimumWidth(200);
  serverMembersList_->setMaximumWidth(240);
  serverMembersList_->setContextMenuPolicy(Qt::CustomContextMenu);
  serverMembersList_->setVisible(false);
  contentSplit->addWidget(serverMembersList_);
  contentSplit->setStretchFactor(0, 4);
  contentSplit->setStretchFactor(1, 1);

  rightLayout->addWidget(contentSplit, /*stretch*/ 1);

  auto* bottom = new QWidget(right);
  auto* bottomLayout = new QHBoxLayout(bottom);
  bottomLayout->setContentsMargins(0, 0, 0, 0);
  input_ = new QLineEdit(bottom);
  input_->setPlaceholderText("Type a message…");
  auto* gifBtn = new QPushButton("Gif", bottom);
  auto* sendBtn = new QPushButton("Send", bottom);
  bottomLayout->addWidget(input_, 1);
  bottomLayout->addWidget(gifBtn);
  bottomLayout->addWidget(sendBtn);
  rightLayout->addWidget(bottom);

  splitter->setStretchFactor(0, 1);
  splitter->setStretchFactor(1, 4);

  setCentralWidget(splitter);
  resize(1000, 650);

  connect(friendList_, &QListWidget::currentRowChanged, this, [this](int row) {
    if (row < 0 || row >= friendList_->count()) return;
    const auto id = friendList_->item(row)->data(kRolePeerId).toString();
    selectFriend(id);
  });

  friendList_->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(friendList_, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
    showChatContextMenu(pos);
  });

  connect(serverList_, &QListWidget::itemPressed, this, [this](QListWidgetItem* item) {
    if (!item) return;
    const int type = item->data(kRoleServerItemType).toInt();
    if (type == kServerHeaderItem) {
      const auto serverId = item->data(kRoleServerId).toString();
      auto* s = profile_.findServer(serverId);
      if (!s) return;
      s->expanded = !s->expanded;
      saveProfile();
      rebuildServerList();
      return;
    }
    if (type == kServerChannelItem) {
      const auto serverId = item->data(kRoleServerId).toString();
      const auto channelId = item->data(kRoleServerChannelId).toString();
      const bool voice = item->data(kRoleServerChannelVoice).toBool();
      selectServerChannel(serverId, channelId, voice);
      return;
    }
    if (type == kServerVoiceMemberItem) {
      const auto serverId = item->data(kRoleServerId).toString();
      const auto channelId = item->data(kRoleServerChannelId).toString();
      if (!serverId.isEmpty() && !channelId.isEmpty()) {
        selectServerChannel(serverId, channelId, /*voice=*/true);
      }
      return;
    }
  });
  connect(serverList_, &QListWidget::itemDoubleClicked, this, [this](QListWidgetItem* item) {
    if (!item) return;
    if (item->data(kRoleServerItemType).toInt() != kServerVoiceMemberItem) return;
    const auto peerId = item->data(kRolePeerId).toString();
    if (!peerId.isEmpty()) showProfilePopup(peerId);
  });

  connect(serverList_, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
    showServerContextMenu(pos);
  });
  connect(serverMembersList_, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
    showServerMemberContextMenu(pos);
  });
  connect(serverMembersList_, &QListWidget::itemClicked, this, [this](QListWidgetItem* item) {
    if (!item) return;
    const auto peerId = item->data(kRolePeerId).toString();
    if (peerId.isEmpty()) return;
    showProfilePopup(peerId);
  });
  connect(videoTiles_, &QListWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
    if (!videoTiles_) return;
    auto* item = videoTiles_->itemAt(pos);
    if (!item) return;
    const auto peerId = item->data(kRolePeerId).toString();
    if (peerId.isEmpty()) return;
    const QString serverId =
        (selectedServerChannelVoice_ && !selectedServerId_.isEmpty()) ? selectedServerId_ : QString();
    showServerPeerContextMenu(peerId, serverId, videoTiles_->viewport()->mapToGlobal(pos), /*allowProfile*/ true);
  });
  connect(videoTiles_, &QListWidget::itemPressed, this, [this](QListWidgetItem* item) {
    if (!item) return;
    if (!(QApplication::mouseButtons() & Qt::LeftButton)) return;
    const auto peerId = item->data(kRolePeerId).toString();
    if (peerId.isEmpty()) return;
    if (item->data(kRoleDmCallAvatar).toBool()) return;
    if (item->data(kRoleWatchOverlay).toBool()) {
      setPeerVideoWatching(peerId, true);
      return;
    }
    if (expandedVideoPeerId_ == peerId) {
      expandedVideoPeerId_.clear();
    } else {
      expandedVideoPeerId_ = peerId;
    }
    refreshVideoPanel();
  });
  connect(exitExpandedBtn_, &QPushButton::clicked, this, [this] {
    expandedVideoPeerId_.clear();
    refreshVideoPanel();
  });

  auto sendNow = [this] {
    const auto msg = input_->text().trimmed();
    if (msg.isEmpty()) return;
    input_->clear();
    const auto pid = currentPeerId();
    if (!pid.isEmpty()) {
      backend_.sendMessage(pid, msg);
      return;
    }
    const auto key = currentChatKey();
    if (key.isEmpty() || selectedServerChannelVoice_) return;
    if (selectedServerId_.isEmpty() || selectedServerChannelId_.isEmpty()) return;
    if (msg.startsWith("/say ", Qt::CaseInsensitive)) {
      broadcastServerGlobalSay(selectedServerId_, msg.mid(5).trimmed());
      return;
    }
    broadcastServerText(selectedServerId_, selectedServerChannelId_, msg);
  };
  connect(sendBtn, &QPushButton::clicked, this, sendNow);
  connect(gifBtn, &QPushButton::clicked, this, &MainWindow::showGifPopup);
  connect(input_, &QLineEdit::returnPressed, this, sendNow);
  connect(callBtn_, &QPushButton::clicked, this, [this] {
    if (!selectedServerChannelId_.isEmpty()) {
      if (!selectedServerChannelVoice_) return;
      const auto key = serverChannelChatKey(selectedServerId_, selectedServerChannelId_);
      if (joinedServerVoiceKey_ == key) {
        broadcastVoicePresence(selectedServerId_, selectedServerChannelId_, false);
        voiceOccupantsByChannel_[key].remove(selfId_);
        joinedServerVoiceKey_.clear();
        backend_.stopVoiceChannel();
        statusBar()->showMessage("Left voice channel", 3000);
      } else {
        if (!joinedServerVoiceKey_.isEmpty()) {
          const auto prevServer = joinedVoiceServerId();
          const auto prevChannel = joinedVoiceChannelId();
          if (!prevServer.isEmpty() && !prevChannel.isEmpty()) {
            broadcastVoicePresence(prevServer, prevChannel, false);
            voiceOccupantsByChannel_[joinedServerVoiceKey_].remove(selfId_);
          }
        }
        joinedServerVoiceKey_ = key;
        voiceOccupantsByChannel_[key].insert(selfId_);
        broadcastVoicePresence(selectedServerId_, selectedServerChannelId_, true);
        statusBar()->showMessage("Joined voice channel", 4000);
      }
      rebuildServerList();
      refreshCallButton();
      refreshHeader();
      maybeSyncVoiceCallForJoinedChannel();
      return;
    }

    const auto pid = currentPeerId();
    if (pid.isEmpty()) return;
    if (!activeCallPeer_.isEmpty() && activeCallPeer_ == pid && !activeCallState_.isEmpty()) {
      backend_.endCall(pid);
      return;
    }
    if (presenceStateFor(pid) == kPresenceOffline) {
      statusBar()->showMessage("Peer is offline", 4000);
      return;
    }
    activeCallPeer_ = pid;
    activeCallState_ = "calling";
    refreshCallButton();
    backend_.startCall(pid,
                       voiceSettingsFromProfile(profile_.audio,
                                                profile_.video,
                                                profile_.screen,
                                                localMicMuted_,
                                                webcamEnabled_,
                                                screenShareEnabled_,
                                                screenShareDisplayName_));
  });
  connect(disconnectBtn_, &QPushButton::clicked, this, [this] {
    if (!joinedServerVoiceKey_.isEmpty()) {
      const auto serverId = joinedVoiceServerId();
      const auto channelId = joinedVoiceChannelId();
      if (!serverId.isEmpty() && !channelId.isEmpty()) {
        broadcastVoicePresence(serverId, channelId, false);
        voiceOccupantsByChannel_[joinedServerVoiceKey_].remove(selfId_);
      }
      joinedServerVoiceKey_.clear();
      backend_.stopVoiceChannel();
      rebuildServerList();
      refreshHeader();
      refreshCallButton();
      statusBar()->showMessage("Left voice channel", 3000);
      return;
    }
    if (!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty()) {
      backend_.endCall(activeCallPeer_);
    }
  });
  connect(micBtn_, &QPushButton::toggled, this, [this](bool muted) {
    localMicMuted_ = muted;
    if (micBtn_) {
      micBtn_->setToolTip(muted ? "Unmute microphone" : "Mute microphone");
    }
    if (micMoreBtn_) micMoreBtn_->setProperty("danger", muted);
    if (callControlsBar_) callControlsBar_->setStyleSheet(callControlsStyleSheet(profile_.darkMode));
    if ((!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty()) || !joinedServerVoiceKey_.isEmpty()) {
      backend_.updateVoiceSettings(voiceSettingsFromProfile(profile_.audio,
                                                            profile_.video,
                                                            profile_.screen,
                                                            localMicMuted_,
                                                            webcamEnabled_,
                                                            screenShareEnabled_,
                                                            screenShareDisplayName_));
    }
  });
  connect(webcamBtn_, &QPushButton::toggled, this, [this](bool enabled) {
    if (enabled && screenShareBtn_ && screenShareBtn_->isChecked()) {
      const QSignalBlocker block(*screenShareBtn_);
      screenShareBtn_->setChecked(false);
      screenShareEnabled_ = false;
      if (activeCallPeer_.isEmpty() || activeCallState_.isEmpty()) {
        remoteVideoFrames_.clear();
        remoteVideoActive_ = false;
      }
    }
    webcamEnabled_ = enabled;
    const bool wasLocalLive = localVideoActive_;
    if (!webcamEnabled_) {
      localVideoActive_ = false;
      localVideoFrame_ = QImage();
    }
    if (wasLocalLive != localVideoActive_) rebuildServerList();
    refreshCallButton();
    refreshVideoPanel();
    if ((!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty()) || !joinedServerVoiceKey_.isEmpty()) {
      backend_.updateVoiceSettings(voiceSettingsFromProfile(profile_.audio,
                                                            profile_.video,
                                                            profile_.screen,
                                                            localMicMuted_,
                                                            webcamEnabled_,
                                                            screenShareEnabled_,
                                                            screenShareDisplayName_));
      if (!joinedServerVoiceKey_.isEmpty()) maybeSyncVoiceCallForJoinedChannel();
      statusBar()->showMessage(webcamEnabled_ ? "Webcam enabled" : "Webcam disabled", 3000);
    }
  });
  connect(screenShareBtn_, &QPushButton::toggled, this, [this](bool enabled) {
    const bool wasLocalLive = localVideoActive_;
    if (enabled) {
      const QString displayName = chooseDisplayForShare(this, profile_.screen.lastDisplayName);
      if (displayName.trimmed().isEmpty()) {
        if (screenShareBtn_) {
          const QSignalBlocker block(*screenShareBtn_);
          screenShareBtn_->setChecked(false);
        }
        screenShareEnabled_ = false;
        refreshCallButton();
        return;
      }
      screenShareDisplayName_ = displayName.trimmed();
      profile_.screen.lastDisplayName = screenShareDisplayName_;
      saveProfile();
      if (webcamBtn_ && webcamBtn_->isChecked()) {
        const QSignalBlocker block(*webcamBtn_);
        webcamBtn_->setChecked(false);
        webcamEnabled_ = false;
        localVideoActive_ = false;
        localVideoFrame_ = QImage();
      }
    } else {
      if (!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty()) {
        localVideoActive_ = false;
        localVideoFrame_ = QImage();
      }
    }
    screenShareEnabled_ = enabled && !screenShareDisplayName_.trimmed().isEmpty();
    if (wasLocalLive != localVideoActive_) rebuildServerList();
    refreshCallButton();
    refreshVideoPanel();
    if ((!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty()) || !joinedServerVoiceKey_.isEmpty()) {
      backend_.updateVoiceSettings(voiceSettingsFromProfile(profile_.audio,
                                                            profile_.video,
                                                            profile_.screen,
                                                            localMicMuted_,
                                                            webcamEnabled_,
                                                            screenShareEnabled_,
                                                            screenShareDisplayName_));
      if (!joinedServerVoiceKey_.isEmpty()) maybeSyncVoiceCallForJoinedChannel();
      statusBar()->showMessage(screenShareEnabled_ ? "Screen share enabled" : "Screen share disabled", 3000);
    }
  });

  // Dark mode toggle (profile loads after UI is built, so we set checked state later in loadProfile()).
  connect(darkMode, &QAction::toggled, this, [this](bool on) {
    profile_.darkMode = on;
    saveProfile();
    applyTheme(on);
    refreshCallButton();
  });
  darkModeAction_ = darkMode;

  if (auto* clickable = dynamic_cast<ClickableLabel*>(myAvatarLabel_)) {
    clickable->onClick = [this] {
      const auto file = QFileDialog::getOpenFileName(
          this, "Choose profile picture", QDir::homePath(), "Images (*.png *.jpg *.jpeg *.bmp *.gif)");
      if (file.isEmpty()) return;
      QImage img(file);
      if (img.isNull()) {
        QMessageBox::warning(this, "Invalid image", "Could not load the selected image.");
        return;
      }
      // Save a reasonably sized local copy.
      const QImage saved = img.scaled(256, 256, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QDir().mkpath(QFileInfo(Profile::selfAvatarFile()).absolutePath());
      if (!saved.save(Profile::selfAvatarFile(), "PNG")) {
        QMessageBox::warning(this, "Save failed", "Failed to save profile picture.");
        return;
      }
      profile_.selfAvatarPath = Profile::selfAvatarFile();
      saveProfile();
      refreshSelfProfileWidget();

      // Send a smaller version to peers over the encrypted P2P channel.
      const QImage wire = img.scaled(96, 96, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
      QByteArray out;
      QBuffer buf(&out);
      buf.open(QIODevice::WriteOnly);
      (void)wire.save(&buf, "PNG");
      backend_.setSelfAvatarPng(out);
      statusBar()->showMessage("Profile picture updated", 4000);
    };
  }
}

void MainWindow::loadProfile() {
  QString err;
  profile_ = Profile::load(Profile::defaultPath(), &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  if (profile_.keyPath.isEmpty()) profile_.keyPath = Profile::defaultKeyPath();
  mutedVoicePeerIds_.clear();
  for (const auto& id : profile_.mutedVoicePeerIds) {
    if (id.isEmpty()) continue;
    mutedVoicePeerIds_.insert(id);
  }
  screenShareDisplayName_ = profile_.screen.lastDisplayName;
  screenShareEnabled_ = false;
  if (darkModeAction_) darkModeAction_->setChecked(profile_.darkMode);
}

void MainWindow::saveProfile() {
  profile_.mutedVoicePeerIds.clear();
  for (const auto& id : mutedVoicePeerIds_) {
    if (id.isEmpty()) continue;
    profile_.mutedVoicePeerIds.push_back(id);
  }
  QString err;
  profile_.save(&err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
}

void MainWindow::syncBackendServerMembers() {
  QSet<QString> ids;
  for (const auto& s : profile_.servers) {
    for (const auto& m : s.members) {
      if (m.id.isEmpty()) continue;
      if (!selfId_.isEmpty() && m.id == selfId_) continue;
      if (s.revokedMemberIds.contains(m.id)) continue;
      ids.insert(m.id);
    }
  }
  for (const auto& pi : profile_.pendingServerInvites) {
    if (pi.ownerId.isEmpty()) continue;
    if (!selfId_.isEmpty() && pi.ownerId == selfId_) continue;
    ids.insert(pi.ownerId);
  }
  for (const auto& ownerId : pendingJoinOwners_) {
    if (ownerId.isEmpty()) continue;
    if (!selfId_.isEmpty() && ownerId == selfId_) continue;
    ids.insert(ownerId);
  }
  QStringList list;
  list.reserve(ids.size());
  for (const auto& id : ids) list.push_back(id);
  backend_.setServerMembers(list);
}

bool MainWindow::isFriendAccepted(const QString& peerId) const {
  const auto* f = profile_.findFriend(peerId);
  return f && f->status == Profile::FriendStatus::Accepted;
}

bool MainWindow::canShowNonFriendIdentity(const QString& peerId, const QString& hintedName) const {
  if (peerId == selfId_) return true;
  if (isFriendAccepted(peerId)) return true;
  // Visibility here is based on what the sender actually disclosed,
  // not on the local viewer's privacy preference.
  return !hintedName.trimmed().isEmpty();
}

bool MainWindow::shouldShowNonFriendAvatar(const QString& peerId, const QString& hintedName) const {
  return canShowNonFriendIdentity(peerId, hintedName);
}

QString MainWindow::serverMemberHintName(const QString& peerId) const {
  for (const auto& s : profile_.servers) {
    for (const auto& m : s.members) {
      if (m.id != peerId) continue;
      if (!m.name.trimmed().isEmpty()) return m.name.trimmed();
    }
  }
  return {};
}

QString MainWindow::serverPeerDisplayName(const QString& peerId, const QString& hintedName) const {
  if (peerId == selfId_) {
    const auto selfName = profile_.selfName.trimmed();
    return selfName.isEmpty() ? QString("Me") : selfName;
  }
  if (isFriendAccepted(peerId)) {
    const auto* f = profile_.findFriend(peerId);
    if (f) return friendDisplay(*f);
    if (!hintedName.trimmed().isEmpty()) return hintedName.trimmed();
  }
  if (canShowNonFriendIdentity(peerId, hintedName)) return hintedName.trimmed();
  return "Unknown User";
}

void MainWindow::applyTheme(bool dark) {
  if (callControlsBar_) callControlsBar_->setStyleSheet(callControlsStyleSheet(dark));
  if (!dark) {
    qApp->setStyleSheet({});
    if (videoTiles_) videoTiles_->setStyleSheet("QListWidget { padding: 3px; }");
    if (serverMembersList_) serverMembersList_->setStyleSheet({});
    return;
  }

  // Use stylesheet-only dark mode to avoid Qt style/palette mutation paths that have crashed on some systems.
  qApp->setStyleSheet(
      "QWidget { background-color: #1e1e1e; color: #dcdcdc; }"
      "QLineEdit, QTextEdit, QTextBrowser, QListWidget { background-color: #141414; color: #dcdcdc; border: 1px solid #3a3a3a; }"
      "QListWidget#videoTiles, QListWidget#videoTiles::item { background: transparent; border: none; }"
      "QPushButton { background-color: #2d2d2d; color: #dcdcdc; border: 1px solid #555; padding: 4px 8px; }"
      "QPushButton:hover { background-color: #3a3a3a; }"
      "QMenuBar, QMenu { background-color: #252525; color: #dcdcdc; }"
      "QMenu::item:selected { background-color: #2a82da; color: #000; }"
      "QTabBar::tab { background: #2d2d2d; color: #dcdcdc; padding: 6px 10px; border: 1px solid #555; }"
      "QTabBar::tab:selected { background: #2a82da; color: #000; }"
      "QHeaderView::section { background-color: #2d2d2d; color: #dcdcdc; }"
      "QSplitter::handle { background-color: #2a2a2a; }"
      "QToolTip { color: #000; background-color: #fff; border: 1px solid #aaa; }");

  if (videoTiles_) {
    videoTiles_->setStyleSheet(
        "QListWidget { padding: 3px; background-color: #141414; color: #dcdcdc; border: 1px solid #3a3a3a; }");
  }
  if (serverMembersList_) {
    serverMembersList_->setStyleSheet(
        "QListWidget { background-color: #141414; color: #dcdcdc; border: 1px solid #3a3a3a; }");
  }
}

void MainWindow::refreshSelfProfileWidget() {
  if (myNameLabel_) {
    myNameLabel_->setText(profile_.selfName.isEmpty() ? QString("(no name)") : profile_.selfName);
  }
  if (myAvatarLabel_) {
    const auto seed = selfId_.isEmpty() ? QString("me") : selfId_;
    myAvatarLabel_->setPixmap(loadAvatarOrPlaceholder(seed, profile_.selfAvatarPath, 48));
  }
}

void MainWindow::rebuildFriendList() {
  friendList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status == Profile::FriendStatus::None) continue;
    auto* item = new QListWidgetItem(friendDisplay(f) + statusTag(f.status));
    item->setData(kRolePeerId, f.id);
    item->setData(kRolePresenceState, presenceStateFor(f.id));
    QString avatarPath = f.avatarPath;
    if (avatarPath.isEmpty()) {
      const auto candidate = Profile::peerAvatarFile(f.id);
      if (QFileInfo::exists(candidate)) avatarPath = candidate;
    }
    item->setIcon(QIcon(loadAvatarOrPlaceholder(f.id, avatarPath, 28)));
    item->setSizeHint(QSize(0, 46));
    friendList_->addItem(item);
  }
  // Restore selection if possible.
  if (!selectedPeerId_.isEmpty()) {
    for (int i = 0; i < friendList_->count(); ++i) {
      if (friendList_->item(i)->data(kRolePeerId).toString() == selectedPeerId_) {
        friendList_->setCurrentRow(i);
        break;
      }
    }
  }
}

void MainWindow::rebuildFriendsTab() {
  if (!requestsList_) return;
  requestsList_->clear();
  for (const auto& f : profile_.friends) {
    if (f.status != Profile::FriendStatus::IncomingPending) continue;
    auto* item = new QListWidgetItem(f.id.left(14) + "…");
    item->setData(Qt::UserRole, f.id);
    requestsList_->addItem(item);
  }
  if (myIdEdit_ && !selfId_.isEmpty()) myIdEdit_->setText(selfId_);
}

void MainWindow::selectFriend(const QString& id) {
  selectedServerId_.clear();
  selectedServerChannelId_.clear();
  selectedServerChannelVoice_ = false;
  if (serverList_) serverList_->clearSelection();

  selectedPeerId_ = id;
  refreshHeader();
  if (chatStack_) chatStack_->setVisible(true);
  if (chatStack_ && chatView_) chatStack_->setCurrentWidget(chatView_);
  if (input_) {
    input_->setEnabled(true);
    input_->setPlaceholderText("Type a message…");
    if (auto* composer = input_->parentWidget()) composer->setVisible(true);
  }
  chatView_->clear();
  refreshServerMembersPane();

  if (!chatCache_.contains(id)) {
    QString err;
    chatCache_[id] = profile_.loadChat(id, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  const auto msgs = chatCache_.value(id);
  const auto* fe = profile_.findFriend(id);
  const auto peerLabel = fe ? friendDisplay(*fe) : id.left(14) + "...";
  for (const auto& m : msgs) {
    const auto who = m.incoming ? peerLabel : "You";
    chatView_->append(renderLine(stampFromUtcMs(m.tsMs), who, m.text));
    maybeFetchGifPreviewsFromText(m.text);
  }
}

QString MainWindow::serverChannelChatKey(const QString& serverId, const QString& channelId) const {
  return QString("srv__%1__ch__%2").arg(serverId, channelId);
}

QString MainWindow::currentChatKey() const {
  if (!selectedPeerId_.isEmpty()) return selectedPeerId_;
  if (!selectedServerId_.isEmpty() && !selectedServerChannelId_.isEmpty()) {
    return serverChannelChatKey(selectedServerId_, selectedServerChannelId_);
  }
  return {};
}

void MainWindow::rebuildServerList() {
  if (!serverList_) return;
  syncBackendServerMembers();
  serverList_->clear();
  if (serverInvitesBtn_) {
    serverInvitesBtn_->setText(QString("Pending Invites (%1)").arg(profile_.pendingServerInvites.size()));
  }

  for (const auto& server : profile_.servers) {
    const auto marker = server.expanded ? "v " : "> ";
    auto* header = new QListWidgetItem(marker + (server.name.isEmpty() ? "Untitled Server" : server.name));
    header->setData(kRoleServerItemType, kServerHeaderItem);
    header->setData(kRoleServerId, server.id);
    serverList_->addItem(header);

    if (!server.expanded) continue;
    for (const auto& ch : server.channels) {
      auto* item = new QListWidgetItem(ch.name.isEmpty() ? "channel" : ch.name);
      item->setIcon(channelTypeIcon(ch.voice));
      item->setData(kRoleServerItemType, kServerChannelItem);
      item->setData(kRoleServerId, server.id);
      item->setData(kRoleServerChannelId, ch.id);
      item->setData(kRoleServerChannelVoice, ch.voice);
      serverList_->addItem(item);

      if (!ch.voice) continue;
      QStringList ids;
      const auto key = serverChannelChatKey(server.id, ch.id);
      for (const auto& id : voiceOccupantsByChannel_.value(key)) {
        if (id.isEmpty()) continue;
        if (server.revokedMemberIds.contains(id)) continue;
        if (findMemberIndex(server.members, id) < 0) continue;
        ids.push_back(id);
      }
      std::sort(ids.begin(), ids.end());
      for (const auto& id : ids) {
        const auto* f = profile_.findFriend(id);
        const auto mIdx = findMemberIndex(server.members, id);
        const auto hinted = (mIdx >= 0) ? server.members[mIdx].name : QString();
        const bool unknown = !canShowNonFriendIdentity(id, hinted);
        QString display = serverPeerDisplayName(id, hinted);
        if (isVoiceMuted(id)) display += " [muted]";
        auto* memberItem = new QListWidgetItem(display);
        memberItem->setData(kRoleServerItemType, kServerVoiceMemberItem);
        memberItem->setData(kRoleServerId, server.id);
        memberItem->setData(kRoleServerChannelId, ch.id);
        memberItem->setData(kRolePeerId, id);
        memberItem->setData(kRoleIndentPx, 24);
        memberItem->setData(kRolePresenceState, presenceStateFor(id));
        const bool liveSharing = (id == selfId_)
                                     ? ((webcamEnabled_ || screenShareEnabled_) && localVideoActive_)
                                     : remoteVideoAvailable_.value(
                                           id, remoteVideoFrames_.contains(id) && !remoteVideoFrames_.value(id).isNull());
        memberItem->setData(kRoleVoiceLive, liveSharing);
        QString avatarPath = (id == selfId_) ? profile_.selfAvatarPath : (f ? f->avatarPath : QString());
        if (avatarPath.isEmpty() && shouldShowNonFriendAvatar(id, hinted)) {
          const auto candidate = Profile::peerAvatarFile(id);
          if (QFileInfo::exists(candidate)) avatarPath = candidate;
        }
        memberItem->setIcon(QIcon(loadAvatarOrPlaceholder(id, avatarPath, 18)));
        memberItem->setFlags(Qt::ItemIsEnabled);
        memberItem->setSizeHint(QSize(0, 28));
        if (unknown) {
          auto font = memberItem->font();
          font.setItalic(true);
          memberItem->setFont(font);
        }
        serverList_->addItem(memberItem);
      }
    }
  }

  if (selectedServerId_.isEmpty() || selectedServerChannelId_.isEmpty()) {
    refreshServerMembersPane();
    return;
  }
  for (int i = 0; i < serverList_->count(); ++i) {
    auto* item = serverList_->item(i);
    if (!item) continue;
    if (item->data(kRoleServerItemType).toInt() != kServerChannelItem) continue;
    if (item->data(kRoleServerId).toString() != selectedServerId_) continue;
    if (item->data(kRoleServerChannelId).toString() != selectedServerChannelId_) continue;
    serverList_->setCurrentRow(i);
    break;
  }
  refreshServerMembersPane();
}

void MainWindow::selectServerChannel(const QString& serverId, const QString& channelId, bool voice) {
  selectedPeerId_.clear();
  if (friendList_) friendList_->clearSelection();

  selectedServerId_ = serverId;
  selectedServerChannelId_ = channelId;
  selectedServerChannelVoice_ = voice;

  refreshHeader();
  refreshServerMembersPane();
  if (voice) {
    if (chatStack_) chatStack_->setVisible(false);
    if (input_) {
      input_->clear();
      input_->setEnabled(false);
      input_->setPlaceholderText("Voice channels do not support text messages");
      if (auto* composer = input_->parentWidget()) composer->setVisible(false);
    }
    if (voiceGallery_) voiceGallery_->clear();
    maybeSyncVoiceCallForJoinedChannel();
    refreshVideoPanel();
    return;
  }
  if (chatStack_) chatStack_->setVisible(true);
  if (chatStack_ && chatView_) chatStack_->setCurrentWidget(chatView_);
  if (input_) {
    input_->setEnabled(true);
    input_->setPlaceholderText("Type a message…");
    if (auto* composer = input_->parentWidget()) composer->setVisible(true);
  }
  chatView_->clear();

  const auto key = serverChannelChatKey(serverId, channelId);
  if (!chatCache_.contains(key)) {
    QString err;
    chatCache_[key] = profile_.loadChat(key, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  const auto msgs = chatCache_.value(key);
  for (const auto& m : msgs) {
    bool unknownUser = false;
    QString who = "You";
    if (m.incoming) {
      if (!m.senderId.isEmpty() && canShowNonFriendIdentity(m.senderId, m.senderName)) {
        who = serverPeerDisplayName(m.senderId, m.senderName);
      } else {
        who = "Unknown User";
        unknownUser = true;
      }
    }
    const bool verified = m.verified && !m.senderId.isEmpty();
    chatView_->append(renderServerLine(stampFromUtcMs(m.tsMs), who, m.text, unknownUser, verified));
    maybeFetchGifPreviewsFromText(m.text);
  }
  refreshVideoPanel();
}

void MainWindow::showChatContextMenu(const QPoint& pos) {
  if (!friendList_) return;
  auto* item = friendList_->itemAt(pos);
  if (!item) return;
  const auto peerId = item->data(kRolePeerId).toString();
  if (peerId.isEmpty()) return;

  QMenu menu(this);
  auto* profile = menu.addAction("View profile…");
  menu.addSeparator();
  auto* clearChat = menu.addAction("Clear chat history");
  auto* unfriend = menu.addAction("Unfriend / Remove");

  const auto* f = profile_.findFriend(peerId);
  if (f && f->status == Profile::FriendStatus::IncomingPending) {
    unfriend->setText("Reject request");
  } else if (f && f->status == Profile::FriendStatus::OutgoingPending) {
    unfriend->setText("Cancel request");
  }

  auto* chosen = menu.exec(friendList_->viewport()->mapToGlobal(pos));
  if (!chosen) return;
  if (chosen == profile) {
    showProfilePopup(peerId);
    return;
  }
  if (chosen == clearChat) {
    clearChatFor(peerId);
    return;
  }
  if (chosen == unfriend) {
    removeFriend(peerId);
    return;
  }
}

void MainWindow::showServerContextMenu(const QPoint& pos) {
  if (!serverList_) return;
  auto* item = serverList_->itemAt(pos);
  if (!item) return;

  const int type = item->data(kRoleServerItemType).toInt();
  if (type == kServerVoiceMemberItem) {
    const auto peerId = item->data(kRolePeerId).toString();
    if (peerId.isEmpty()) return;
    const auto serverId = item->data(kRoleServerId).toString();
    showServerPeerContextMenu(peerId, serverId, serverList_->viewport()->mapToGlobal(pos), /*allowProfile*/ true);
    return;
  }
  const auto serverId = item->data(kRoleServerId).toString();
  if (serverId.isEmpty()) return;

  QMenu menu(this);
  QAction* addText = nullptr;
  QAction* addVoice = nullptr;
  QAction* inviteFriend = nullptr;
  QAction* leaveServerAct = nullptr;
  QAction* removeServerAct = nullptr;
  QAction* removeChannelAct = nullptr;
  QAction* renameChannelAct = nullptr;
  QString channelId;
  const auto* server = profile_.findServer(serverId);
  const bool isOwner = (server && !selfId_.isEmpty() && server->ownerId == selfId_);

  if (type == kServerHeaderItem) {
    if (isOwner) {
      inviteFriend = menu.addAction("Invite Friend...");
      if (inviteFriend) menu.addSeparator();
      addText = menu.addAction("Add Text Channel");
      addVoice = menu.addAction("Add Voice Channel");
      menu.addSeparator();
      removeServerAct = menu.addAction("Delete Server");
    } else {
      leaveServerAct = menu.addAction("Leave Server");
    }
  } else if (type == kServerChannelItem) {
    if (!isOwner) return;
    channelId = item->data(kRoleServerChannelId).toString();
    const bool voice = item->data(kRoleServerChannelVoice).toBool();
    renameChannelAct = menu.addAction("Rename Channel...");
    menu.addSeparator();
    if (!voice) addText = menu.addAction("Add Text Channel");
    addVoice = menu.addAction("Add Voice Channel");
    menu.addSeparator();
    removeChannelAct = menu.addAction("Delete Channel");
  }

  auto* chosen = menu.exec(serverList_->viewport()->mapToGlobal(pos));
  if (!chosen) return;

  if (chosen == inviteFriend) {
    inviteFriendToServer(serverId);
    return;
  }
  if (chosen == addText) {
    addChannelToServer(serverId, false);
    return;
  }
  if (chosen == addVoice) {
    addChannelToServer(serverId, true);
    return;
  }
  if (chosen == removeServerAct) {
    removeServer(serverId);
    return;
  }
  if (chosen == leaveServerAct) {
    selectedServerId_ = serverId;
    leaveSelectedServer();
    return;
  }
  if (chosen == removeChannelAct) {
    removeServerChannel(serverId, channelId);
    return;
  }
  if (chosen == renameChannelAct) {
    renameServerChannel(serverId, channelId);
    return;
  }
}

void MainWindow::showServerMemberContextMenu(const QPoint& pos) {
  if (!serverMembersList_) return;
  auto* item = serverMembersList_->itemAt(pos);
  if (!item) return;
  if (selectedServerId_.isEmpty()) return;

  const auto memberId = item->data(kRolePeerId).toString();
  if (memberId.isEmpty()) return;
  showServerPeerContextMenu(memberId,
                            selectedServerId_,
                            serverMembersList_->viewport()->mapToGlobal(pos),
                            /*allowProfile*/ true);
}

void MainWindow::showServerPeerContextMenu(const QString& peerId,
                                           const QString& serverId,
                                           const QPoint& globalPos,
                                           bool allowProfile) {
  if (peerId.isEmpty()) return;
  const auto* server = serverId.isEmpty() ? nullptr : profile_.findServer(serverId);
  const bool canKick = (server && !selfId_.isEmpty() && server->ownerId == selfId_ && peerId != selfId_);
  const bool canMute = (peerId != selfId_);
  const bool canToggleSelfPreview = (!serverId.isEmpty() && !selfId_.isEmpty() && peerId == selfId_);
  const bool canWatchControl =
      (peerId != selfId_) && (peerId == activeCallPeer_ || remoteVideoAvailable_.value(peerId, false) ||
                              remoteVideoFrames_.contains(peerId));
  QMenu menu(this);
  QAction* profileAct = nullptr;
  QAction* muteAct = nullptr;
  QAction* watchAct = nullptr;
  QAction* selfPreviewAct = nullptr;
  QAction* kickAct = nullptr;
  if (allowProfile) profileAct = menu.addAction("View profile...");
  if (canToggleSelfPreview) {
    selfPreviewAct =
        menu.addAction(selfStreamPreviewHiddenInServer_ ? "Show my stream preview" : "Hide my stream preview");
  }
  if (canMute) muteAct = menu.addAction(isVoiceMuted(peerId) ? "Unmute in voice channels" : "Mute in voice channels");
  if (canWatchControl) {
    watchAct = menu.addAction(isWatchingPeerVideo(peerId) ? "Stop watching stream" : "Watch stream");
  }
  if (canKick) {
    if (profileAct || selfPreviewAct || muteAct || watchAct) menu.addSeparator();
    kickAct = menu.addAction("Kick user");
  }

  if (!profileAct && !selfPreviewAct && !muteAct && !watchAct && !kickAct) return;
  auto* chosen = menu.exec(globalPos);
  if (!chosen) return;
  if (chosen == profileAct) {
    showProfilePopup(peerId);
    return;
  }
  if (chosen == selfPreviewAct) {
    setSelfStreamPreviewHiddenInServer(!selfStreamPreviewHiddenInServer_);
    return;
  }
  if (chosen == muteAct) {
    setVoiceMuted(peerId, !isVoiceMuted(peerId));
    return;
  }
  if (chosen == watchAct) {
    setPeerVideoWatching(peerId, !isWatchingPeerVideo(peerId));
    return;
  }
  if (chosen == kickAct && server) {
    const auto who = serverPeerDisplayName(peerId);
    const auto confirm = QMessageBox::question(this,
                                               "Kick user",
                                               QString("Kick %1 from this server?").arg(who));
    if (confirm != QMessageBox::Yes) return;
    kickServerMember(serverId, peerId);
    return;
  }
}

bool MainWindow::isVoiceMuted(const QString& peerId) const {
  return mutedVoicePeerIds_.contains(peerId);
}

bool MainWindow::isWatchingPeerVideo(const QString& peerId) const {
  if (peerId.isEmpty()) return false;
  return !stoppedWatchingVideoPeerIds_.contains(peerId);
}

void MainWindow::setSelfStreamPreviewHiddenInServer(bool hidden) {
  if (selfStreamPreviewHiddenInServer_ == hidden) return;
  selfStreamPreviewHiddenInServer_ = hidden;
  if (hidden) {
    localVideoActive_ = false;
    localVideoFrame_ = QImage();
    if (expandedVideoPeerId_ == selfId_) expandedVideoPeerId_.clear();
  }
  refreshVideoPanel();
  statusBar()->showMessage(hidden ? "Hid your stream preview in server voice channels"
                                  : "Showing your stream preview in server voice channels",
                           3500);
}

void MainWindow::setPeerVideoWatching(const QString& peerId, bool watching) {
  if (peerId.isEmpty() || peerId == selfId_) return;
  const bool current = isWatchingPeerVideo(peerId);
  if (current == watching) return;

  if (watching) {
    stoppedWatchingVideoPeerIds_.remove(peerId);
  } else {
    stoppedWatchingVideoPeerIds_.insert(peerId);
    remoteVideoFrames_.remove(peerId);
    if (remoteVideoPeerId_ == peerId) remoteVideoPeerId_.clear();
    remoteVideoActive_ = !remoteVideoFrames_.isEmpty();
    if (expandedVideoPeerId_ == peerId) expandedVideoPeerId_.clear();
  }

  backend_.setPeerVideoWatch(peerId, watching);
  rebuildServerList();
  refreshVideoPanel();
  statusBar()->showMessage(
      watching ? QString("Watching %1's stream").arg(serverPeerDisplayName(peerId))
               : QString("Stopped watching %1's stream").arg(serverPeerDisplayName(peerId)),
      3500);
}

void MainWindow::setVoiceMuted(const QString& peerId, bool muted) {
  if (peerId.isEmpty() || peerId == selfId_) return;
  const bool had = mutedVoicePeerIds_.contains(peerId);
  if (muted == had) return;

  if (muted) {
    mutedVoicePeerIds_.insert(peerId);
  } else {
    mutedVoicePeerIds_.remove(peerId);
  }
  backend_.setPeerMuted(peerId, muted);
  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  statusBar()->showMessage(
      muted ? QString("Muted %1 in voice channels").arg(serverPeerDisplayName(peerId))
            : QString("Unmuted %1 in voice channels").arg(serverPeerDisplayName(peerId)),
      4000);
}

void MainWindow::addServerDialog() {
  bool ok = false;
  const auto name =
      QInputDialog::getText(this, "Create Server", "Server name:", QLineEdit::Normal, "New Server", &ok).trimmed();
  if (!ok) return;

  Profile::ServerEntry s;
  s.id = makeServerObjectId();
  s.name = name.isEmpty() ? "New Server" : name;
  s.ownerId = selfId_;
  s.expanded = true;
  Profile::ServerChannel text;
  text.id = makeServerObjectId();
  text.name = "general";
  text.voice = false;
  Profile::ServerChannel voice;
  voice.id = makeServerObjectId();
  voice.name = "voice";
  voice.voice = true;
  s.channels.push_back(text);
  s.channels.push_back(voice);
  Profile::ServerMember selfMember;
  selfMember.id = selfId_;
  selfMember.name = profile_.selfName;
  s.members.push_back(selfMember);
  profile_.servers.push_back(s);
  saveProfile();
  rebuildServerList();
  statusBar()->showMessage("Server created", 4000);
}

void MainWindow::addChannelToServer(const QString& serverId, bool voice) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;

  bool ok = false;
  const auto defaultName = voice ? "voice" : "text";
  const auto name =
      QInputDialog::getText(this, "Add Channel", "Channel name:", QLineEdit::Normal, defaultName, &ok).trimmed();
  if (!ok) return;

  Profile::ServerChannel c;
  c.id = makeServerObjectId();
  c.name = name.isEmpty() ? defaultName : name;
  c.voice = voice;
  s->channels.push_back(c);
  s->expanded = true;
  if (s->ownerId == selfId_) broadcastServerMemberSync(*s);
  saveProfile();
  rebuildServerList();
  statusBar()->showMessage("Channel added", 3000);
}

void MainWindow::renameServerChannel(const QString& serverId, const QString& channelId) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (s->ownerId != selfId_) return;

  Profile::ServerChannel* target = nullptr;
  for (auto& ch : s->channels) {
    if (ch.id != channelId) continue;
    target = &ch;
    break;
  }
  if (!target) return;

  const auto current = target->name.isEmpty() ? (target->voice ? "voice" : "channel") : target->name;
  bool ok = false;
  const auto name = QInputDialog::getText(
      this, "Rename Channel", "Channel name:", QLineEdit::Normal, current, &ok).trimmed();
  if (!ok) return;
  if (name.isEmpty() || name == target->name) return;

  target->name = name;
  if (s->ownerId == selfId_) broadcastServerMemberSync(*s);
  saveProfile();
  rebuildServerList();
  refreshHeader();
  statusBar()->showMessage("Channel renamed", 3000);
}

void MainWindow::inviteFriendToServer(const QString& serverId) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (selfId_.isEmpty()) {
    QMessageBox::warning(this, "Not ready", "Still connecting; try again in a moment.");
    return;
  }
  if (s->ownerId != selfId_) {
    QMessageBox::warning(this, "Not owner", "Only the server owner can invite friends.");
    return;
  }

  QStringList labels;
  QVector<QString> ids;
  for (const auto& f : profile_.friends) {
    if (f.status != Profile::FriendStatus::Accepted) continue;
    if (f.id == selfId_) continue;
    labels.push_back(QString("%1 (%2...)").arg(friendDisplay(f), f.id.left(12)));
    ids.push_back(f.id);
  }
  if (ids.isEmpty()) {
    QMessageBox::information(this, "No friends", "You need at least one accepted friend to invite.");
    return;
  }

  bool ok = false;
  const auto chosen = QInputDialog::getItem(this, "Invite Friend", "Friend:", labels, 0, false, &ok);
  if (!ok || chosen.isEmpty()) return;
  const int idx = labels.indexOf(chosen);
  if (idx < 0 || idx >= ids.size()) return;
  const auto targetId = ids[idx];

  QJsonObject payload;
  payload["server_id"] = s->id;
  payload["server_name"] = s->name;
  payload["owner_id"] = s->ownerId;
  payload["invited_id"] = targetId;
  payload["issued_ms"] = static_cast<double>(nowUtcMs());
  payload["nonce"] = makeServerObjectId();
  payload["channels"] = channelsToJson(s->channels);

  backend_.sendSignedControl(targetId, "server_invite", compactJsonString(payload));
  statusBar()->showMessage("Server invite sent", 4000);
}

void MainWindow::reviewPendingServerInvites() {
  if (profile_.pendingServerInvites.isEmpty()) {
    QMessageBox::information(this, "Pending Invites", "No pending server invites.");
    return;
  }
  if (selfId_.isEmpty()) {
    QMessageBox::warning(this, "Not ready", "Still connecting; try again in a moment.");
    return;
  }

  QStringList labels;
  for (const auto& pi : profile_.pendingServerInvites) {
    QString serverName = pi.serverId;
    QJsonParseError pe;
    const auto doc = QJsonDocument::fromJson(pi.payloadJson.toUtf8(), &pe);
    if (pe.error == QJsonParseError::NoError && doc.isObject()) {
      serverName = doc.object().value("server_name").toString(serverName);
    }
    labels.push_back(QString("%1 (owner %2...)").arg(serverName, pi.ownerId.left(10)));
  }

  bool ok = false;
  const auto chosen = QInputDialog::getItem(this, "Pending Invites", "Invite:", labels, 0, false, &ok);
  if (!ok || chosen.isEmpty()) return;
  const int idx = labels.indexOf(chosen);
  if (idx < 0 || idx >= profile_.pendingServerInvites.size()) return;
  const auto invite = profile_.pendingServerInvites[idx];

  QJsonParseError pe;
  const auto doc = QJsonDocument::fromJson(invite.payloadJson.toUtf8(), &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isObject()) {
    QMessageBox::warning(this, "Invite invalid", "This invite payload is corrupted.");
    return;
  }
  const auto payload = doc.object();
  const auto serverName = payload.value("server_name").toString(invite.serverId);
  const auto ownerId = payload.value("owner_id").toString(invite.ownerId);
  const auto serverId = payload.value("server_id").toString(invite.serverId);

  auto decision = QMessageBox::question(this,
                                        "Accept Server Invite",
                                        QString("Accept invite to \"%1\" from %2...?").arg(serverName, ownerId.left(12)));
  if (decision != QMessageBox::Yes) {
    profile_.pendingServerInvites.removeAt(idx);
    saveProfile();
    rebuildServerList();
    return;
  }

  QJsonObject req;
  req["server_id"] = serverId;
  req["owner_id"] = ownerId;
  req["invite_payload"] = invite.payloadJson;
  req["invite_sig"] = invite.signature;
  req["requester_id"] = selfId_;
  req["requester_name"] =
      (profile_.shareIdentityWithNonFriendsInServers || isFriendAccepted(ownerId)) ? profile_.selfName : QString();
  req["issued_ms"] = static_cast<double>(nowUtcMs());
  req["nonce"] = makeServerObjectId();
  pendingJoinOwners_.insert(ownerId);
  syncBackendServerMembers();
  backend_.sendSignedControl(ownerId, "server_join_request", compactJsonString(req));
  profile_.pendingServerInvites.removeAt(idx);
  saveProfile();
  rebuildServerList();
  statusBar()->showMessage("Join request sent to server owner", 5000);
}

void MainWindow::handleSignedControl(const QString& peerId,
                                     const QString& kind,
                                     const QString& payloadJsonCompact,
                                     const QString& signature,
                                     const QString& fromId) {
  if (peerId != fromId) return;
  QJsonParseError pe;
  const auto doc = QJsonDocument::fromJson(payloadJsonCompact.toUtf8(), &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isObject()) return;
  const auto payload = doc.object();

  if (kind == "server_invite") {
    handleServerInvite(peerId, payload, signature);
    return;
  }
  if (kind == "server_join_request") {
    handleServerJoinRequest(peerId, payload);
    return;
  }
  if (kind == "server_membership_cert") {
    handleServerMembershipCert(peerId, payload, signature);
    return;
  }
  if (kind == "server_member_sync") {
    handleServerMemberSync(peerId, payload, signature);
    return;
  }
  if (kind == "server_leave") {
    handleServerLeave(peerId, payload, signature);
    return;
  }
  if (kind == "server_revocation") {
    handleServerRevocation(peerId, payload, signature);
    return;
  }
  if (kind == "server_channel_text") {
    handleServerChannelText(peerId, payload, signature);
    return;
  }
  if (kind == "server_voice_presence") {
    handleServerVoicePresence(peerId, payload, signature);
    return;
  }
}

void MainWindow::handleUnsignedControl(const QString& peerId,
                                       const QString& kind,
                                       const QString& payloadJsonCompact,
                                       const QString& fromId) {
  if (profile_.signedOnlyServerMessages) return;
  if (peerId != fromId) return;
  QJsonParseError pe;
  const auto doc = QJsonDocument::fromJson(payloadJsonCompact.toUtf8(), &pe);
  if (pe.error != QJsonParseError::NoError || !doc.isObject()) return;
  const auto payload = doc.object();

  if (kind == "server_global_say") {
    handleServerGlobalSay(peerId, payload);
    return;
  }
}

void MainWindow::handleServerInvite(const QString& peerId, const QJsonObject& payload, const QString& signature) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto invitedId = payload.value("invited_id").toString();
  const auto serverId = payload.value("server_id").toString();
  if (ownerId.isEmpty() || invitedId.isEmpty() || serverId.isEmpty()) return;
  if (ownerId != peerId) return;
  if (invitedId != selfId_) return;
  const auto payloadJson = compactJsonString(payload);
  if (!verifyCanonicalJsonSignature(ownerId, payloadJson, signature)) return;

  auto* existing = profile_.findPendingServerInvite(serverId, ownerId);
  if (!existing) {
    Profile::PendingServerInvite pi;
    pi.serverId = serverId;
    pi.ownerId = ownerId;
    pi.payloadJson = payloadJson;
    pi.signature = signature;
    profile_.pendingServerInvites.push_back(pi);
  } else {
    existing->payloadJson = payloadJson;
    existing->signature = signature;
  }
  saveProfile();
  rebuildServerList();

  const auto serverName = payload.value("server_name").toString(serverId);
  statusBar()->showMessage(QString("Server invite received: %1").arg(serverName), 6000);
}

void MainWindow::handleServerJoinRequest(const QString& peerId, const QJsonObject& payload) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto requesterId = payload.value("requester_id").toString();
  const auto serverId = payload.value("server_id").toString();
  const auto invitePayloadRaw = payload.value("invite_payload").toString();
  const auto inviteSig = payload.value("invite_sig").toString();
  if (ownerId.isEmpty() || requesterId.isEmpty() || serverId.isEmpty()) return;
  if (ownerId != selfId_) return;
  if (requesterId != peerId) return;
  if (invitePayloadRaw.isEmpty() || inviteSig.isEmpty()) return;

  QJsonParseError pe;
  const auto inviteDoc = QJsonDocument::fromJson(invitePayloadRaw.toUtf8(), &pe);
  if (pe.error != QJsonParseError::NoError || !inviteDoc.isObject()) return;
  const auto invitePayload = inviteDoc.object();
  if (invitePayload.value("owner_id").toString() != selfId_) return;
  if (invitePayload.value("invited_id").toString() != requesterId) return;
  if (invitePayload.value("server_id").toString() != serverId) return;
  if (!verifyCanonicalJsonSignature(selfId_, invitePayloadRaw, inviteSig)) return;

  auto* server = profile_.findServer(serverId);
  if (!server) return;
  if (!server->ownerId.isEmpty() && server->ownerId != selfId_) return;
  if (server->ownerId.isEmpty()) server->ownerId = selfId_;
  for (int i = 0; i < server->revokedMemberIds.size(); ++i) {
    if (server->revokedMemberIds[i] != requesterId) continue;
    server->revokedMemberIds.removeAt(i);
    --i;
  }
  const auto requesterName = payload.value("requester_name").toString();
  const int existing = findMemberIndex(server->members, requesterId);
  if (existing < 0) {
    Profile::ServerMember m;
    m.id = requesterId;
    m.name = requesterName;
    server->members.push_back(m);
  } else if (!requesterName.isEmpty()) {
    server->members[existing].name = requesterName;
  }
  if (findMemberIndex(server->members, selfId_) < 0) {
    Profile::ServerMember selfMember;
    selfMember.id = selfId_;
    selfMember.name = profile_.selfName;
    server->members.push_back(selfMember);
  }

  QJsonObject cert;
  cert["server_id"] = server->id;
  cert["server_name"] = server->name;
  cert["owner_id"] = selfId_;
  cert["member_id"] = requesterId;
  cert["issued_ms"] = static_cast<double>(nowUtcMs());
  cert["nonce"] = makeServerObjectId();
  cert["channels"] = channelsToJson(server->channels);
  cert["members"] = membersToJson(server->members);

  syncBackendServerMembers();
  backend_.sendSignedControl(requesterId, "server_membership_cert", compactJsonString(cert));
  broadcastServerMemberSync(*server);
  saveProfile();
  refreshServerMembersPane();
  statusBar()->showMessage(QString("Approved server join for %1...").arg(requesterId.left(12)), 5000);
}

void MainWindow::handleServerMembershipCert(const QString& peerId,
                                            const QJsonObject& payload,
                                            const QString& signature) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto memberId = payload.value("member_id").toString();
  const auto serverId = payload.value("server_id").toString();
  if (ownerId.isEmpty() || memberId.isEmpty() || serverId.isEmpty()) return;
  if (ownerId != peerId) return;
  if (memberId != selfId_) return;

  auto* server = profile_.findServer(serverId);
  if (!server) {
    Profile::ServerEntry s;
    s.id = serverId;
    s.name = payload.value("server_name").toString(serverId);
    s.ownerId = ownerId;
    s.expanded = true;
    s.channels = channelsFromJson(payload.value("channels").toArray());
    s.members = membersFromJson(payload.value("members").toArray());
    if (findMemberIndex(s.members, selfId_) < 0) {
      Profile::ServerMember selfMember;
      selfMember.id = selfId_;
      selfMember.name = profile_.selfName;
      s.members.push_back(selfMember);
    }
    s.membershipCertPayload = compactJsonString(payload);
    s.membershipCertSignature = signature;
    profile_.servers.push_back(s);
  } else {
    server->name = payload.value("server_name").toString(server->name);
    server->ownerId = ownerId;
    server->channels = channelsFromJson(payload.value("channels").toArray());
    const auto members = membersFromJson(payload.value("members").toArray());
    if (!members.isEmpty()) server->members = members;
    if (findMemberIndex(server->members, selfId_) < 0) {
      Profile::ServerMember selfMember;
      selfMember.id = selfId_;
      selfMember.name = profile_.selfName;
      server->members.push_back(selfMember);
    }
    server->membershipCertPayload = compactJsonString(payload);
    server->membershipCertSignature = signature;
  }
  sanitizeVoiceOccupantsForServer(serverId);

  for (int i = 0; i < profile_.pendingServerInvites.size(); ++i) {
    if (profile_.pendingServerInvites[i].serverId == serverId &&
        profile_.pendingServerInvites[i].ownerId == ownerId) {
      profile_.pendingServerInvites.removeAt(i);
      break;
    }
  }
  pendingJoinOwners_.remove(ownerId);

  saveProfile();
  syncBackendServerMembers();
  rebuildServerList();
  refreshServerMembersPane();
  statusBar()->showMessage(QString("Joined server %1").arg(payload.value("server_name").toString(serverId)), 5000);
}

void MainWindow::broadcastServerMemberSync(const Profile::ServerEntry& server) {
  if (server.ownerId != selfId_) return;
  QJsonObject payload;
  payload["server_id"] = server.id;
  payload["server_name"] = server.name;
  payload["owner_id"] = selfId_;
  payload["channels"] = channelsToJson(server.channels);
  payload["members"] = membersToJson(server.members);
  QJsonArray revoked;
  for (const auto& r : server.revokedMemberIds) revoked.push_back(r);
  payload["revoked_member_ids"] = revoked;
  payload["issued_ms"] = static_cast<double>(nowUtcMs());
  payload["nonce"] = makeServerObjectId();

  for (const auto& m : server.members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    if (server.revokedMemberIds.contains(m.id)) continue;
    backend_.sendSignedControl(m.id, "server_member_sync", compactJsonString(payload));
  }
}

void MainWindow::handleServerMemberSync(const QString& peerId, const QJsonObject& payload, const QString& signature) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto serverId = payload.value("server_id").toString();
  if (ownerId.isEmpty() || serverId.isEmpty()) return;
  if (ownerId != peerId) return;

  auto* server = profile_.findServer(serverId);
  if (!server) return;
  if (!server->ownerId.isEmpty() && server->ownerId != ownerId) return;
  server->ownerId = ownerId;
  server->name = payload.value("server_name").toString(server->name);
  if (payload.value("channels").isArray()) {
    server->channels = channelsFromJson(payload.value("channels").toArray());
  }
  server->members = membersFromJson(payload.value("members").toArray());
  if (findMemberIndex(server->members, selfId_) < 0) {
    Profile::ServerMember selfMember;
    selfMember.id = selfId_;
    selfMember.name = profile_.selfName;
    server->members.push_back(selfMember);
  }
  server->revokedMemberIds.clear();
  for (const auto& rv : payload.value("revoked_member_ids").toArray()) {
    if (rv.isString() && !rv.toString().isEmpty()) server->revokedMemberIds.push_back(rv.toString());
  }
  sanitizeVoiceOccupantsForServer(serverId);
  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  maybeSyncVoiceCallForJoinedChannel();
}

void MainWindow::handleServerLeave(const QString& peerId, const QJsonObject& payload, const QString&) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto serverId = payload.value("server_id").toString();
  const auto memberId = payload.value("member_id").toString();
  if (ownerId != selfId_) return;
  if (serverId.isEmpty() || memberId.isEmpty()) return;
  if (memberId != peerId) return;

  auto* server = profile_.findServer(serverId);
  if (!server) return;
  if (!server->ownerId.isEmpty() && server->ownerId != selfId_) return;

  for (int i = 0; i < server->members.size(); ++i) {
    if (server->members[i].id == memberId) {
      server->members.removeAt(i);
      break;
    }
  }
  for (int i = 0; i < server->revokedMemberIds.size(); ++i) {
    if (server->revokedMemberIds[i] != memberId) continue;
    server->revokedMemberIds.removeAt(i);
    --i;
  }
  sanitizeVoiceOccupantsForServer(serverId);

  QJsonObject rev;
  rev["server_id"] = serverId;
  rev["owner_id"] = selfId_;
  rev["member_id"] = memberId;
  rev["reason"] = "left";
  rev["issued_ms"] = static_cast<double>(nowUtcMs());
  rev["nonce"] = makeServerObjectId();
  const auto revCompact = compactJsonString(rev);

  backend_.sendSignedControl(memberId, "server_revocation", revCompact);
  for (const auto& m : server->members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    backend_.sendSignedControl(m.id, "server_revocation", revCompact);
  }
  broadcastServerMemberSync(*server);

  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  maybeSyncVoiceCallForJoinedChannel();
  statusBar()->showMessage(QString("%1 left server").arg(memberId.left(12)), 4000);
}

void MainWindow::handleServerRevocation(const QString& peerId, const QJsonObject& payload, const QString& signature) {
  const auto ownerId = payload.value("owner_id").toString();
  const auto serverId = payload.value("server_id").toString();
  const auto memberId = payload.value("member_id").toString();
  if (ownerId.isEmpty() || serverId.isEmpty() || memberId.isEmpty()) return;
  if (ownerId != peerId) return;

  auto* server = profile_.findServer(serverId);
  if (!server) return;
  if (!server->ownerId.isEmpty() && server->ownerId != ownerId) return;

  if (memberId == selfId_) {
    removeServer(serverId);
    statusBar()->showMessage("You were removed from server", 5000);
    return;
  }

  for (int i = 0; i < server->members.size(); ++i) {
    if (server->members[i].id == memberId) {
      server->members.removeAt(i);
      break;
    }
  }
  for (int i = 0; i < server->revokedMemberIds.size(); ++i) {
    if (server->revokedMemberIds[i] != memberId) continue;
    server->revokedMemberIds.removeAt(i);
    --i;
  }
  sanitizeVoiceOccupantsForServer(serverId);
  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  maybeSyncVoiceCallForJoinedChannel();
}

void MainWindow::broadcastServerText(const QString& serverId, const QString& channelId, const QString& text) {
  if (text.isEmpty()) return;
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  bool channelOk = false;
  for (const auto& ch : s->channels) {
    if (ch.id == channelId && !ch.voice) {
      channelOk = true;
      break;
    }
  }
  if (!channelOk) return;
  if (s->revokedMemberIds.contains(selfId_)) return;

  for (const auto& m : s->members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    if (s->revokedMemberIds.contains(m.id)) continue;
    QJsonObject payload;
    payload["server_id"] = serverId;
    payload["channel_id"] = channelId;
    payload["member_id"] = selfId_;
    payload["member_name"] =
        (profile_.shareIdentityWithNonFriendsInServers || isFriendAccepted(m.id)) ? profile_.selfName : QString();
    payload["text"] = text;
    payload["issued_ms"] = static_cast<double>(nowUtcMs());
    payload["nonce"] = makeServerObjectId();
    backend_.sendSignedControl(m.id, "server_channel_text", compactJsonString(payload));
  }
  appendServerChannelMessage(serverId, channelId, selfId_, profile_.selfName, text, false, true);
}

void MainWindow::broadcastServerGlobalSay(const QString& serverId, const QString& text) {
  if (text.isEmpty()) return;
  if (profile_.signedOnlyServerMessages) {
    statusBar()->showMessage("Signed-only mode is enabled; /say is disabled", 5000);
    return;
  }
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (s->ownerId != selfId_) {
    statusBar()->showMessage("Only the server owner can use /say", 4000);
    return;
  }
  if (s->revokedMemberIds.contains(selfId_)) return;

  QJsonObject payload;
  payload["server_id"] = serverId;
  payload["member_id"] = selfId_;
  payload["member_name"] = profile_.selfName;
  payload["text"] = text;
  payload["issued_ms"] = static_cast<double>(nowUtcMs());
  payload["nonce"] = makeServerObjectId();

  for (const auto& m : s->members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    if (s->revokedMemberIds.contains(m.id)) continue;
    backend_.sendUnsignedControl(m.id, "server_global_say", compactJsonString(payload));
  }

  const auto line = "[GLOBAL] " + text;
  for (const auto& ch : s->channels) {
    if (ch.voice) continue;
    appendServerChannelMessage(serverId, ch.id, selfId_, profile_.selfName, line, false, false);
  }
}

void MainWindow::broadcastVoicePresence(const QString& serverId, const QString& channelId, bool joined) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  bool channelOk = false;
  for (const auto& ch : s->channels) {
    if (ch.id == channelId && ch.voice) {
      channelOk = true;
      break;
    }
  }
  if (!channelOk) return;
  if (s->revokedMemberIds.contains(selfId_)) return;

  QJsonObject payload;
  payload["server_id"] = serverId;
  payload["channel_id"] = channelId;
  payload["member_id"] = selfId_;
  payload["joined"] = joined;
  payload["issued_ms"] = static_cast<double>(nowUtcMs());
  payload["nonce"] = makeServerObjectId();

  for (const auto& m : s->members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    if (s->revokedMemberIds.contains(m.id)) continue;
    backend_.sendSignedControl(m.id, "server_voice_presence", compactJsonString(payload));
  }
}

void MainWindow::appendServerChannelMessage(const QString& serverId,
                                            const QString& channelId,
                                            const QString& senderId,
                                            const QString& senderName,
                                            const QString& text,
                                            bool incoming,
                                            bool verified) {
  const auto key = serverChannelChatKey(serverId, channelId);
  if (!chatCache_.contains(key)) {
    QString err;
    chatCache_[key] = profile_.loadChat(key, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  auto& msgs = chatCache_[key];
  Profile::ChatMessage m;
  m.tsMs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
  m.incoming = incoming;
  m.senderId = senderId;
  m.senderName = canShowNonFriendIdentity(senderId, senderName) ? senderName : QString();
  m.senderUnknown = incoming && !senderId.isEmpty() && !canShowNonFriendIdentity(senderId, senderName);
  m.verified = verified;
  m.text = text;
  msgs.push_back(m);
  while (msgs.size() > 500) msgs.removeFirst();

  QString err;
  profile_.saveChat(key, msgs, &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);

  QString who = "You";
  bool unknownUser = false;
  if (incoming) {
    if (canShowNonFriendIdentity(senderId, senderName)) {
      who = serverPeerDisplayName(senderId, senderName);
    } else {
      who = "Unknown User";
      unknownUser = true;
    }
  }
  if (key == currentChatKey()) {
    const bool msgVerified = m.verified && !m.senderId.isEmpty();
    chatView_->append(renderServerLine(stampFromUtcMs(m.tsMs), who, text, unknownUser, msgVerified));
    maybeFetchGifPreviewsFromText(text);
  }
}

void MainWindow::handleServerChannelText(const QString& peerId, const QJsonObject& payload, const QString&) {
  const auto serverId = payload.value("server_id").toString();
  const auto channelId = payload.value("channel_id").toString();
  const auto memberId = payload.value("member_id").toString();
  const auto memberName = payload.value("member_name").toString();
  const auto text = payload.value("text").toString();
  if (serverId.isEmpty() || channelId.isEmpty() || memberId.isEmpty() || text.isEmpty()) return;
  if (memberId != peerId) return;

  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (s->revokedMemberIds.contains(memberId)) return;
  if (findMemberIndex(s->members, memberId) < 0) return;
  bool channelOk = false;
  for (const auto& ch : s->channels) {
    if (ch.id == channelId && !ch.voice) {
      channelOk = true;
      break;
    }
  }
  if (!channelOk) return;
  appendServerChannelMessage(serverId, channelId, memberId, memberName, text, true, true);
}

void MainWindow::handleServerVoicePresence(const QString& peerId, const QJsonObject& payload, const QString&) {
  const auto serverId = payload.value("server_id").toString();
  const auto channelId = payload.value("channel_id").toString();
  const auto memberId = payload.value("member_id").toString();
  const bool joined = payload.value("joined").toBool(false);
  if (serverId.isEmpty() || channelId.isEmpty() || memberId.isEmpty()) return;
  if (memberId != peerId) return;

  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (s->revokedMemberIds.contains(memberId)) return;
  if (findMemberIndex(s->members, memberId) < 0) return;
  bool channelOk = false;
  for (const auto& ch : s->channels) {
    if (ch.id == channelId && ch.voice) {
      channelOk = true;
      break;
    }
  }
  if (!channelOk) return;

  const auto key = serverChannelChatKey(serverId, channelId);
  if (joined) {
    voiceOccupantsByChannel_[key].insert(memberId);
  } else {
    voiceOccupantsByChannel_[key].remove(memberId);
  }
  rebuildServerList();
  refreshServerMembersPane();
  maybeSyncVoiceCallForJoinedChannel();
}

void MainWindow::handleServerGlobalSay(const QString& peerId, const QJsonObject& payload) {
  const auto serverId = payload.value("server_id").toString();
  const auto memberId = payload.value("member_id").toString();
  const auto memberName = payload.value("member_name").toString();
  const auto text = payload.value("text").toString();
  if (serverId.isEmpty() || memberId.isEmpty() || text.isEmpty()) return;
  if (memberId != peerId) return;

  auto* s = profile_.findServer(serverId);
  if (!s) return;
  if (s->ownerId != peerId) return;
  if (s->revokedMemberIds.contains(memberId)) return;
  if (findMemberIndex(s->members, memberId) < 0) return;

  const auto line = "[GLOBAL] " + text;
  for (const auto& ch : s->channels) {
    if (ch.voice) continue;
    appendServerChannelMessage(serverId, ch.id, memberId, memberName, line, true, false);
  }
}

QString MainWindow::joinedVoiceServerId() const {
  if (!joinedServerVoiceKey_.startsWith("srv__")) return {};
  const int sep = joinedServerVoiceKey_.indexOf("__ch__");
  if (sep <= 5) return {};
  return joinedServerVoiceKey_.mid(5, sep - 5);
}

QString MainWindow::joinedVoiceChannelId() const {
  const int sep = joinedServerVoiceKey_.indexOf("__ch__");
  if (sep < 0) return {};
  return joinedServerVoiceKey_.mid(sep + 6);
}

void MainWindow::announceJoinedVoicePresence() {
  if (joinedServerVoiceKey_.isEmpty()) return;
  const auto serverId = joinedVoiceServerId();
  const auto channelId = joinedVoiceChannelId();
  if (serverId.isEmpty() || channelId.isEmpty()) return;
  broadcastVoicePresence(serverId, channelId, true);
}

void MainWindow::sanitizeVoiceOccupantsForServer(const QString& serverId) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  QSet<QString> allowed;
  for (const auto& m : s->members) {
    if (m.id.isEmpty()) continue;
    if (s->revokedMemberIds.contains(m.id)) continue;
    allowed.insert(m.id);
  }

  const QString prefix = QString("srv__%1__ch__").arg(serverId);
  for (auto it = voiceOccupantsByChannel_.begin(); it != voiceOccupantsByChannel_.end(); ++it) {
    if (!it.key().startsWith(prefix)) continue;
    QSet<QString> next;
    for (const auto& id : it.value()) {
      if (allowed.contains(id)) next.insert(id);
    }
    it.value() = next;
  }
}

void MainWindow::maybeSyncVoiceCallForJoinedChannel() {
  if (joinedServerVoiceKey_.isEmpty()) {
    backend_.stopVoiceChannel();
    return;
  }

  auto peers = voiceOccupantsByChannel_.value(joinedServerVoiceKey_);
  peers.remove(selfId_);
  for (auto it = peers.begin(); it != peers.end();) {
    if (presenceStateFor(*it) == kPresenceOffline) {
      it = peers.erase(it);
    } else {
      ++it;
    }
  }

  if (peers.isEmpty()) {
    backend_.stopVoiceChannel();
    return;
  }

  QStringList sortedPeers;
  for (const auto& p : peers) sortedPeers.push_back(p);
  std::sort(sortedPeers.begin(), sortedPeers.end());
  backend_.setVoiceChannelPeers(sortedPeers,
                                voiceSettingsFromProfile(profile_.audio,
                                                         profile_.video,
                                                         profile_.screen,
                                                         localMicMuted_,
                                                         webcamEnabled_,
                                                         screenShareEnabled_,
                                                         screenShareDisplayName_));
}

void MainWindow::leaveSelectedServer() {
  if (selectedServerId_.isEmpty()) return;
  auto* s = profile_.findServer(selectedServerId_);
  if (!s) return;
  if (s->ownerId == selfId_) {
    removeServer(selectedServerId_);
    return;
  }
  if (!s->ownerId.isEmpty() && !selfId_.isEmpty()) {
    QJsonObject leave;
    leave["server_id"] = s->id;
    leave["owner_id"] = s->ownerId;
    leave["member_id"] = selfId_;
    leave["issued_ms"] = static_cast<double>(nowUtcMs());
    leave["nonce"] = makeServerObjectId();
    backend_.sendSignedControl(s->ownerId, "server_leave", compactJsonString(leave));
  }
  removeServer(selectedServerId_);
}

void MainWindow::removeServer(const QString& serverId) {
  const QString prefix = QString("srv__%1__ch__").arg(serverId);
  for (auto it = voiceOccupantsByChannel_.begin(); it != voiceOccupantsByChannel_.end();) {
    if (it.key().startsWith(prefix)) {
      it = voiceOccupantsByChannel_.erase(it);
    } else {
      ++it;
    }
  }
  for (int i = 0; i < profile_.servers.size(); ++i) {
    if (profile_.servers[i].id != serverId) continue;
    profile_.servers.removeAt(i);
    break;
  }
  if (selectedServerId_ == serverId) {
    if (!joinedServerVoiceKey_.isEmpty() && joinedVoiceServerId() == serverId) {
      joinedServerVoiceKey_.clear();
      backend_.stopVoiceChannel();
    }
    selectedServerId_.clear();
    selectedServerChannelId_.clear();
    selectedServerChannelVoice_ = false;
    chatView_->clear();
  }
  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  refreshHeader();
  statusBar()->showMessage("Server deleted", 3000);
}

void MainWindow::removeServerChannel(const QString& serverId, const QString& channelId) {
  auto* s = profile_.findServer(serverId);
  if (!s) return;
  const auto key = serverChannelChatKey(serverId, channelId);
  voiceOccupantsByChannel_.remove(key);
  for (int i = 0; i < s->channels.size(); ++i) {
    if (s->channels[i].id == channelId) {
      s->channels.removeAt(i);
      break;
    }
  }
  if (s->ownerId == selfId_) broadcastServerMemberSync(*s);

  if (selectedServerId_ == serverId && selectedServerChannelId_ == channelId) {
    if (joinedServerVoiceKey_ == key) {
      joinedServerVoiceKey_.clear();
      backend_.stopVoiceChannel();
    }
    selectedServerChannelId_.clear();
    selectedServerChannelVoice_ = false;
    chatView_->clear();
  }

  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  refreshHeader();
  statusBar()->showMessage("Channel deleted", 3000);
}

void MainWindow::kickServerMember(const QString& serverId, const QString& memberId) {
  if (serverId.isEmpty() || memberId.isEmpty()) return;
  if (memberId == selfId_) return;

  auto* server = profile_.findServer(serverId);
  if (!server) return;
  if (server->ownerId != selfId_) return;

  bool wasMember = false;
  for (int i = 0; i < server->members.size(); ++i) {
    if (server->members[i].id != memberId) continue;
    server->members.removeAt(i);
    wasMember = true;
    break;
  }
  if (!wasMember) return;

  for (int i = 0; i < server->revokedMemberIds.size(); ++i) {
    if (server->revokedMemberIds[i] != memberId) continue;
    server->revokedMemberIds.removeAt(i);
    --i;
  }
  sanitizeVoiceOccupantsForServer(serverId);

  QJsonObject rev;
  rev["server_id"] = serverId;
  rev["owner_id"] = selfId_;
  rev["member_id"] = memberId;
  rev["reason"] = "kicked";
  rev["issued_ms"] = static_cast<double>(nowUtcMs());
  rev["nonce"] = makeServerObjectId();
  const auto revCompact = compactJsonString(rev);

  backend_.sendSignedControl(memberId, "server_revocation", revCompact);
  for (const auto& m : server->members) {
    if (m.id.isEmpty() || m.id == selfId_) continue;
    backend_.sendSignedControl(m.id, "server_revocation", revCompact);
  }
  broadcastServerMemberSync(*server);

  saveProfile();
  rebuildServerList();
  refreshServerMembersPane();
  maybeSyncVoiceCallForJoinedChannel();
  statusBar()->showMessage(QString("Kicked %1 from server").arg(memberId.left(12)), 4000);
}

void MainWindow::showProfilePopup(const QString& peerId) {
  const auto* f = profile_.findFriend(peerId);
  const bool friendAccepted = isFriendAccepted(peerId);
  const auto hintedName = serverMemberHintName(peerId);
  const auto display = serverPeerDisplayName(peerId, hintedName);

  QDialog dlg(this);
  dlg.setWindowTitle("Profile");
  dlg.setMinimumSize(520, 360);
  auto* root = new QVBoxLayout(&dlg);
  root->setContentsMargins(10, 10, 10, 10);

  auto* header = new QWidget(&dlg);
  auto* headerLayout = new QHBoxLayout(header);
  headerLayout->setContentsMargins(0, 0, 0, 0);
  headerLayout->setSpacing(12);

  auto* avatar = new QLabel(header);
  avatar->setFixedSize(96, 96);
  avatar->setScaledContents(true);
  QString avatarPath = f ? f->avatarPath : QString();
  if (avatarPath.isEmpty() && shouldShowNonFriendAvatar(peerId, hintedName)) {
    const auto candidate = Profile::peerAvatarFile(peerId);
    if (QFileInfo::exists(candidate)) avatarPath = candidate;
  }
  avatar->setPixmap(loadAvatarOrPlaceholder(peerId, avatarPath, 96));
  headerLayout->addWidget(avatar, 0);

  auto* title = new QLabel(display, header);
  title->setStyleSheet("font-weight:600; font-size:16px;");
  title->setWordWrap(true);
  headerLayout->addWidget(title, 1);
  root->addWidget(header);

  auto* form = new QFormLayout();

  const QString profileName =
      (peerId == selfId_) ? profile_.selfName
                          : (friendAccepted && f ? f->name : (canShowNonFriendIdentity(peerId, hintedName) ? hintedName
                                                                                       : QString("hidden")));
  auto* nameLabel = new QLabel(profileName, &dlg);
  form->addRow("Name:", nameLabel);

  auto* aliasLabel = new QLabel(f ? f->alias : QString(), &dlg);
  form->addRow("Alias:", aliasLabel);

  auto* statusLabel = new QLabel(f ? Profile::statusToString(f->status) : QString("unknown"), &dlg);
  form->addRow("Status:", statusLabel);

  auto* keyRow = new QWidget(&dlg);
  auto* keyRowLayout = new QHBoxLayout(keyRow);
  keyRowLayout->setContentsMargins(0, 0, 0, 0);
  auto* keyEdit = new QLineEdit(keyRow);
  keyEdit->setReadOnly(true);
  keyEdit->setText(peerId);
  keyEdit->setCursorPosition(0);
  auto* copyBtn = new QPushButton("Copy", keyRow);
  keyRowLayout->addWidget(keyEdit, 1);
  keyRowLayout->addWidget(copyBtn, 0);
  form->addRow("Public key:", keyRow);

  root->addLayout(form);

  connect(copyBtn, &QPushButton::clicked, this, [peerId] { QGuiApplication::clipboard()->setText(peerId); });

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
  QPushButton* addFriendBtn = nullptr;
  if (peerId != selfId_ && !friendAccepted) {
    addFriendBtn = buttons->addButton("Add Friend", QDialogButtonBox::ActionRole);
    connect(addFriendBtn, &QPushButton::clicked, this, [this, peerId, &dlg] {
      sendFriendRequestToId(peerId);
      dlg.accept();
    });
  }
  connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  root->addWidget(buttons);

  dlg.exec();
}

void MainWindow::clearChatFor(const QString& peerId) {
  chatCache_.remove(peerId);
  if (selectedPeerId_ == peerId) chatView_->clear();
  QString err;
  profile_.deleteChat(peerId, &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  statusBar()->showMessage("Chat cleared", 4000);
}

void MainWindow::removeFriend(const QString& peerId) {
  backend_.disconnectPeer(peerId);
  backend_.setFriendAccepted(peerId, false);

  for (int i = 0; i < profile_.friends.size(); ++i) {
    if (profile_.friends[i].id == peerId) {
      profile_.friends.removeAt(i);
      break;
    }
  }
  saveProfile();

  // Keep chat history unless user explicitly clears it.
  chatCache_.remove(peerId);
  if (selectedPeerId_ == peerId) {
    selectedPeerId_.clear();
    chatView_->clear();
    refreshHeader();
  }
  rebuildFriendList();
  rebuildFriendsTab();
  statusBar()->showMessage("Removed", 4000);
}

QString MainWindow::currentPeerId() const {
  if (!selectedServerId_.isEmpty()) return {};
  return selectedPeerId_;
}

int MainWindow::presenceStateFor(const QString& peerId) const {
  if (!selfId_.isEmpty() && peerId == selfId_) return kPresenceDirect;
  if (directOnline_.value(peerId, false)) return kPresenceDirect;
  if (rendezvousOnline_.value(peerId, false)) return kPresenceRendezvous;
  return kPresenceOffline;
}

void MainWindow::refreshFriendPresenceRow(const QString& peerId) {
  if (!friendList_) return;
  for (int i = 0; i < friendList_->count(); ++i) {
    auto* item = friendList_->item(i);
    if (!item) continue;
    if (item->data(kRolePeerId).toString() != peerId) continue;
    item->setData(kRolePresenceState, presenceStateFor(peerId));
    friendList_->viewport()->update();
    return;
  }
}

void MainWindow::refreshServerMembersPane() {
  if (!serverMembersList_) return;
  if (selectedServerId_.isEmpty() || selectedServerChannelVoice_) {
    serverMembersList_->clear();
    serverMembersList_->setVisible(false);
    refreshVoiceGallery();
    refreshVideoPanel();
    return;
  }
  const auto* s = profile_.findServer(selectedServerId_);
  if (!s) {
    serverMembersList_->clear();
    serverMembersList_->setVisible(false);
    refreshVoiceGallery();
    refreshVideoPanel();
    return;
  }
  serverMembersList_->setVisible(true);
  serverMembersList_->clear();
  const auto vcKey = (selectedServerChannelVoice_ && !selectedServerChannelId_.isEmpty())
                         ? serverChannelChatKey(selectedServerId_, selectedServerChannelId_)
                         : QString();
  for (const auto& m : s->members) {
    auto* item = new QListWidgetItem();
    const auto* f = profile_.findFriend(m.id);
    const bool unknown = !canShowNonFriendIdentity(m.id, m.name);
    QString display = serverPeerDisplayName(m.id, m.name);
    if (!vcKey.isEmpty() && voiceOccupantsByChannel_.value(vcKey).contains(m.id)) {
      display += " [vc]";
    }
    if (isVoiceMuted(m.id)) display += " [muted]";
    item->setText(display);
    item->setData(kRolePeerId, m.id);
    item->setData(kRolePresenceState, presenceStateFor(m.id));
    QString avatarPath = (m.id == selfId_) ? profile_.selfAvatarPath : (f ? f->avatarPath : QString());
    if (avatarPath.isEmpty() && shouldShowNonFriendAvatar(m.id, m.name)) {
      const auto candidate = Profile::peerAvatarFile(m.id);
      if (QFileInfo::exists(candidate)) avatarPath = candidate;
    }
    item->setIcon(QIcon(loadAvatarOrPlaceholder(m.id, avatarPath, 22)));
    item->setSizeHint(QSize(0, 38));
    if (unknown) {
      auto font = item->font();
      font.setItalic(true);
      item->setFont(font);
    }
    serverMembersList_->addItem(item);
  }
  refreshVoiceGallery();
  refreshVideoPanel();
}

void MainWindow::refreshVoiceGallery() {
  if (!voiceGallery_) return;
  voiceGallery_->clear();
  // Voice gallery tiles were replaced by the top video panel placeholders/streams.
}

void MainWindow::refreshVideoPanel() {
  if (!videoPanel_ || !videoTiles_) return;
  const bool callActive = (!activeCallPeer_.isEmpty() &&
                           (activeCallState_ == "in_call" || activeCallState_ == "connecting" ||
                            activeCallState_ == "calling"));
  const bool inSelectedVoiceChannel = (selectedServerChannelVoice_ && !selectedServerId_.isEmpty() &&
                                       !selectedServerChannelId_.isEmpty());
  const bool inSelectedDirectCallView = (!selectedPeerId_.isEmpty() && selectedPeerId_ == activeCallPeer_);
  const bool inSelectedDirectCall = callActive && inSelectedDirectCallView;
  const bool hideSelfPreviewInThisView = inSelectedVoiceChannel && selfStreamPreviewHiddenInServer_;
  backend_.setLocalVideoPreviewEnabled(!hideSelfPreviewInThisView);
  const QString directPeerId = !activeCallPeer_.isEmpty() ? activeCallPeer_ : selectedPeerId_;
  const bool directLocalLive = (webcamEnabled_ || screenShareEnabled_) && localVideoActive_ && !localVideoFrame_.isNull();
  const bool directRemoteLive = !directPeerId.isEmpty() && remoteVideoFrames_.contains(directPeerId) &&
                                !remoteVideoFrames_.value(directPeerId).isNull();
  const bool directRemoteAvailable = !directPeerId.isEmpty() && remoteVideoAvailable_.value(directPeerId, directRemoteLive);
  const bool directShowVisuals =
      directLocalLive || directRemoteLive || (directRemoteAvailable && !isWatchingPeerVideo(directPeerId));
  const bool directAvatarMode = inSelectedDirectCall && !directShowVisuals;
  const bool show = inSelectedVoiceChannel || inSelectedDirectCall;
  const bool hardHide = !(inSelectedVoiceChannel || inSelectedDirectCall);
  videoPanel_->setVisible(show);
  if (dmAvatarRow_) dmAvatarRow_->setVisible(false);
  if (videoTiles_) videoTiles_->setVisible(true);
  if (exitExpandedBtn_) exitExpandedBtn_->setVisible(show && !expandedVideoPeerId_.isEmpty() && !directAvatarMode);
  if (!show) {
    if (hardHide) {
      remoteVideoPeerId_.clear();
      remoteVideoActive_ = false;
      localVideoActive_ = false;
      localVideoFrame_ = QImage();
      remoteVideoFrames_.clear();
    }
    expandedVideoPeerId_.clear();
    videoTiles_->clear();
    if (dmAvatarLayout_) {
      while (auto* item = dmAvatarLayout_->takeAt(0)) {
        if (item->widget()) item->widget()->deleteLater();
        delete item;
      }
    }
    return;
  }

  if (directAvatarMode) {
    expandedVideoPeerId_.clear();
    if (exitExpandedBtn_) exitExpandedBtn_->setVisible(false);
    if (videoTiles_) videoTiles_->setVisible(false);
    if (dmAvatarRow_) dmAvatarRow_->setVisible(true);

    QStringList peerIds;
    if (!selfId_.isEmpty()) peerIds.push_back(selfId_);
    if (!directPeerId.isEmpty() && !peerIds.contains(directPeerId)) peerIds.push_back(directPeerId);
    peerIds.removeAll(QString());
    std::sort(peerIds.begin(), peerIds.end());
    if (!selfId_.isEmpty() && peerIds.contains(selfId_)) {
      peerIds.removeAll(selfId_);
      peerIds.push_front(selfId_);
    }

    constexpr int kDmAvatarSize = 80;
    constexpr int kDmAvatarSpacing = 16;
    if (!dmAvatarLayout_ || !dmAvatarRow_) return;
    while (auto* item = dmAvatarLayout_->takeAt(0)) {
      if (item->widget()) item->widget()->deleteLater();
      delete item;
    }
    const int count = std::max(1, static_cast<int>(peerIds.size()));
    const int totalW = count * kDmAvatarSize + std::max(0, count - 1) * kDmAvatarSpacing;
    dmAvatarRow_->setFixedWidth(totalW);
    dmAvatarRow_->setFixedHeight(kDmAvatarSize + 8);
    for (const auto& peerId : peerIds) {
      QString display;
      if (peerId == selfId_) {
        display = profile_.selfName.trimmed().isEmpty() ? QString("Me") : profile_.selfName.trimmed();
      } else {
        display = serverPeerDisplayName(peerId, serverMemberHintName(peerId));
      }

      QString avatarPath;
      if (peerId == selfId_) {
        avatarPath = profile_.selfAvatarPath;
      } else if (const auto* f = profile_.findFriend(peerId)) {
        avatarPath = f->avatarPath;
      }
      if (avatarPath.isEmpty()) {
        const auto candidate = Profile::peerAvatarFile(peerId);
        if (QFileInfo::exists(candidate)) avatarPath = candidate;
      }

      auto* avatar = new QLabel(dmAvatarRow_);
      avatar->setPixmap(dmCallAvatarTile(peerId, avatarPath, QSize(kDmAvatarSize, kDmAvatarSize), peerId == selfId_));
      avatar->setFixedSize(kDmAvatarSize, kDmAvatarSize);
      avatar->setToolTip(display);
      dmAvatarLayout_->addWidget(avatar);
    }
    return;
  }

  if (dmAvatarRow_) {
    dmAvatarRow_->setVisible(false);
    dmAvatarRow_->setMinimumWidth(0);
    dmAvatarRow_->setMaximumWidth(QWIDGETSIZE_MAX);
  }
  if (videoTiles_) videoTiles_->setVisible(true);
  videoTiles_->setFlow(QListView::LeftToRight);
  videoTiles_->setWrapping(true);
  videoTiles_->setResizeMode(QListView::Adjust);
  videoTiles_->setSpacing(10);
  videoTiles_->setMinimumWidth(0);
  videoTiles_->setMaximumWidth(QWIDGETSIZE_MAX);
  videoTiles_->setMinimumHeight(220);
  videoTiles_->setMaximumHeight(QWIDGETSIZE_MAX);
  videoTiles_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
  videoTiles_->setContentsMargins(0, 0, 0, 0);
  if (profile_.darkMode) {
    videoTiles_->setStyleSheet(
        "QListWidget#videoTiles { padding: 3px; background-color: #141414; color: #dcdcdc; border: 1px solid "
        "#3a3a3a; }");
  } else {
    videoTiles_->setStyleSheet("QListWidget#videoTiles { padding: 3px; }");
  }

  QStringList peerIds;
  if (inSelectedVoiceChannel) {
    const auto key = serverChannelChatKey(selectedServerId_, selectedServerChannelId_);
    const auto occupants = voiceOccupantsByChannel_.value(key);
    for (const auto& id : occupants) {
      if (!id.isEmpty()) peerIds.push_back(id);
    }
    if (joinedServerVoiceKey_ == key && !selfId_.isEmpty() && !peerIds.contains(selfId_)) {
      peerIds.push_back(selfId_);
    }
  } else {
    if (directLocalLive && !selfId_.isEmpty()) peerIds.push_back(selfId_);
    const auto pid = directPeerId;
    const bool wantRemoteTile = !pid.isEmpty() &&
                                (directRemoteLive || (directRemoteAvailable && !isWatchingPeerVideo(pid)));
    if (wantRemoteTile && !peerIds.contains(pid)) peerIds.push_back(pid);
  }

  peerIds.removeAll(QString());
  std::sort(peerIds.begin(), peerIds.end());
  if (!selfId_.isEmpty() && peerIds.contains(selfId_)) {
    peerIds.removeAll(selfId_);
    peerIds.push_front(selfId_);
  }

  if (!expandedVideoPeerId_.isEmpty()) {
    if (peerIds.contains(expandedVideoPeerId_)) {
      peerIds = QStringList{expandedVideoPeerId_};
    } else {
      expandedVideoPeerId_.clear();
    }
  }
  if (exitExpandedBtn_) exitExpandedBtn_->setVisible(!expandedVideoPeerId_.isEmpty());

  const int count = std::max(1, static_cast<int>(peerIds.size()));
  const int spacing = videoTiles_->spacing();
  const int viewW = std::max(320, videoTiles_->viewport()->width());
  const int cols = expandedVideoPeerId_.isEmpty() ? std::max(1, std::min(2, count)) : 1;
  int tileW = (viewW - spacing * (cols - 1)) / cols;
  tileW = std::max(120, std::min(tileW, 560));
  if (!expandedVideoPeerId_.isEmpty()) {
    tileW = std::max(320, viewW - spacing);
  }
  int tileH = std::max(112, (tileW * 9) / 16);
  if (!expandedVideoPeerId_.isEmpty()) {
    tileH = std::max(180, videoTiles_->viewport()->height() - spacing);
  }
  videoTiles_->setIconSize(QSize(tileW, tileH));
  videoTiles_->setGridSize(QSize(tileW + spacing, tileH + spacing));

  videoTiles_->clear();
  for (const auto& peerId : peerIds) {
    auto* item = new QListWidgetItem();
    item->setData(kRolePeerId, peerId);
    item->setData(kRoleWatchOverlay, false);
    item->setData(kRoleDmCallAvatar, false);

    QString display;
    if (peerId == selfId_) {
      display = profile_.selfName.trimmed().isEmpty() ? QString("Me") : profile_.selfName.trimmed();
    } else {
      display = serverPeerDisplayName(peerId, serverMemberHintName(peerId));
    }
    item->setText({});
    item->setToolTip(display);

    QString avatarPath;
    if (peerId == selfId_) {
      avatarPath = profile_.selfAvatarPath;
    } else if (const auto* f = profile_.findFriend(peerId)) {
      avatarPath = f->avatarPath;
    }
    if (avatarPath.isEmpty()) {
      const auto candidate = Profile::peerAvatarFile(peerId);
      if (QFileInfo::exists(candidate)) avatarPath = candidate;
    }

    QPixmap tile;
    const bool expanded = !expandedVideoPeerId_.isEmpty();
    const bool selfTile = (peerId == selfId_);
    const bool watchingRemote = selfTile ? true : isWatchingPeerVideo(peerId);
    const bool remoteAvailable =
        !selfTile && remoteVideoAvailable_.value(peerId, remoteVideoFrames_.contains(peerId) && !remoteVideoFrames_[peerId].isNull());
    const bool showWatchOverlay = remoteAvailable && !watchingRemote;
    const bool hideSelfLiveTile = selfTile && hideSelfPreviewInThisView;
    if (!hideSelfLiveTile && selfTile && (webcamEnabled_ || screenShareEnabled_) && localVideoActive_ &&
        !localVideoFrame_.isNull()) {
      tile = expanded ? roundedContain(localVideoFrame_, QSize(tileW, tileH)) : roundedCover(localVideoFrame_, QSize(tileW, tileH));
    } else if (remoteVideoFrames_.contains(peerId) && !remoteVideoFrames_[peerId].isNull()) {
      tile = expanded ? roundedContain(remoteVideoFrames_[peerId], QSize(tileW, tileH))
                      : roundedCover(remoteVideoFrames_[peerId], QSize(tileW, tileH));
    } else {
      tile = videoPlaceholderCard(peerId, display, avatarPath, QSize(tileW, tileH));
    }
    if (showWatchOverlay) {
      tile = withWatchStreamOverlay(tile);
      item->setData(kRoleWatchOverlay, true);
      item->setToolTip(display + " — Watch Stream");
    }
    item->setIcon(QIcon(tile));
    item->setSizeHint(QSize(tileW, tileH));
    videoTiles_->addItem(item);
  }
}

void MainWindow::refreshCallButton() {
  if (!callBtn_) return;
  const bool dark = profile_.darkMode;
  const bool callSessionActive =
      !joinedServerVoiceKey_.isEmpty() || (!activeCallPeer_.isEmpty() && !activeCallState_.isEmpty());
  if (webcamBtn_) {
    const bool hasCamera = !profile_.video.devicePath.trimmed().isEmpty();
    if (!hasCamera && webcamEnabled_) {
      webcamEnabled_ = false;
      localVideoActive_ = false;
      localVideoFrame_ = QImage();
    }
    const bool inVoiceContext =
        callSessionActive ||
        (!selectedServerId_.isEmpty() && !selectedServerChannelId_.isEmpty() && selectedServerChannelVoice_) ||
        !currentPeerId().isEmpty();
    webcamBtn_->setEnabled(hasCamera && inVoiceContext);
    webcamBtn_->setChecked(webcamEnabled_ && hasCamera);
    webcamBtn_->setIcon(discordCameraIcon(!webcamEnabled_, dark, false));
    webcamBtn_->setToolTip(!hasCamera ? "No camera configured" : (webcamEnabled_ ? "Turn camera off" : "Turn camera on"));
  }
  if (screenShareBtn_) {
    const bool hasScreens = !QGuiApplication::screens().isEmpty();
    if ((!hasScreens || screenShareDisplayName_.trimmed().isEmpty()) && screenShareEnabled_) {
      screenShareEnabled_ = false;
    }
    const bool inVoiceContext =
        callSessionActive ||
        (!selectedServerId_.isEmpty() && !selectedServerChannelId_.isEmpty() && selectedServerChannelVoice_) ||
        !currentPeerId().isEmpty();
    screenShareBtn_->setEnabled(hasScreens && inVoiceContext);
    screenShareBtn_->setChecked(screenShareEnabled_ && hasScreens);
    screenShareBtn_->setIcon(discordScreenIcon(dark, false));
    screenShareBtn_->setToolTip(!hasScreens ? "No display available"
                                            : (screenShareEnabled_ ? "Stop screen sharing" : "Start screen sharing"));
  }

  bool callEnabled = false;
  QString callText = "Call";
  if (!selectedServerId_.isEmpty() && !selectedServerChannelId_.isEmpty()) {
    if (!selectedServerChannelVoice_) {
      callEnabled = false;
      callText = "Call";
    } else {
      const auto key = serverChannelChatKey(selectedServerId_, selectedServerChannelId_);
      const bool joined = (joinedServerVoiceKey_ == key);
      callEnabled = true;
      callText = joined ? "Leave Voice" : "Join Voice";
    }
  } else {
    const auto pid = currentPeerId();
    if (pid.isEmpty()) {
      callEnabled = false;
      callText = "Call";
    } else {
      const bool callActiveForThis =
          (!activeCallPeer_.isEmpty() && activeCallPeer_ == pid && !activeCallState_.isEmpty());
      if (callActiveForThis) {
        callEnabled = true;
        callText = "Hang up";
      } else {
        const auto* f = profile_.findFriend(pid);
        const bool accepted = (f && f->status == Profile::FriendStatus::Accepted);
        const bool online = presenceStateFor(pid) != kPresenceOffline;
        callEnabled = accepted && online;
        callText = "Call";
      }
    }
  }
  callBtn_->setEnabled(callEnabled);
  callBtn_->setText(callText);

  if (callControlsBar_) callControlsBar_->setVisible(callSessionActive);
  if (callBtn_) callBtn_->setVisible(!callSessionActive);
  if (disconnectBtn_) disconnectBtn_->setEnabled(callSessionActive);
  if (micBtn_) {
    micBtn_->setEnabled(callSessionActive);
    {
      const QSignalBlocker block(*micBtn_);
      micBtn_->setChecked(localMicMuted_);
    }
    micBtn_->setIcon(discordMicIcon(localMicMuted_, dark));
    micBtn_->setToolTip(localMicMuted_ ? "Unmute microphone" : "Mute microphone");
  }
  if (micMoreBtn_) micMoreBtn_->setProperty("danger", localMicMuted_);
  if (disconnectBtn_) disconnectBtn_->setIcon(discordHangupIcon(dark));
  if (micMoreBtn_) micMoreBtn_->setEnabled(callSessionActive);
  if (camMoreBtn_) camMoreBtn_->setEnabled(callSessionActive);
}

void MainWindow::appendMessage(const QString& peerId, const QString& label, const QString& text, bool incoming) {
  // Best-effort: if we learned a peer name, store it in the profile.
  if (incoming) {
    auto* f = profile_.findFriend(peerId);
    if (f && f->status == Profile::FriendStatus::Accepted) {
      if (!label.isEmpty() && label != peerId && f->name != label) {
        f->name = label;
        saveProfile();
        rebuildFriendList();
        refreshHeader();
      }
    }
  }

  if (!chatCache_.contains(peerId)) {
    QString err;
    chatCache_[peerId] = profile_.loadChat(peerId, &err);
    if (!err.isEmpty()) statusBar()->showMessage(err, 8000);
  }

  auto& msgs = chatCache_[peerId];
  Profile::ChatMessage m;
  m.tsMs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
  m.incoming = incoming;
  m.text = text;
  msgs.push_back(m);
  while (msgs.size() > 500) msgs.removeFirst();

  QString err;
  profile_.saveChat(peerId, msgs, &err);
  if (!err.isEmpty()) statusBar()->showMessage(err, 8000);

  QString who = "You";
  if (incoming) {
    const auto* f = profile_.findFriend(peerId);
    who = f ? friendDisplay(*f) : label;
  }
  const auto line = renderLine(stampFromUtcMs(m.tsMs), who, text);
  if (peerId == currentChatKey()) {
    chatView_->append(line);
    maybeFetchGifPreviewsFromText(text);
  }
}

void MainWindow::maybeFetchGifPreviewsFromText(const QString& text) {
  static const QRegularExpression kUrlRe(R"((https?://[^\s<>"']+))", QRegularExpression::CaseInsensitiveOption);
  auto it = kUrlRe.globalMatch(text);
  while (it.hasNext()) {
    const auto m = it.next();
    const QString urlText = m.captured(1).trimmed();
    if (urlText.isEmpty()) continue;
    const QUrl url(urlText);
    if (!url.isValid()) continue;
    const QString scheme = url.scheme().toLower();
    if (scheme != "http" && scheme != "https") continue;
    if (!url.path().toLower().endsWith(".gif")) continue;
    ensureGifPreview(url.toString());
  }
}

void MainWindow::ensureGifPreview(const QString& gifUrl) {
  if (!chatView_ || gifUrl.isEmpty()) return;
  if (readyGifPreviewUrls_.contains(gifUrl)) {
    const QString localUrl = gifLocalUrlByRemote_.value(gifUrl);
    if (!localUrl.isEmpty()) {
      auto* bar = chatView_->verticalScrollBar();
      const int y = bar ? bar->value() : 0;
      QString html = chatView_->toHtml();
      html.replace(QString("src=\"%1\"").arg(gifUrl.toHtmlEscaped()),
                   QString("src=\"%1\"").arg(localUrl.toHtmlEscaped()));
      chatView_->setHtml(html);
      if (bar) bar->setValue(y);
    }
    return;
  }
  if (pendingGifPreviewUrls_.contains(gifUrl)) return;

  if (!gifPreviewNet_) gifPreviewNet_ = new QNetworkAccessManager(this);
  pendingGifPreviewUrls_.insert(gifUrl);

  QNetworkRequest req{QUrl(gifUrl)};
  req.setTransferTimeout(15000);
  auto* reply = gifPreviewNet_->get(req);
  connect(reply, &QNetworkReply::finished, this, [this, reply, gifUrl] {
    pendingGifPreviewUrls_.remove(gifUrl);
    const auto err = reply->error();
    const QByteArray payload = reply->readAll();
    reply->deleteLater();
    if (err != QNetworkReply::NoError || payload.isEmpty()) return;

    const QByteArray hash = QCryptographicHash::hash(gifUrl.toUtf8(), QCryptographicHash::Sha1).toHex();
    const QString cacheRoot =
        QDir(QStandardPaths::writableLocation(QStandardPaths::CacheLocation)).filePath("gif-preview-cache");
    QDir().mkpath(cacheRoot);
    const QString gifPath = QDir(cacheRoot).filePath(QString::fromLatin1(hash) + ".gif");
    QFile out(gifPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    if (out.write(payload) != payload.size()) {
      out.close();
      return;
    }
    out.close();

    const QString localUrl = QUrl::fromLocalFile(gifPath).toString();
    readyGifPreviewUrls_.insert(gifUrl);
    gifLocalUrlByRemote_[gifUrl] = localUrl;
    auto* bar = chatView_->verticalScrollBar();
    const int y = bar ? bar->value() : 0;
    QString html = chatView_->toHtml();
    html.replace(QString("src=\"%1\"").arg(gifUrl.toHtmlEscaped()),
                 QString("src=\"%1\"").arg(localUrl.toHtmlEscaped()));
    chatView_->setHtml(html);
    if (bar) bar->setValue(y);
  });
}

void MainWindow::refreshHeader() {
  if (!selectedServerId_.isEmpty() && !selectedServerChannelId_.isEmpty()) {
    const auto* server = profile_.findServer(selectedServerId_);
    QString channelName = selectedServerChannelId_;
    if (server) {
      for (const auto& ch : server->channels) {
        if (ch.id == selectedServerChannelId_) {
          channelName = ch.name.isEmpty() ? "channel" : ch.name;
          break;
        }
      }
    }
    const auto serverName = (server && !server->name.isEmpty()) ? server->name : QString("Server");
    if (selectedServerChannelVoice_) {
      const auto key = serverChannelChatKey(selectedServerId_, selectedServerChannelId_);
      const auto joined = joinedServerVoiceKey_ == key ? " [joined]" : "";
      headerLabel_->setText(QString("%1 / %2 (voice)%3").arg(serverName, channelName, joined));
    } else {
      headerLabel_->setText(QString("%1 / #%2").arg(serverName, channelName));
    }
    refreshCallButton();
    return;
  }

  if (selectedPeerId_.isEmpty()) {
    headerLabel_->setText("No chat selected");
    refreshCallButton();
    return;
  }
  const auto* f = profile_.findFriend(selectedPeerId_);
  const auto title = f ? friendDisplay(*f) : selectedPeerId_.left(14) + "...";
  headerLabel_->setText(title);
  refreshCallButton();
}

void MainWindow::addFriendDialog() {
  QDialog dlg(this);
  dlg.setWindowTitle("Add Friend");
  QFormLayout form(&dlg);

  QLineEdit idEdit;
  idEdit.setPlaceholderText("Friend ID (base64url public key)");
  form.addRow("ID:", &idEdit);

  QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
  form.addRow(&buttons);
  connect(&buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(&buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

  if (dlg.exec() != QDialog::Accepted) return;
  const auto id = idEdit.text().trimmed();
  if (id.isEmpty()) return;
  sendFriendRequestToId(id);
}

void MainWindow::showGifPopup() {
  QDialog dlg(this);
  dlg.setWindowTitle("GIF Search");
  dlg.resize(700, 520);

  auto* root = new QVBoxLayout(&dlg);
  auto* top = new QHBoxLayout();
  auto* queryEdit = new QLineEdit(&dlg);
  queryEdit->setPlaceholderText("Search GIFs (for example: cat, wow, dancing)");
  auto* searchBtn = new QPushButton("Search", &dlg);
  top->addWidget(queryEdit, 1);
  top->addWidget(searchBtn);
  root->addLayout(top);

  auto* keyRow = new QHBoxLayout();
  auto* keyLabel = new QLabel("GIPHY API Key:", &dlg);
  auto* keyEdit = new QLineEdit(&dlg);
  keyEdit->setPlaceholderText("Enter your GIPHY API key");
  keyEdit->setText(qEnvironmentVariable("GIPHY_API_KEY").trimmed());
  keyRow->addWidget(keyLabel);
  keyRow->addWidget(keyEdit, 1);
  root->addLayout(keyRow);

  auto* list = new QListWidget(&dlg);
  list->setSelectionMode(QAbstractItemView::SingleSelection);
  root->addWidget(list, 1);

  auto* status = new QLabel("Type a query and click Search.", &dlg);
  root->addWidget(status);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
  if (auto* ok = buttons->button(QDialogButtonBox::Ok)) ok->setText("Insert");
  root->addWidget(buttons);
  connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
  connect(list, &QListWidget::itemDoubleClicked, &dlg, [&dlg](QListWidgetItem*) { dlg.accept(); });

  struct GifResult {
    QString title;
    QString url;
  };
  QVector<GifResult> results;
  auto* net = new QNetworkAccessManager(&dlg);

  auto runSearch = [&] {
    const QString query = queryEdit->text().trimmed();
    if (query.isEmpty()) {
      status->setText("Enter a search term.");
      return;
    }

    searchBtn->setEnabled(false);
    status->setText("Searching...");
    list->clear();
    results.clear();

    const QString apiKey = keyEdit->text().trimmed();
    if (apiKey.isEmpty()) {
      status->setText("Enter a GIPHY API key to enable GIF search.");
      searchBtn->setEnabled(true);
      return;
    }
    QUrl url("https://api.giphy.com/v1/gifs/search");
    QUrlQuery params;
    params.addQueryItem("api_key", apiKey);
    params.addQueryItem("q", query);
    params.addQueryItem("limit", "25");
    params.addQueryItem("rating", "pg-13");
    params.addQueryItem("lang", "en");
    url.setQuery(params);

    QNetworkRequest req(url);
    req.setTransferTimeout(10000);
    auto* reply = net->get(req);

    connect(reply, &QNetworkReply::finished, &dlg, [&, reply] {
      searchBtn->setEnabled(true);
      const QNetworkReply::NetworkError err = reply->error();
      const QByteArray payload = reply->readAll();
      const int httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
      reply->deleteLater();

      if (err != QNetworkReply::NoError) {
        status->setText(QString("Search failed (%1, HTTP %2).")
                            .arg(reply->errorString())
                            .arg(httpStatus == 0 ? -1 : httpStatus));
        return;
      }

      QJsonParseError parseErr {};
      const QJsonDocument doc = QJsonDocument::fromJson(payload, &parseErr);
      if (parseErr.error != QJsonParseError::NoError || !doc.isObject()) {
        status->setText("Search failed: invalid response.");
        return;
      }

      const QJsonObject root = doc.object();
      const QJsonObject meta = root.value("meta").toObject();
      const int apiStatus = meta.value("status").toInt(200);
      if (apiStatus < 200 || apiStatus >= 300) {
        const QString msg = meta.value("msg").toString().trimmed();
        status->setText(msg.isEmpty() ? QString("Search failed: GIPHY error %1.").arg(apiStatus)
                                      : QString("Search failed: %1").arg(msg));
        return;
      }

      const QJsonArray arr = root.value("data").toArray();
      for (const auto& v : arr) {
        const QJsonObject obj = v.toObject();
        const QJsonObject images = obj.value("images").toObject();
        const QJsonObject original = images.value("original").toObject();
        const QString gifUrl = original.value("url").toString().trimmed();
        if (gifUrl.isEmpty()) continue;

        QString title = obj.value("title").toString().trimmed();
        if (title.isEmpty()) title = "GIF";

        results.push_back({title, gifUrl});
        auto* item = new QListWidgetItem(QString("%1\n%2").arg(title, gifUrl), list);
        item->setData(Qt::UserRole, results.size() - 1);
        item->setToolTip(gifUrl);
        list->addItem(item);
      }

      if (list->count() == 0) {
        status->setText("No GIF results found.");
      } else {
        list->setCurrentRow(0);
        status->setText(QString("Found %1 GIFs. Select one and click Insert.").arg(list->count()));
      }
    });
  };

  connect(searchBtn, &QPushButton::clicked, &dlg, runSearch);
  connect(queryEdit, &QLineEdit::returnPressed, &dlg, runSearch);

  queryEdit->setText("funny");
  runSearch();

  if (dlg.exec() != QDialog::Accepted) return;
  auto* current = list->currentItem();
  if (!current) return;

  const int idx = current->data(Qt::UserRole).toInt();
  if (idx < 0 || idx >= results.size()) return;
  const QString selectedUrl = results[idx].url;
  if (selectedUrl.isEmpty()) return;

  QString nextText = input_ ? input_->text().trimmed() : QString();
  if (nextText.isEmpty()) {
    nextText = selectedUrl;
  } else {
    nextText += " " + selectedUrl;
  }
  if (input_) {
    input_->setText(nextText);
    input_->setFocus();
  }
  statusBar()->showMessage("GIF URL inserted into message box", 3000);
}

void MainWindow::sendFriendRequestToId(const QString& id) {
  if (id.isEmpty() || id == selfId_) return;
  Profile::FriendEntry e;
  auto* ex = profile_.findFriend(id);
  if (ex) e = *ex;
  e.id = id;
  if (e.status == Profile::FriendStatus::None) e.status = Profile::FriendStatus::OutgoingPending;
  profile_.upsertFriend(e);
  saveProfile();
  rebuildFriendList();
  backend_.sendFriendRequest(id);
  statusBar()->showMessage("Friend request sent", 5000);
}
