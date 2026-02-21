#include "secure_guards.h"

#include <QApplication>
#include <QClipboard>
#include <QMimeData>
#include <QImage>
#include <QVariant>
#include <QUrl>
#include <QWidget>

#if defined(_WIN32)
#include <windows.h>
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
#endif

SecureGuards::SecureGuards(QWidget* window, size_t clipboard_max_bytes, QObject* parent)
    : QObject(parent), window_(window), clipboard_max_bytes_(clipboard_max_bytes) {
  clipboard_ = QApplication::clipboard();
  if (clipboard_) {
    connect(clipboard_, &QClipboard::dataChanged, this, &SecureGuards::onClipboardChanged);
  }
}

void SecureGuards::setSecureMode(bool enabled) {
  secure_mode_ = enabled;
  if (clipboard_ && secure_mode_) {
    clipboard_->clear();
  }
  applyScreenshotPolicy(enabled);
}

void SecureGuards::onClipboardChanged() {
  if (!secure_mode_) return;
  if (!clipboard_) return;
  const QMimeData* mime = clipboard_->mimeData();
  if (!mime) return;

  bool has_text = mime->hasText();
  bool has_html = mime->hasHtml();
  bool has_urls = mime->hasUrls();
  bool has_image = mime->hasImage();
  bool has_data = has_text || has_html || has_urls || has_image;
  if (!has_data) return;

  size_t bytes = 0;
  if (has_text) {
    bytes += static_cast<size_t>(mime->text().toUtf8().size());
  }
  if (has_html) {
    bytes += static_cast<size_t>(mime->html().toUtf8().size());
  }
  if (has_urls) {
    const auto urls = mime->urls();
    for (const auto& url : urls) {
      bytes += static_cast<size_t>(url.toString().toUtf8().size());
    }
  }
  if (has_image) {
    QVariant image_data = mime->imageData();
    if (image_data.canConvert<QImage>()) {
      QImage img = image_data.value<QImage>();
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
      bytes += static_cast<size_t>(img.sizeInBytes());
#else
      bytes += static_cast<size_t>(img.byteCount());
#endif
    }
  }

  bool block_all = clipboard_max_bytes_ == 0;
  bool too_large = block_all || bytes > clipboard_max_bytes_ || has_urls || has_image;
  if (too_large) {
    clipboard_->clear();
    QString reason = block_all ? "Обнаружена активность буфера обмена"
                               : QString("Превышен лимит буфера обмена (%1 байт)").arg(bytes);
    emit violationDetected(reason);
  }
}

void SecureGuards::applyScreenshotPolicy(bool enabled) {
#if defined(_WIN32)
  if (!window_) return;
  HWND hwnd = reinterpret_cast<HWND>(window_->winId());
  if (enabled) {
    SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
  } else {
    SetWindowDisplayAffinity(hwnd, WDA_NONE);
  }
#else
  Q_UNUSED(enabled);
#endif
}
