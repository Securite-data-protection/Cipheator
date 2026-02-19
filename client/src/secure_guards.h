#pragma once

#include <cstddef>
#include <QObject>
#include <QString>

class QWidget;
class QClipboard;

class SecureGuards : public QObject {
  Q_OBJECT
 public:
  explicit SecureGuards(QWidget* window, size_t clipboard_max_bytes, QObject* parent = nullptr);
  void setSecureMode(bool enabled);

signals:
  void violationDetected(const QString& reason);

 private slots:
  void onClipboardChanged();

 private:
  void applyScreenshotPolicy(bool enabled);

  QWidget* window_ = nullptr;
  QClipboard* clipboard_ = nullptr;
  bool secure_mode_ = false;
  size_t clipboard_max_bytes_ = 0;
};
