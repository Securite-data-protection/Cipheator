#pragma once

#include <QDialog>

class QLineEdit;

class LoginDialog : public QDialog {
  Q_OBJECT
 public:
  explicit LoginDialog(QWidget* parent = nullptr);

  void setDefaults(const QString& host, int port);

  QString username() const;
  QString password() const;
  QString host() const;
  int port() const;

 private:
  QLineEdit* host_edit_ = nullptr;
  QLineEdit* port_edit_ = nullptr;
  QLineEdit* user_edit_ = nullptr;
  QLineEdit* pass_edit_ = nullptr;
};
