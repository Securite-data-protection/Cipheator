#include "login_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLineEdit>
#include <QVBoxLayout>

LoginDialog::LoginDialog(QWidget* parent) : QDialog(parent) {
  setWindowTitle("Вход в систему");
  auto* layout = new QVBoxLayout(this);
  auto* form = new QFormLayout();

  host_edit_ = new QLineEdit(this);
  port_edit_ = new QLineEdit(this);
  user_edit_ = new QLineEdit(this);
  pass_edit_ = new QLineEdit(this);
  pass_edit_->setEchoMode(QLineEdit::Password);

  form->addRow("Логин:", user_edit_);
  form->addRow("Пароль:", pass_edit_);

  layout->addLayout(form);

  auto* advanced_box = new QGroupBox("Дополнительно", this);
  auto* advanced_layout = new QFormLayout(advanced_box);
  advanced_layout->addRow("Сервер:", host_edit_);
  advanced_layout->addRow("Порт:", port_edit_);
  advanced_box->setStyleSheet("QGroupBox { color: #666666; }");
  host_edit_->setStyleSheet("color: #666666;");
  port_edit_->setStyleSheet("color: #666666;");
  layout->addWidget(advanced_box);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  layout->addWidget(buttons);

  user_edit_->setFocus();
}

void LoginDialog::setDefaults(const QString& host, int port) {
  host_edit_->setText(host);
  port_edit_->setText(QString::number(port));
}

QString LoginDialog::username() const { return user_edit_->text(); }
QString LoginDialog::password() const { return pass_edit_->text(); }
QString LoginDialog::host() const { return host_edit_->text(); }

int LoginDialog::port() const {
  return port_edit_->text().toInt();
}
