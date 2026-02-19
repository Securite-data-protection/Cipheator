#include "login_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QVBoxLayout>

LoginDialog::LoginDialog(QWidget* parent) : QDialog(parent) {
  setWindowTitle("Cipheator Login");
  auto* layout = new QVBoxLayout(this);
  auto* form = new QFormLayout();

  host_edit_ = new QLineEdit(this);
  port_edit_ = new QLineEdit(this);
  user_edit_ = new QLineEdit(this);
  pass_edit_ = new QLineEdit(this);
  pass_edit_->setEchoMode(QLineEdit::Password);

  form->addRow("Server Host:", host_edit_);
  form->addRow("Server Port:", port_edit_);
  form->addRow("Username:", user_edit_);
  form->addRow("Password:", pass_edit_);

  layout->addLayout(form);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  layout->addWidget(buttons);
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
