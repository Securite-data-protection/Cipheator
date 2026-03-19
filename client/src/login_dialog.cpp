#include "login_dialog.h"

#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QToolButton>
#include <QVBoxLayout>

LoginDialog::LoginDialog(QWidget* parent) : QDialog(parent) {
  setWindowTitle("Вход в систему");
  auto* layout = new QVBoxLayout(this);
  layout->setSpacing(10);
  layout->setContentsMargins(16, 16, 16, 16);
  auto* form = new QFormLayout();
  form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  form->setHorizontalSpacing(14);
  form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

  host_edit_ = new QLineEdit(this);
  port_edit_ = new QLineEdit(this);
  user_edit_ = new QLineEdit(this);
  pass_edit_ = new QLineEdit(this);
  pass_edit_->setEchoMode(QLineEdit::Password);

  auto* user_label = new QLabel("Логин:", this);
  auto* pass_label = new QLabel("Пароль:", this);
  user_label->setMinimumWidth(120);
  pass_label->setMinimumWidth(120);
  form->addRow(user_label, user_edit_);
  form->addRow(pass_label, pass_edit_);

  layout->addLayout(form);

  auto* toggle = new QToolButton(this);
  toggle->setText("Сетевые настройки");
  toggle->setCheckable(true);
  toggle->setChecked(false);
  layout->addWidget(toggle);

  auto* advanced_box = new QGroupBox("", this);
  auto* advanced_layout = new QFormLayout(advanced_box);
  advanced_layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  advanced_layout->setHorizontalSpacing(14);
  advanced_layout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
  auto* host_label = new QLabel("Сервер:", advanced_box);
  auto* port_label = new QLabel("Порт:", advanced_box);
  host_label->setMinimumWidth(120);
  port_label->setMinimumWidth(120);
  advanced_layout->addRow(host_label, host_edit_);
  advanced_layout->addRow(port_label, port_edit_);
  advanced_box->setStyleSheet("QGroupBox { color: #666666; }");
  host_edit_->setStyleSheet("color: #666666;");
  port_edit_->setStyleSheet("color: #666666;");
  advanced_box->setVisible(false);
  connect(toggle, &QToolButton::toggled, advanced_box, &QWidget::setVisible);
  layout->addWidget(advanced_box);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
  if (auto* ok_btn = buttons->button(QDialogButtonBox::Ok)) {
    ok_btn->setText("ОК");
  }
  if (auto* cancel_btn = buttons->button(QDialogButtonBox::Cancel)) {
    cancel_btn->setText("Отмена");
  }
  connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
  connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
  layout->addWidget(buttons);

  user_edit_->setFocus();
  setMinimumWidth(500);
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
