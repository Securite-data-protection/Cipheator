#include "main_window.h"
#include "login_dialog.h"
#include "client_core.h"

#include "cipheator/config.h"
#include "cipheator/pki.h"

#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QIcon>
#include <QLineEdit>
#include <QMessageBox>
#include <QLabel>
#include <QVBoxLayout>
#include <QPushButton>
#include <QObject>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

std::string lock_file_path() {
  std::error_code ec;
  auto base = std::filesystem::temp_directory_path(ec);
  if (ec) {
    base = std::filesystem::current_path();
  }
  return (base / "cipheator_login_lock").string();
}

bool is_device_locked() {
  std::error_code ec;
  return std::filesystem::exists(lock_file_path(), ec);
}

void set_device_lock() {
  std::ofstream out(lock_file_path(), std::ios::trunc);
  if (out) {
    out << "locked\n";
  }
}

std::string trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::string resolve_relative_path(const std::string& value,
                                  const std::string& config_path,
                                  const std::filesystem::path& exe_path) {
  if (value.empty()) return value;
  std::filesystem::path p(value);
  if (p.is_absolute()) return p.string();
  std::vector<std::filesystem::path> bases;
  if (!config_path.empty()) {
    bases.push_back(std::filesystem::path(config_path).parent_path());
  }
  if (!exe_path.empty()) {
    bases.push_back(exe_path.parent_path());
  }
  bases.push_back(std::filesystem::current_path());

  std::error_code ec;
  for (const auto& base : bases) {
    if (base.empty()) continue;
    std::filesystem::path candidate = base / p;
    if (std::filesystem::exists(candidate, ec)) {
      return candidate.string();
    }
  }
  return value;
}

bool update_config_values(const std::string& path,
                          const std::vector<std::pair<std::string, std::string>>& updates) {
  if (path.empty()) return false;
  std::unordered_map<std::string, std::string> update_map;
  for (const auto& kv : updates) {
    update_map[kv.first] = kv.second;
  }

  std::vector<std::string> lines;
  std::unordered_set<std::string> seen;
  std::ifstream in(path);
  if (in) {
    std::string line;
    while (std::getline(in, line)) {
      std::string trimmed = trim(line);
      if (trimmed.empty() || trimmed[0] == '#') {
        lines.push_back(line);
        continue;
      }
      auto pos = trimmed.find('=');
      if (pos == std::string::npos) {
        lines.push_back(line);
        continue;
      }
      std::string key = trim(trimmed.substr(0, pos));
      auto it = update_map.find(key);
      if (it != update_map.end()) {
        lines.push_back(key + "=" + it->second);
        seen.insert(key);
      } else {
        lines.push_back(line);
      }
    }
  }

  for (const auto& kv : update_map) {
    if (seen.find(kv.first) == seen.end()) {
      lines.push_back(kv.first + "=" + kv.second);
    }
  }

  std::filesystem::path p(path);
  if (!p.parent_path().empty()) {
    std::error_code ec;
    std::filesystem::create_directories(p.parent_path(), ec);
  }

  std::ofstream out(path, std::ios::trunc);
  if (!out) return false;
  for (const auto& line : lines) {
    out << line << "\n";
  }
  return true;
}

bool prompt_password_change(QWidget* parent, QString* new_password_out) {
  if (!new_password_out) return false;
  QDialog dialog(parent);
  dialog.setWindowTitle("Смена пароля");
  dialog.setMinimumWidth(500);
  auto* layout = new QVBoxLayout(&dialog);
  auto* form = new QFormLayout();
  form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
  form->setHorizontalSpacing(14);
  form->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);

  auto* new_pass = new QLineEdit(&dialog);
  auto* confirm = new QLineEdit(&dialog);
  new_pass->setEchoMode(QLineEdit::Password);
  confirm->setEchoMode(QLineEdit::Password);

  auto* new_pass_label = new QLabel("Новый пароль:", &dialog);
  auto* confirm_label = new QLabel("Подтверждение:", &dialog);
  new_pass_label->setMinimumWidth(140);
  confirm_label->setMinimumWidth(140);
  form->addRow(new_pass_label, new_pass);
  form->addRow(confirm_label, confirm);
  layout->addLayout(form);

  auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
  if (auto* ok_btn = buttons->button(QDialogButtonBox::Ok)) {
    ok_btn->setText("ОК");
  }
  if (auto* cancel_btn = buttons->button(QDialogButtonBox::Cancel)) {
    cancel_btn->setText("Отмена");
  }
  QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
  QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
  layout->addWidget(buttons);

  if (dialog.exec() != QDialog::Accepted) {
    return false;
  }
  if (new_pass->text().isEmpty()) {
    QMessageBox::warning(parent, "Смена пароля", "Пароль не может быть пустым");
    return false;
  }
  if (new_pass->text() != confirm->text()) {
    QMessageBox::warning(parent, "Смена пароля", "Пароли не совпадают");
    return false;
  }
  *new_password_out = new_pass->text();
  return true;
}

bool ensure_client_tls(cipheator::ClientConfig* cfg,
                       const std::string& config_path,
                       const std::string& enroll_token,
                       int enroll_port,
                       std::string* err) {
  if (!cfg) return false;
  std::filesystem::path base = config_path.empty()
                                  ? std::filesystem::current_path()
                                  : std::filesystem::path(config_path).parent_path();
  std::filesystem::path cert_dir = base / "certs";
  std::error_code ec;
  std::filesystem::create_directories(cert_dir, ec);

  if (cfg->client_key.empty()) {
    cfg->client_key = (cert_dir / "client.key").string();
  }
  if (cfg->client_cert.empty()) {
    cfg->client_cert = (cert_dir / "client.crt").string();
  }
  if (cfg->ca_file.empty()) {
    cfg->ca_file = (cert_dir / "ca.crt").string();
  }

  bool key_ok = std::filesystem::exists(cfg->client_key, ec);
  bool cert_ok = std::filesystem::exists(cfg->client_cert, ec);
  bool ca_ok = std::filesystem::exists(cfg->ca_file, ec);
  if (key_ok && cert_ok && ca_ok) return true;

  if (!key_ok) {
    std::string gen_err;
    if (!cipheator::generate_rsa_key(cfg->client_key, 2048, &gen_err)) {
      if (err) *err = "Не удалось создать ключ: " + gen_err;
      return false;
    }
  }

  std::filesystem::path csr_path = cert_dir / "client.csr";
  cipheator::CertSubject subject;
  subject.common_name = "cipheator-client";
  std::string csr_err;
  if (!cipheator::generate_csr(cfg->client_key, csr_path.string(), subject, &csr_err)) {
    if (err) *err = "Не удалось создать CSR: " + csr_err;
    return false;
  }

  std::string csr_pem;
  if (!cipheator::read_text_file(csr_path.string(), &csr_pem, &csr_err)) {
    if (err) *err = "Не удалось прочитать CSR: " + csr_err;
    return false;
  }

  cipheator::ClientConfig enroll_cfg = *cfg;
  enroll_cfg.port = enroll_port > 0 ? enroll_port : cfg->port;
  enroll_cfg.verify_peer = false;
  enroll_cfg.client_cert.clear();
  enroll_cfg.client_key.clear();

  cipheator::ClientCore enroll_client(enroll_cfg);
  cipheator::EnrollResult enroll;
  if (!enroll_client.enroll_certificate("client", enroll_token, csr_pem, &enroll)) {
    if (err) *err = enroll.message.empty() ? "Ошибка регистрации TLS" : enroll.message;
    return false;
  }

  std::string write_err;
  if (!cipheator::write_text_file(cfg->client_cert, enroll.cert_pem, &write_err)) {
    if (err) *err = "Не удалось сохранить сертификат: " + write_err;
    return false;
  }
  if (!cipheator::write_text_file(cfg->ca_file, enroll.ca_pem, &write_err)) {
    if (err) *err = "Не удалось сохранить CA: " + write_err;
    return false;
  }

  return true;
}

} // namespace

int main(int argc, char** argv) {
  QApplication app(argc, argv);
  app.setWindowIcon(QIcon(":/app/assets/app_icon.svg"));
  app.setStyle("Fusion");
  const char* kStyle = R"(
    QWidget {
      font-family: "Segoe UI", "SF Pro Text", "Helvetica Neue", Arial;
      font-size: 13px;
      color: #1f2937;
    }
    QDialog {
      background: #f7f9fb;
    }
    QMainWindow { background: #f7f9fb; }
    QLabel {
      color: #1f2937;
      padding-right: 4px;
    }
    QGroupBox {
      border: 1px solid #e3e8ef;
      border-radius: 8px;
      margin-top: 14px;
      padding: 16px 12px 12px 12px;
      background: #ffffff;
    }
    QGroupBox::title {
      subcontrol-origin: margin;
      left: 12px;
      top: 0px;
      padding: 0 6px;
      color: #0f5f5f;
      font-weight: 600;
      background: #f7f9fb;
    }
    QLabel#headerTitle {
      font-size: 20px;
      font-weight: 700;
      color: #0f5f5f;
    }
    QLabel#headerSub {
      color: #6b7280;
    }
    QLabel#headerSub { margin-bottom: 6px; }
    QLineEdit, QComboBox {
      background: #f8fafc;
      border: 1px solid #d7dee7;
      border-radius: 6px;
      padding: 4px 8px;
    }
    QComboBox QAbstractItemView {
      background: #ffffff;
      color: #1f2937;
      selection-background-color: #0f5f5f;
      selection-color: #ffffff;
      border: 1px solid #d7dee7;
    }
    QListWidget {
      background: #ffffff;
      border: 1px solid #e3e8ef;
      border-radius: 6px;
    }
    QPlainTextEdit, QTextEdit {
      background: #ffffff;
      color: #1f2937;
      border: 1px solid #d7dee7;
      border-radius: 6px;
      selection-background-color: #0f5f5f;
      selection-color: #ffffff;
    }
    QCheckBox { padding: 2px; }
    QCheckBox::indicator {
      width: 16px;
      height: 16px;
      border: 1px solid #c7ced8;
      border-radius: 3px;
      background: #ffffff;
    }
    QCheckBox::indicator:checked {
      border: 1px solid #0f5f5f;
      background: #ffffff;
      image: url(:/app/assets/checkmark.svg);
    }
    QPushButton {
      background: #0f5f5f;
      color: white;
      border: none;
      border-radius: 6px;
      padding: 6px 12px;
    }
    QPushButton:disabled {
      background: #a3b9b8;
      color: #f0f0f0;
    }
    QPushButton#secondary {
      background: #eef2f6;
      color: #0f5f5f;
      border: 1px solid #d7dee7;
    }
    QPushButton#danger {
      background: transparent;
      color: #b00020;
      border: 1px solid #b00020;
    }
    QPushButton#danger:hover {
      background: rgba(176, 0, 32, 0.08);
    }
    QToolButton {
      background: transparent;
      color: #0f5f5f;
      border: none;
      text-decoration: underline;
    }
  )";
  app.setStyleSheet(kStyle);

  namespace fs = std::filesystem;
  fs::path exe_path = fs::absolute(argv[0]);

  cipheator::Config config;
  std::string config_path = "config/client.conf";
  bool loaded = config.load(config_path);
  if (!loaded) {
    std::vector<fs::path> candidates = {
        exe_path.parent_path() / "config" / "client.conf",
        exe_path.parent_path() / ".." / "config" / "client.conf",
        fs::current_path() / ".." / "config" / "client.conf",
    };
    for (const auto& path : candidates) {
      if (config.load(path.string())) {
        loaded = true;
        config_path = path.string();
        break;
      }
    }
  }

  cipheator::ClientConfig client_cfg;
  client_cfg.host = config.get("server_host", "127.0.0.1");
  client_cfg.port = config.get_int("server_port", 7443);
  client_cfg.ca_file = resolve_relative_path(config.get("ca_file"), config_path, exe_path);
  client_cfg.client_cert = resolve_relative_path(config.get("client_cert"), config_path, exe_path);
  client_cfg.client_key = resolve_relative_path(config.get("client_key"), config_path, exe_path);
  client_cfg.verify_peer = config.get_bool("verify_peer", true);
  client_cfg.default_key_storage = config.get("default_key_storage", "server");
  client_cfg.clipboard_max_bytes = static_cast<size_t>(config.get_int("clipboard_max_bytes", 0));
  client_cfg.decrypt_to_temp = config.get_bool("decrypt_to_temp", false);
  client_cfg.demo_mode = config.get_bool("demo_mode", false);
  std::string enroll_token = config.get("enroll_token");
  int enroll_port = config.get_int("enroll_port", 7445);
  uint64_t last_policy_version = 0;
  try {
    last_policy_version = static_cast<uint64_t>(std::stoull(config.get("last_policy_version", "0")));
  } catch (...) {
    last_policy_version = 0;
  }

  if (!loaded) {
    QMessageBox::warning(nullptr, "ПАК АС",
                         "Файл config/client.conf не найден. Используются значения по умолчанию; TLS может не работать.");
  }

  std::string enroll_err;
  if (!ensure_client_tls(&client_cfg, config_path, enroll_token, enroll_port, &enroll_err)) {
    QMessageBox::critical(nullptr, "Вход в систему",
                          "Ошибка регистрации TLS: " + QString::fromStdString(enroll_err));
    return 1;
  }

  if (is_device_locked()) {
    QMessageBox::critical(nullptr, "Вход в систему",
                          "АРМ заблокирован до перезапуска устройства.");
    return 1;
  }

  QString session_user;
  QString session_pass;
  int login_failures = 0;
  uint64_t policy_version = 0;
  for (;;) {
    LoginDialog login;
    login.setDefaults(QString::fromStdString(client_cfg.host), client_cfg.port);
    if (login.exec() != QDialog::Accepted) {
      return 0;
    }

    client_cfg.host = login.host().toStdString();
    client_cfg.port = login.port();

    cipheator::ClientCore auth_client(client_cfg);
    std::string auth_err;
    std::string auth_code;
    if (!auth_client.authenticate(login.username().toStdString(),
                                  login.password().toStdString(),
                                  &auth_err,
                                  &auth_code,
                                  &policy_version)) {
      if (auth_code == "password_expired") {
        QString new_password;
        if (!prompt_password_change(nullptr, &new_password)) {
          QMessageBox::warning(nullptr, "Вход в систему",
                               "Пароль просрочен. Требуется смена пароля.");
          continue;
        }
        std::string change_err;
        if (!auth_client.change_password(login.username().toStdString(),
                                         login.password().toStdString(),
                                         new_password.toStdString(),
                                         &change_err)) {
          QMessageBox::warning(nullptr, "Смена пароля",
                               "Ошибка: " + QString::fromStdString(change_err));
          continue;
        }
        std::string reauth_err;
        std::string reauth_code;
        if (!auth_client.authenticate(login.username().toStdString(),
                                      new_password.toStdString(),
                                      &reauth_err,
                                      &reauth_code,
                                      &policy_version)) {
          QMessageBox::warning(nullptr, "Вход в систему",
                               "Ошибка авторизации: " + QString::fromStdString(reauth_err));
          continue;
        }
        session_user = login.username();
        session_pass = new_password;
        break;
      }

      if (auth_code == "auth_failed") {
        login_failures += 1;
        if (login_failures >= 3) {
          set_device_lock();
          QMessageBox::critical(nullptr, "Вход в систему",
                                "АРМ заблокирован до перезапуска устройства.");
          return 1;
        }
      }
      QMessageBox::warning(nullptr, "Вход в систему",
                           "Ошибка авторизации: " + QString::fromStdString(auth_err));
      continue;
    }

    login_failures = 0;
    session_user = login.username();
    session_pass = login.password();
    break;
  }

  if (policy_version > last_policy_version) {
    QMessageBox::information(nullptr, "Вход в систему",
                             "Политики безопасности были обновлены администратором.");
    last_policy_version = policy_version;
  }

  std::vector<std::pair<std::string, std::string>> updates = {
      {"server_host", client_cfg.host},
      {"server_port", std::to_string(client_cfg.port)},
      {"ca_file", client_cfg.ca_file},
      {"client_cert", client_cfg.client_cert},
      {"client_key", client_cfg.client_key},
      {"enroll_port", std::to_string(enroll_port)},
      {"last_policy_version", std::to_string(last_policy_version)}
  };
  if (!enroll_token.empty()) {
    updates.push_back({"enroll_token", enroll_token});
  }
  update_config_values(config_path, updates);

  MainWindow window(client_cfg, session_user, session_pass);
  window.show();

  return app.exec();
}
