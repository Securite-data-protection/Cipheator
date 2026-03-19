#include "main_window.h"
#include "login_dialog.h"
#include "client_core.h"

#include "cipheator/config.h"

#include <QApplication>
#include <QIcon>
#include <QMessageBox>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

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

  if (!loaded) {
    QMessageBox::warning(nullptr, "ПАК АС",
                         "Файл config/client.conf не найден. Используются значения по умолчанию; TLS может не работать.");
  }

  QString session_user;
  QString session_pass;
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
    if (!auth_client.authenticate(login.username().toStdString(),
                                  login.password().toStdString(),
                                  &auth_err)) {
      QMessageBox::warning(nullptr, "Вход в систему",
                           "Ошибка авторизации: " + QString::fromStdString(auth_err));
      continue;
    }

    session_user = login.username();
    session_pass = login.password();
    break;
  }

  update_config_values(config_path, {
      {"server_host", client_cfg.host},
      {"server_port", std::to_string(client_cfg.port)}
  });

  MainWindow window(client_cfg, session_user, session_pass);
  window.show();

  return app.exec();
}
