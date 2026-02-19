#include "main_window.h"
#include "login_dialog.h"

#include "cipheator/config.h"

#include <QApplication>
#include <QMessageBox>

#include <filesystem>
#include <vector>

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  cipheator::Config config;
  bool loaded = config.load("config/client.conf");
  if (!loaded) {
    namespace fs = std::filesystem;
    fs::path exe = fs::absolute(argv[0]);
    std::vector<fs::path> candidates = {
        exe.parent_path() / "config" / "client.conf",
        exe.parent_path() / ".." / "config" / "client.conf",
        fs::current_path() / ".." / "config" / "client.conf",
    };
    for (const auto& path : candidates) {
      if (config.load(path.string())) {
        loaded = true;
        break;
      }
    }
  }

  cipheator::ClientConfig client_cfg;
  client_cfg.host = config.get("server_host", "127.0.0.1");
  client_cfg.port = config.get_int("server_port", 7443);
  client_cfg.ca_file = config.get("ca_file");
  client_cfg.client_cert = config.get("client_cert");
  client_cfg.client_key = config.get("client_key");
  client_cfg.verify_peer = config.get_bool("verify_peer", true);
  client_cfg.default_key_storage = config.get("default_key_storage", "server");
  client_cfg.clipboard_max_bytes = static_cast<size_t>(config.get_int("clipboard_max_bytes", 0));
  client_cfg.decrypt_to_temp = config.get_bool("decrypt_to_temp", false);

  if (!loaded) {
    QMessageBox::warning(nullptr, "Cipheator",
                         "config/client.conf not found. Using defaults; TLS may fail.");
  }

  LoginDialog login;
  login.setDefaults(QString::fromStdString(client_cfg.host), client_cfg.port);
  if (login.exec() != QDialog::Accepted) {
    return 0;
  }

  client_cfg.host = login.host().toStdString();
  client_cfg.port = login.port();

  MainWindow window(client_cfg, login.username(), login.password());
  window.show();

  return app.exec();
}
