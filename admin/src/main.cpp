#include "admin_window.h"

#include "cipheator/config.h"
#include "cipheator/net.h"
#include "cipheator/pki.h"
#include "cipheator/protocol.h"
#include "cipheator/tls.h"

#include <QApplication>
#include <QMessageBox>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace {

std::string trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
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

  std::ofstream out(path, std::ios::trunc);
  if (!out) return false;
  for (const auto& line : lines) {
    out << line << "\n";
  }
  return true;
}

std::string detect_enroll_host() {
  std::ifstream in("config/admin_devices.conf");
  if (!in) return "";
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    size_t p1 = line.find('|');
    size_t p2 = line.find('|', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) continue;
    return line.substr(p1 + 1, p2 - p1 - 1);
  }
  return "";
}

bool enroll_over_tls(const std::string& host,
                     int port,
                     const std::string& token,
                     const std::string& csr_pem,
                     std::string* cert_pem,
                     std::string* ca_pem,
                     std::string* err) {
  cipheator::NetInit net_init;
  if (!net_init.ok()) {
    if (err) *err = "Network init failed";
    return false;
  }
  cipheator::Socket socket;
  std::string conn_err;
  if (!socket.connect_to(host, port, &conn_err)) {
    if (err) *err = "Connect failed: " + conn_err;
    return false;
  }

  cipheator::TlsContext tls_ctx;
  if (!tls_ctx.init_client("", "", "", false, &conn_err)) {
    if (err) *err = "TLS init failed: " + conn_err;
    return false;
  }

  cipheator::TlsStream stream;
  if (!stream.connect(std::move(socket), tls_ctx, host, &conn_err)) {
    if (err) *err = "TLS connect failed: " + conn_err;
    return false;
  }

  cipheator::Header header;
  header.set("op", "enroll");
  header.set("role", "admin");
  if (!token.empty()) header.set("enroll_token", token);
  header.set("payload_size", std::to_string(csr_pem.size()));

  if (!cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, header)) {
    if (err) *err = "Failed to send enroll header";
    return false;
  }

  size_t total = 0;
  while (total < csr_pem.size()) {
    int n = stream.write(reinterpret_cast<const uint8_t*>(csr_pem.data()) + total,
                         csr_pem.size() - total);
    if (n <= 0) {
      if (err) *err = "Failed to send CSR payload";
      return false;
    }
    total += static_cast<size_t>(n);
  }

  cipheator::Header resp;
  if (!cipheator::read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, 65536, &resp)) {
    if (err) *err = "Failed to read enroll response";
    return false;
  }

  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Enroll failed");
    return false;
  }

  size_t payload_size = 0;
  try {
    payload_size = static_cast<size_t>(std::stoull(resp.get("payload_size", "0")));
  } catch (...) {
    if (err) *err = "Invalid payload_size";
    return false;
  }

  std::string payload;
  payload.resize(payload_size);
  total = 0;
  while (total < payload_size) {
    int n = stream.read(reinterpret_cast<uint8_t*>(&payload[0]) + total,
                        payload_size - total);
    if (n <= 0) {
      if (err) *err = "Failed to read enroll payload";
      return false;
    }
    total += static_cast<size_t>(n);
  }

  const std::string delimiter = "\n-----CIPHEATOR-CERT-----\n";
  auto pos = payload.find(delimiter);
  if (pos == std::string::npos) {
    if (err) *err = "Invalid enroll payload";
    return false;
  }
  if (ca_pem) *ca_pem = payload.substr(0, pos);
  if (cert_pem) *cert_pem = payload.substr(pos + delimiter.size());
  return true;
}

bool ensure_admin_tls(cipheator::AdminConfig* cfg,
                      const std::string& config_path,
                      const std::string& enroll_host,
                      int enroll_port,
                      const std::string& enroll_token,
                      std::string* err) {
  if (!cfg) return false;
  std::filesystem::path base = config_path.empty()
                                  ? std::filesystem::current_path()
                                  : std::filesystem::path(config_path).parent_path();
  std::filesystem::path cert_dir = base / "certs";
  std::error_code ec;
  std::filesystem::create_directories(cert_dir, ec);

  if (cfg->client_key.empty()) {
    cfg->client_key = (cert_dir / "admin.key").string();
  }
  if (cfg->client_cert.empty()) {
    cfg->client_cert = (cert_dir / "admin.crt").string();
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

  std::filesystem::path csr_path = cert_dir / "admin.csr";
  cipheator::CertSubject subject;
  subject.common_name = "cipheator-admin";
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

  std::string cert_pem;
  std::string ca_pem;
  if (!enroll_over_tls(enroll_host, enroll_port, enroll_token, csr_pem,
                       &cert_pem, &ca_pem, err)) {
    return false;
  }

  std::string write_err;
  if (!cipheator::write_text_file(cfg->client_cert, cert_pem, &write_err)) {
    if (err) *err = "Не удалось сохранить сертификат: " + write_err;
    return false;
  }
  if (!cipheator::write_text_file(cfg->ca_file, ca_pem, &write_err)) {
    if (err) *err = "Не удалось сохранить CA: " + write_err;
    return false;
  }

  return true;
}

} // namespace

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  cipheator::Config config;
  std::string config_path = "config/admin.conf";
  config.load(config_path);

  cipheator::AdminConfig admin_cfg;
  admin_cfg.ca_file = config.get("ca_file");
  admin_cfg.client_cert = config.get("client_cert");
  admin_cfg.client_key = config.get("client_key");
  admin_cfg.verify_peer = config.get_bool("verify_peer", true);

  std::string enroll_host = config.get("enroll_host");
  if (enroll_host.empty()) {
    enroll_host = detect_enroll_host();
  }
  if (enroll_host.empty()) {
    enroll_host = "127.0.0.1";
  }
  int enroll_port = config.get_int("enroll_port", 7445);
  std::string enroll_token = config.get("enroll_token");
  std::string enroll_err;
  if (!ensure_admin_tls(&admin_cfg, config_path, enroll_host, enroll_port,
                        enroll_token, &enroll_err)) {
    QMessageBox::critical(nullptr, "Админ-панель",
                          "Ошибка регистрации TLS: " + QString::fromStdString(enroll_err));
    return 1;
  }

  std::vector<std::pair<std::string, std::string>> updates = {
      {"ca_file", admin_cfg.ca_file},
      {"client_cert", admin_cfg.client_cert},
      {"client_key", admin_cfg.client_key},
      {"enroll_host", enroll_host},
      {"enroll_port", std::to_string(enroll_port)}
  };
  if (!enroll_token.empty()) {
    updates.push_back({"enroll_token", enroll_token});
  }
  update_config_values(config_path, updates);

  AdminWindow window(admin_cfg);
  window.show();

  return app.exec();
}
