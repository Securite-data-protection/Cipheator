#include "cipheator/auth.h"
#include "cipheator/base64.h"
#include "cipheator/config.h"
#include "cipheator/crypto.h"
#include "cipheator/gost_cli.h"
#include "cipheator/net.h"
#include "cipheator/protocol.h"
#include "cipheator/tls.h"
#include "cipheator/bytes.h"
#include "cipheator/pki.h"

#include "audit.h"
#include "monitor.h"
#include "admin_server.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <thread>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <ctime>

#include <openssl/rand.h>

namespace fs = std::filesystem;

namespace {

struct ServerContext {
  cipheator::Config config;
  cipheator::UserStore users;
  std::mutex users_mutex;
  std::string users_db_path;
  int password_max_age_days = 90;
  bool proactive_enabled = true;
  std::string policy_path;
  std::atomic<bool> admin_enabled{true};
  int64_t admin_created_ts = 0;
  int64_t last_config_change_ts = 0;
  int last_config_change_day = 0;
  int config_changes_today = 0;
  uint64_t policy_version = 0;

  std::string storage_dir;
  std::string keys_dir;
  std::string hashes_dir;
  std::string admin_token;
  std::string binding_db_path;
  std::string ca_cert_path;
  std::string ca_key_path;
  std::string enroll_token;
  bool enroll_open = false;
  std::string enroll_host;
  int enroll_port = 7445;

  cipheator::GostCli gost;
  cipheator::CryptoEngine crypto;
  cipheator::TlsContext tls_ctx;
  bool tls_ready = false;
  std::unique_ptr<cipheator::TlsContext> enroll_tls_ctx;

  std::unique_ptr<cipheator::AuditService> audit;
  std::unique_ptr<cipheator::SecurityMonitor> monitor;
  std::unique_ptr<cipheator::AdminServer> admin_server;
  cipheator::MonitorConfig monitor_cfg;

  struct ClientBindingRecord {
    bool allowed = false;
    int64_t first_seen_ts = 0;
    int64_t last_seen_ts = 0;
    std::string label;
  };
  std::mutex binding_mutex;
  bool binding_enabled = false;
  std::unordered_map<std::string, ClientBindingRecord> client_bindings;

  size_t max_header_bytes = 65536;
  size_t max_file_bytes = 100 * 1024 * 1024;

  ServerContext(const cipheator::GostCliConfig& gost_cfg)
      : gost(gost_cfg), crypto(&gost) {}
};

std::string random_hex(size_t bytes) {
  std::vector<uint8_t> data(bytes);
  RAND_bytes(data.data(), static_cast<int>(data.size()));
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes * 2);
  for (uint8_t b : data) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

std::string resolve_relative_path(const std::string& value,
                                  const std::string& config_path,
                                  const fs::path& exe_path) {
  if (value.empty()) return value;
  fs::path p(value);
  if (p.is_absolute()) return p.string();
  std::vector<fs::path> bases;
  if (!config_path.empty()) {
    bases.push_back(fs::path(config_path).parent_path());
  }
  if (!exe_path.empty()) {
    bases.push_back(exe_path.parent_path());
  }
  bases.push_back(fs::current_path());

  std::error_code ec;
  for (const auto& base : bases) {
    if (base.empty()) continue;
    fs::path candidate = base / p;
    if (fs::exists(candidate, ec)) {
      return candidate.string();
    }
  }
  return value;
}

bool read_exact(cipheator::TlsStream& stream, std::vector<uint8_t>* out, size_t size) {
  out->resize(size);
  size_t total = 0;
  while (total < size) {
    int n = stream.read(out->data() + total, size - total);
    if (n <= 0) return false;
    total += static_cast<size_t>(n);
  }
  return true;
}

bool discard_payload(cipheator::TlsStream& stream, size_t size) {
  if (size == 0) return true;
  std::vector<uint8_t> tmp;
  if (!read_exact(stream, &tmp, size)) return false;
  if (!tmp.empty()) {
    cipheator::secure_zero(tmp.data(), tmp.size());
  }
  return true;
}

bool write_all(cipheator::TlsStream& stream, const std::vector<uint8_t>& data) {
  size_t total = 0;
  while (total < data.size()) {
    int n = stream.write(data.data() + total, data.size() - total);
    if (n <= 0) return false;
    total += static_cast<size_t>(n);
  }
  return true;
}

bool store_key(const std::string& path,
               const std::vector<uint8_t>& key,
               const std::vector<uint8_t>& iv,
               const std::vector<uint8_t>& tag) {
  std::vector<uint8_t> blob(12);
  cipheator::write_be32(static_cast<uint32_t>(key.size()), blob.data());
  cipheator::write_be32(static_cast<uint32_t>(iv.size()), blob.data() + 4);
  cipheator::write_be32(static_cast<uint32_t>(tag.size()), blob.data() + 8);
  blob.insert(blob.end(), key.begin(), key.end());
  blob.insert(blob.end(), iv.begin(), iv.end());
  blob.insert(blob.end(), tag.begin(), tag.end());
  return cipheator::write_file(path, blob);
}

bool load_key(const std::string& path,
              std::vector<uint8_t>* key,
              std::vector<uint8_t>* iv,
              std::vector<uint8_t>* tag) {
  bool ok = false;
  std::vector<uint8_t> blob = cipheator::read_file(path, &ok);
  if (!ok || blob.size() < 12) return false;
  uint32_t key_len = cipheator::read_be32(blob.data());
  uint32_t iv_len = cipheator::read_be32(blob.data() + 4);
  uint32_t tag_len = cipheator::read_be32(blob.data() + 8);
  size_t offset = 12;
  if (blob.size() < offset + key_len + iv_len + tag_len) return false;
  key->assign(blob.begin() + offset, blob.begin() + offset + key_len);
  offset += key_len;
  iv->assign(blob.begin() + offset, blob.begin() + offset + iv_len);
  offset += iv_len;
  tag->assign(blob.begin() + offset, blob.begin() + offset + tag_len);
  return true;
}

struct HashRecord {
  std::string alg;
  std::string hex;
  std::string file_name;
};

bool parse_hash_record(const std::string& payload, HashRecord* out) {
  if (!out) return false;
  size_t p1 = payload.find(':');
  if (p1 == std::string::npos) return false;
  size_t p2 = payload.find(':', p1 + 1);
  if (p2 == std::string::npos) return false;
  out->alg = payload.substr(0, p1);
  out->hex = payload.substr(p1 + 1, p2 - p1 - 1);
  out->file_name = payload.substr(p2 + 1);
  return !out->alg.empty() && !out->hex.empty();
}

bool load_hash_record(const std::string& path, HashRecord* out) {
  bool ok = false;
  std::vector<uint8_t> data = cipheator::read_file(path, &ok);
  if (!ok || data.empty()) return false;
  std::string payload(data.begin(), data.end());
  return parse_hash_record(payload, out);
}

void send_error(cipheator::TlsStream& stream,
                const std::string& message,
                const std::string& code = "") {
  cipheator::Header header;
  header.set("status", "error");
  header.set("message", message);
  if (!code.empty()) {
    header.set("error_code", code);
  }
  cipheator::write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, header);
}

void send_payload(cipheator::TlsStream& stream,
                  const cipheator::Header& header,
                  const std::string& payload) {
  if (!cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, header)) {
    return;
  }
  if (payload.empty()) return;
  size_t total = 0;
  while (total < payload.size()) {
    int n = stream.write(reinterpret_cast<const uint8_t*>(payload.data()) + total,
                         payload.size() - total);
    if (n <= 0) return;
    total += static_cast<size_t>(n);
  }
}

bool read_payload(cipheator::TlsStream& stream, size_t size, std::string* out) {
  if (!out) return false;
  if (size == 0) {
    out->clear();
    return true;
  }
  std::vector<uint8_t> buf;
  if (!read_exact(stream, &buf, size)) return false;
  out->assign(buf.begin(), buf.end());
  if (!buf.empty()) {
    cipheator::secure_zero(buf.data(), buf.size());
  }
  return true;
}

std::string sanitize_label(std::string label) {
  for (char& c : label) {
    if (c == '|') c = '/';
  }
  return label;
}

void save_binding_policy(ServerContext& ctx) {
  if (ctx.binding_db_path.empty()) return;
  std::ofstream out(ctx.binding_db_path, std::ios::trunc);
  if (!out) return;
  out << "enabled=" << (ctx.binding_enabled ? "1" : "0") << "\n";
  for (const auto& kv : ctx.client_bindings) {
    const auto& id = kv.first;
    const auto& rec = kv.second;
    out << "client|" << id << "|"
        << (rec.allowed ? "1" : "0") << "|"
        << rec.first_seen_ts << "|"
        << rec.last_seen_ts << "|"
        << sanitize_label(rec.label) << "\n";
  }
}

void load_binding_policy(ServerContext& ctx) {
  ctx.client_bindings.clear();
  ctx.binding_enabled = false;
  std::ifstream in(ctx.binding_db_path);
  if (!in) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    if (line.rfind("enabled=", 0) == 0) {
      ctx.binding_enabled = (line.substr(8) == "1");
      continue;
    }
    if (line.rfind("client|", 0) != 0) continue;
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string part;
    while (std::getline(ss, part, '|')) {
      parts.push_back(part);
    }
    if (parts.size() < 6) continue;
    ServerContext::ClientBindingRecord rec;
    rec.allowed = (parts[2] == "1");
    try {
      rec.first_seen_ts = std::stoll(parts[3]);
      rec.last_seen_ts = std::stoll(parts[4]);
    } catch (...) {
      rec.first_seen_ts = 0;
      rec.last_seen_ts = 0;
    }
    rec.label = parts[5];
    ctx.client_bindings[parts[1]] = rec;
  }
}

void save_security_policy(ServerContext& ctx) {
  if (ctx.policy_path.empty()) return;
  std::ofstream out(ctx.policy_path, std::ios::trunc);
  if (!out) return;
  out << "password_max_age_days=" << ctx.password_max_age_days << "\n";
  out << "proactive_enabled=" << (ctx.proactive_enabled ? "1" : "0") << "\n";
  out << "admin_enabled=" << (ctx.admin_enabled.load() ? "1" : "0") << "\n";
  out << "admin_created_ts=" << ctx.admin_created_ts << "\n";
  out << "last_config_change_ts=" << ctx.last_config_change_ts << "\n";
  out << "last_config_change_day=" << ctx.last_config_change_day << "\n";
  out << "config_changes_today=" << ctx.config_changes_today << "\n";
  out << "policy_version=" << ctx.policy_version << "\n";
  out << "work_hours_start=" << ctx.monitor_cfg.work_hours_start << "\n";
  out << "work_hours_end=" << ctx.monitor_cfg.work_hours_end << "\n";
  out << "failed_login_threshold=" << ctx.monitor_cfg.failed_login_threshold << "\n";
  out << "failed_login_window_sec=" << ctx.monitor_cfg.failed_login_window_sec << "\n";
  out << "bulk_files_threshold=" << ctx.monitor_cfg.bulk_files_threshold << "\n";
  out << "bulk_files_window_sec=" << ctx.monitor_cfg.bulk_files_window_sec << "\n";
  out << "decrypt_burst_threshold=" << ctx.monitor_cfg.decrypt_burst_threshold << "\n";
  out << "decrypt_burst_window_sec=" << ctx.monitor_cfg.decrypt_burst_window_sec << "\n";
  out << "decrypt_volume_threshold_mb=" << ctx.monitor_cfg.decrypt_volume_threshold_mb << "\n";
  out << "decrypt_volume_window_sec=" << ctx.monitor_cfg.decrypt_volume_window_sec << "\n";
}

void load_security_policy(ServerContext& ctx) {
  if (ctx.policy_path.empty()) return;
  std::ifstream in(ctx.policy_path);
  if (!in) return;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') continue;
    auto pos = line.find('=');
    if (pos == std::string::npos) continue;
    std::string key = line.substr(0, pos);
    std::string val = line.substr(pos + 1);
    if (key == "password_max_age_days") {
      try {
        ctx.password_max_age_days = std::stoi(val);
      } catch (...) {
      }
    } else if (key == "proactive_enabled") {
      ctx.proactive_enabled = (val == "1" || val == "true");
    } else if (key == "admin_enabled") {
      ctx.admin_enabled.store(val == "1" || val == "true");
    } else if (key == "admin_created_ts") {
      try {
        ctx.admin_created_ts = std::stoll(val);
      } catch (...) {
      }
    } else if (key == "last_config_change_ts") {
      try {
        ctx.last_config_change_ts = std::stoll(val);
      } catch (...) {
      }
    } else if (key == "last_config_change_day") {
      try {
        ctx.last_config_change_day = std::stoi(val);
      } catch (...) {
      }
    } else if (key == "config_changes_today") {
      try {
        ctx.config_changes_today = std::stoi(val);
      } catch (...) {
      }
    } else if (key == "policy_version") {
      try {
        ctx.policy_version = static_cast<uint64_t>(std::stoull(val));
      } catch (...) {
      }
    } else if (key == "work_hours_start") {
      try {
        ctx.monitor_cfg.work_hours_start = std::stoi(val);
      } catch (...) {
      }
    } else if (key == "work_hours_end") {
      try {
        ctx.monitor_cfg.work_hours_end = std::stoi(val);
      } catch (...) {
      }
    } else if (key == "failed_login_threshold") {
      try {
        ctx.monitor_cfg.failed_login_threshold = static_cast<size_t>(std::stoull(val));
      } catch (...) {
      }
    } else if (key == "failed_login_window_sec") {
      try {
        ctx.monitor_cfg.failed_login_window_sec = std::stoll(val);
      } catch (...) {
      }
    } else if (key == "bulk_files_threshold") {
      try {
        ctx.monitor_cfg.bulk_files_threshold = static_cast<size_t>(std::stoull(val));
      } catch (...) {
      }
    } else if (key == "bulk_files_window_sec") {
      try {
        ctx.monitor_cfg.bulk_files_window_sec = std::stoll(val);
      } catch (...) {
      }
    } else if (key == "decrypt_burst_threshold") {
      try {
        ctx.monitor_cfg.decrypt_burst_threshold = static_cast<size_t>(std::stoull(val));
      } catch (...) {
      }
    } else if (key == "decrypt_burst_window_sec") {
      try {
        ctx.monitor_cfg.decrypt_burst_window_sec = std::stoll(val);
      } catch (...) {
      }
    } else if (key == "decrypt_volume_threshold_mb") {
      try {
        ctx.monitor_cfg.decrypt_volume_threshold_mb = static_cast<size_t>(std::stoull(val));
      } catch (...) {
      }
    } else if (key == "decrypt_volume_window_sec") {
      try {
        ctx.monitor_cfg.decrypt_volume_window_sec = std::stoll(val);
      } catch (...) {
      }
    }
  }
}

void register_client(ServerContext& ctx,
                     const std::string& client_id,
                     const std::string& client_label) {
  const int64_t now = cipheator::now_epoch_sec();
  std::lock_guard<std::mutex> lock(ctx.binding_mutex);
  auto it = ctx.client_bindings.find(client_id);
  if (it == ctx.client_bindings.end()) {
    ServerContext::ClientBindingRecord rec;
    rec.allowed = !ctx.binding_enabled;
    rec.first_seen_ts = now;
    rec.last_seen_ts = now;
    rec.label = sanitize_label(client_label);
    ctx.client_bindings[client_id] = rec;
    save_binding_policy(ctx);
    return;
  }
  it->second.last_seen_ts = now;
  if (!client_label.empty()) {
    it->second.label = sanitize_label(client_label);
  }
  save_binding_policy(ctx);
}

bool is_client_allowed(ServerContext& ctx, const std::string& client_id) {
  std::lock_guard<std::mutex> lock(ctx.binding_mutex);
  if (!ctx.binding_enabled) return true;
  auto it = ctx.client_bindings.find(client_id);
  if (it == ctx.client_bindings.end()) return false;
  return it->second.allowed;
}

bool enforce_client_binding(ServerContext& ctx,
                            cipheator::TlsStream& stream,
                            const cipheator::Header& req,
                            const std::string& username,
                            const std::string& op) {
  std::string client_id = req.get("client_id");
  std::string client_host = req.get("client_host", "unknown");
  if (client_id.empty()) {
    client_id = "unknown";
  }
  register_client(ctx, client_id, client_host);
  if (is_client_allowed(ctx, client_id)) {
    return true;
  }
  if (ctx.audit) {
    ctx.audit->log_alert("client_binding_block", username,
                         "op=" + op + " client_id=" + client_id + " host=" + client_host);
  }
  send_error(stream, "Client is not allowed by binding policy", "client_blocked");
  return false;
}

bool is_password_expired(ServerContext& ctx, const std::string& username) {
  if (ctx.password_max_age_days <= 0) return false;
  return ctx.users.is_password_expired(username, ctx.password_max_age_days);
}

bool is_cipher_allowed_for_encrypt(const std::string& cipher) {
  return cipher == "kuznechik" || cipher == "aes-256-gcm";
}

int local_day_index(int64_t ts) {
  std::time_t t = static_cast<time_t>(ts);
  std::tm tm_val{};
#if defined(_WIN32)
  localtime_s(&tm_val, &t);
#else
  localtime_r(&t, &tm_val);
#endif
  return (tm_val.tm_year + 1900) * 1000 + tm_val.tm_yday;
}

bool is_first_day(const ServerContext& ctx, int64_t now) {
  if (ctx.admin_created_ts == 0) return true;
  return (now - ctx.admin_created_ts) < 24 * 60 * 60;
}

bool can_change_config(ServerContext& ctx, std::string* reason) {
  const int64_t now = cipheator::now_epoch_sec();
  if (is_first_day(ctx, now)) return true;
  const int today = local_day_index(now);
  if (ctx.last_config_change_day == today && ctx.config_changes_today >= 1) {
    if (reason) *reason = "Config change limit reached for today";
    return false;
  }
  return true;
}

void record_config_change(ServerContext& ctx) {
  const int64_t now = cipheator::now_epoch_sec();
  const int today = local_day_index(now);
  if (ctx.last_config_change_day != today) {
    ctx.last_config_change_day = today;
    ctx.config_changes_today = 0;
  }
  ctx.config_changes_today += 1;
  ctx.last_config_change_ts = now;
}

void record_policy_change(ServerContext& ctx) {
  record_config_change(ctx);
  ctx.policy_version += 1;
}

void handle_encrypt(ServerContext& ctx,
                    cipheator::TlsStream& stream,
                    const cipheator::Header& req) {
  std::string username = req.get("username");
  std::string password = req.get("password");
  std::string cipher_str = req.get("cipher");
  std::string hash_str = req.get("hash");
  std::string key_storage = req.get("key_storage", "server");
  std::string file_name = req.get("file_name");
  size_t file_size = 0;
  try {
    file_size = static_cast<size_t>(std::stoull(req.get("file_size", "0")));
  } catch (...) {
    send_error(stream, "Invalid file_size");
    return;
  }

  if (file_size > ctx.max_file_bytes) {
    send_error(stream, "File too large");
    return;
  }

  if (!enforce_client_binding(ctx, stream, req, username, "encrypt")) {
    discard_payload(stream, file_size);
    return;
  }

  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "encrypt remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "encrypt");
      send_error(stream, "Authentication failed", "auth_failed");
      return;
    }
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_success(username);
  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "encrypt post_login remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }
  if (is_password_expired(ctx, username)) {
    send_error(stream, "Password expired", "password_expired");
    return;
  }

  cipheator::Cipher cipher;
  if (!cipheator::CryptoEngine::cipher_from_string(cipher_str, &cipher)) {
    send_error(stream, "Unknown cipher");
    return;
  }
  if (!is_cipher_allowed_for_encrypt(cipher_str)) {
    send_error(stream, "Cipher not allowed");
    return;
  }
  cipheator::HashAlg hash_alg;
  if (!cipheator::CryptoEngine::hash_from_string(hash_str, &hash_alg)) {
    send_error(stream, "Unknown hash algorithm");
    return;
  }

  std::vector<uint8_t> plaintext;
  if (!read_exact(stream, &plaintext, file_size)) {
    send_error(stream, "Failed to read file");
    return;
  }

  cipheator::HashResult hash_result;
  std::string err;
  if (!ctx.crypto.hash(hash_alg, plaintext, &hash_result, &err)) {
    send_error(stream, "Hash failed: " + err);
    return;
  }

  cipheator::CryptoResult crypto_result;
  if (!ctx.crypto.encrypt(cipher, plaintext, &crypto_result, &err)) {
    send_error(stream, "Encrypt failed: " + err);
    return;
  }
  if (!plaintext.empty()) {
    cipheator::secure_zero(plaintext.data(), plaintext.size());
  }

  std::string key_id;
  if (key_storage != "server" && key_storage != "client") {
    send_error(stream, "Invalid key_storage");
    return;
  }

  if (key_storage == "server") {
    key_id = random_hex(16);
    fs::path key_path = fs::path(ctx.keys_dir) / (key_id + ".bin");
    if (!store_key(key_path.string(), crypto_result.key, crypto_result.iv, crypto_result.tag)) {
      send_error(stream, "Failed to store key");
      return;
    }
  }

  std::string file_id = random_hex(16);
  fs::path hash_path = fs::path(ctx.hashes_dir) / (file_id + ".hash");
  std::string hash_payload = hash_str + ":" + hash_result.hex + ":" + file_name;
  cipheator::write_file(hash_path.string(),
                        std::vector<uint8_t>(hash_payload.begin(), hash_payload.end()));

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("cipher", cipher_str);
  resp.set("hash", hash_str);
  resp.set("file_id", file_id);
  resp.set("hash_value", hash_result.hex);
  resp.set("enc_size", std::to_string(crypto_result.data.size()));
  resp.set("policy_version", std::to_string(ctx.policy_version));

  if (!key_id.empty()) {
    resp.set("key_id", key_id);
  }
  if (key_storage == "client") {
    resp.set("key", cipheator::base64_encode(crypto_result.key));
  }
  if (!crypto_result.iv.empty()) {
    resp.set("iv", cipheator::base64_encode(crypto_result.iv));
  }
  if (!crypto_result.tag.empty()) {
    resp.set("tag", cipheator::base64_encode(crypto_result.tag));
  }

  if (!cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp)) {
    return;
  }
  write_all(stream, crypto_result.data);
  if (!crypto_result.data.empty()) {
    cipheator::secure_zero(crypto_result.data.data(), crypto_result.data.size());
  }
  if (!crypto_result.key.empty()) {
    cipheator::secure_zero(crypto_result.key.data(), crypto_result.key.size());
  }
  if (!crypto_result.iv.empty()) {
    cipheator::secure_zero(crypto_result.iv.data(), crypto_result.iv.size());
  }
  if (!crypto_result.tag.empty()) {
    cipheator::secure_zero(crypto_result.tag.data(), crypto_result.tag.size());
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_file_op(username, "encrypt", 1, file_size);
  if (ctx.audit) {
    std::ostringstream detail;
    detail << "file=" << file_name
           << " file_size=" << file_size
           << " enc_size=" << crypto_result.data.size()
           << " cipher=" << cipher_str;
    ctx.audit->log_event("encrypt", username, detail.str());
  }
}

void handle_decrypt(ServerContext& ctx,
                    cipheator::TlsStream& stream,
                    const cipheator::Header& req) {
  std::string username = req.get("username");
  std::string password = req.get("password");
  std::string cipher_str = req.get("cipher");
  std::string hash_str = req.get("hash");
  std::string file_id = req.get("file_id");
  std::string key_id = req.get("key_id");
  std::string key_b64 = req.get("key");
  std::string iv_b64 = req.get("iv");
  std::string tag_b64 = req.get("tag");
  size_t file_size = 0;
  try {
    file_size = static_cast<size_t>(std::stoull(req.get("file_size", "0")));
  } catch (...) {
    send_error(stream, "Invalid file_size");
    return;
  }

  if (file_size > ctx.max_file_bytes) {
    send_error(stream, "File too large");
    return;
  }

  if (!enforce_client_binding(ctx, stream, req, username, "decrypt")) {
    discard_payload(stream, file_size);
    return;
  }

  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "decrypt remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "decrypt");
      send_error(stream, "Authentication failed", "auth_failed");
      return;
    }
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_success(username);
  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "decrypt post_login remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }
  if (is_password_expired(ctx, username)) {
    send_error(stream, "Password expired", "password_expired");
    return;
  }

  cipheator::Cipher cipher;
  if (!cipheator::CryptoEngine::cipher_from_string(cipher_str, &cipher)) {
    send_error(stream, "Unknown cipher");
    return;
  }

  std::vector<uint8_t> ciphertext;
  if (!read_exact(stream, &ciphertext, file_size)) {
    send_error(stream, "Failed to read file");
    return;
  }

  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> tag;

  if (!key_id.empty()) {
    fs::path key_path = fs::path(ctx.keys_dir) / (key_id + ".bin");
    if (!load_key(key_path.string(), &key, &iv, &tag)) {
      send_error(stream, "Key not found");
      return;
    }
  } else {
    bool ok = false;
    key = cipheator::base64_decode(key_b64, &ok);
    if (!ok || key.empty()) {
      send_error(stream, "Invalid key" );
      return;
    }
    if (!iv_b64.empty()) {
      iv = cipheator::base64_decode(iv_b64, &ok);
      if (!ok) {
        send_error(stream, "Invalid IV" );
        return;
      }
    }
    if (!tag_b64.empty()) {
      tag = cipheator::base64_decode(tag_b64, &ok);
      if (!ok) {
        send_error(stream, "Invalid tag" );
        return;
      }
    }
  }

  cipheator::CryptoResult crypto_result;
  std::string err;
  if (!ctx.crypto.decrypt(cipher, ciphertext, key, iv, tag, &crypto_result, &err)) {
    send_error(stream, "Decrypt failed: " + err);
    return;
  }

  auto scrub_sensitive = [&]() {
    if (!crypto_result.data.empty()) {
      cipheator::secure_zero(crypto_result.data.data(), crypto_result.data.size());
    }
    if (!crypto_result.key.empty()) {
      cipheator::secure_zero(crypto_result.key.data(), crypto_result.key.size());
    }
    if (!crypto_result.iv.empty()) {
      cipheator::secure_zero(crypto_result.iv.data(), crypto_result.iv.size());
    }
    if (!crypto_result.tag.empty()) {
      cipheator::secure_zero(crypto_result.tag.data(), crypto_result.tag.size());
    }
    if (!ciphertext.empty()) {
      cipheator::secure_zero(ciphertext.data(), ciphertext.size());
    }
    if (!key.empty()) {
      cipheator::secure_zero(key.data(), key.size());
    }
    if (!iv.empty()) {
      cipheator::secure_zero(iv.data(), iv.size());
    }
    if (!tag.empty()) {
      cipheator::secure_zero(tag.data(), tag.size());
    }
  };

  if (!file_id.empty()) {
    HashRecord record;
    fs::path hash_path = fs::path(ctx.hashes_dir) / (file_id + ".hash");
    if (!load_hash_record(hash_path.string(), &record)) {
      send_error(stream, "Hash record not found");
      scrub_sensitive();
      return;
    }
    if (!hash_str.empty() && hash_str != record.alg) {
      if (ctx.audit) {
        ctx.audit->log_event("hash_mismatch", username,
                             "file_id=" + file_id + " request=" + hash_str +
                             " stored=" + record.alg);
      }
    }
    cipheator::HashAlg hash_alg;
    if (!cipheator::CryptoEngine::hash_from_string(record.alg, &hash_alg)) {
      send_error(stream, "Unknown hash algorithm");
      scrub_sensitive();
      return;
    }
    cipheator::HashResult verify;
    if (!ctx.crypto.hash(hash_alg, crypto_result.data, &verify, &err)) {
      send_error(stream, "Hash failed: " + err);
      scrub_sensitive();
      return;
    }
    if (verify.hex != record.hex) {
      if (ctx.audit) {
        ctx.audit->log_alert("integrity_failed", username,
                             "file_id=" + file_id + " expected=" + record.hex +
                             " got=" + verify.hex);
      }
      send_error(stream, "Integrity check failed");
      scrub_sensitive();
      return;
    }
  }

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("plain_size", std::to_string(crypto_result.data.size()));
  resp.set("policy_version", std::to_string(ctx.policy_version));

  if (!cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp)) {
    return;
  }
  write_all(stream, crypto_result.data);
  if (!crypto_result.data.empty()) {
    cipheator::secure_zero(crypto_result.data.data(), crypto_result.data.size());
  }
  if (!crypto_result.key.empty()) {
    cipheator::secure_zero(crypto_result.key.data(), crypto_result.key.size());
  }
  if (!crypto_result.iv.empty()) {
    cipheator::secure_zero(crypto_result.iv.data(), crypto_result.iv.size());
  }
  if (!crypto_result.tag.empty()) {
    cipheator::secure_zero(crypto_result.tag.data(), crypto_result.tag.size());
  }
  if (!ciphertext.empty()) {
    cipheator::secure_zero(ciphertext.data(), ciphertext.size());
  }
  if (!key.empty()) {
    cipheator::secure_zero(key.data(), key.size());
  }
  if (!iv.empty()) {
    cipheator::secure_zero(iv.data(), iv.size());
  }
  if (!tag.empty()) {
    cipheator::secure_zero(tag.data(), tag.size());
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_file_op(username, "decrypt", 1, crypto_result.data.size());
  if (ctx.audit) {
    std::ostringstream detail;
    detail << "file_id=" << file_id
           << " enc_size=" << file_size
           << " plain_size=" << crypto_result.data.size()
           << " cipher=" << cipher_str;
    ctx.audit->log_event("decrypt", username, detail.str());
  }
}

void handle_change_password(ServerContext& ctx,
                            cipheator::TlsStream& stream,
                            const cipheator::Header& req) {
  std::string username = req.get("username");
  std::string password = req.get("password");
  std::string new_password = req.get("new_password");

  if (!enforce_client_binding(ctx, stream, req, username, "change_password")) {
    return;
  }

  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "change_password remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }

  std::lock_guard<std::mutex> lock(ctx.users_mutex);
  if (!ctx.users.verify(username, password)) {
    if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_failure(username);
    if (ctx.audit) ctx.audit->log_event("auth_failed", username, "change_password");
    send_error(stream, "Authentication failed", "auth_failed");
    return;
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_success(username);
  ctx.users.upsert(username, new_password);
  ctx.users.save(ctx.users_db_path);
  if (ctx.audit) ctx.audit->log_event("change_password", username, "ok");

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("message", "Password updated");
  cipheator::write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, resp);
}

void handle_auth_check(ServerContext& ctx,
                       cipheator::TlsStream& stream,
                       const cipheator::Header& req) {
  const std::string username = req.get("username");
  const std::string password = req.get("password");

  if (!enforce_client_binding(ctx, stream, req, username, "auth_check")) {
    return;
  }

  if (ctx.proactive_enabled && ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "auth_check remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s",
                 "account_locked");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "auth_check");
      send_error(stream, "Authentication failed", "auth_failed");
      return;
    }
  }
  if (ctx.proactive_enabled && ctx.monitor) ctx.monitor->record_login_success(username);
  if (is_password_expired(ctx, username)) {
    send_error(stream, "Password expired", "password_expired");
    return;
  }
  if (ctx.audit) ctx.audit->log_event("auth_ok", username, "auth_check");

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("message", "Authentication successful");
  resp.set("policy_version", std::to_string(ctx.policy_version));
  cipheator::write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, resp);
}

void handle_enroll_request(ServerContext& ctx,
                           cipheator::TlsStream& stream,
                           const cipheator::Header& req) {
  if (!ctx.enroll_open && !ctx.enroll_token.empty() &&
      req.get("enroll_token") != ctx.enroll_token) {
    send_error(stream, "Unauthorized enrollment");
    return;
  }

  size_t payload_size = 0;
  try {
    payload_size = static_cast<size_t>(std::stoull(req.get("payload_size", "0")));
  } catch (...) {
    send_error(stream, "Invalid payload_size");
    return;
  }
  if (payload_size == 0 || payload_size > ctx.max_header_bytes) {
    send_error(stream, "Invalid CSR size");
    return;
  }

  std::string csr_pem;
  if (!read_payload(stream, payload_size, &csr_pem)) {
    send_error(stream, "Failed to read CSR");
    return;
  }

  std::string role = req.get("role", "client");
  bool client_cert = true;
  if (role == "server") {
    client_cert = false;
  }

  std::string cert_pem;
  std::string err;
  if (!cipheator::sign_csr_pem(ctx.ca_key_path, ctx.ca_cert_path,
                               csr_pem, 365, client_cert, &cert_pem, &err)) {
    send_error(stream, "CSR sign failed: " + err);
    return;
  }

  std::string ca_pem;
  if (!cipheator::read_text_file(ctx.ca_cert_path, &ca_pem, &err)) {
    send_error(stream, "CA read failed: " + err);
    return;
  }

  const std::string delimiter = "\n-----CIPHEATOR-CERT-----\n";
  std::string payload = ca_pem + delimiter + cert_pem;

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("payload_size", std::to_string(payload.size()));
  send_payload(stream, resp, payload);

  if (ctx.audit) {
    ctx.audit->log_event("enroll_cert", "system", "role=" + role);
  }
}

void handle_enroll_session(ServerContext& ctx, cipheator::Socket client) {
  if (!ctx.enroll_tls_ctx) return;
  cipheator::TlsStream stream;
  std::string err;
  if (!stream.accept(std::move(client), *ctx.enroll_tls_ctx, &err)) {
    return;
  }

  cipheator::Header req;
  if (!cipheator::read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, ctx.max_header_bytes, &req)) {
    return;
  }

  if (req.get("op") != "enroll") {
    send_error(stream, "Unknown operation");
    return;
  }

  handle_enroll_request(ctx, stream, req);
}

void run_enroll_server(ServerContext* ctx) {
  if (!ctx) return;
  cipheator::NetInit net_init;
  if (!net_init.ok()) return;

  std::string err;
  cipheator::Socket server = cipheator::Socket::listen_on(ctx->enroll_host, ctx->enroll_port, &err);
  if (!server.valid()) {
    if (ctx->audit) {
      ctx->audit->log_event("enroll_listen_error", "system", err);
    }
    return;
  }
  if (ctx->audit) {
    ctx->audit->log_event("enroll_server_start", "system",
                          ctx->enroll_host + ":" + std::to_string(ctx->enroll_port));
  }

  while (true) {
    cipheator::Socket client = server.accept(&err);
    if (!client.valid()) continue;
    std::thread([ctx, c = std::move(client)]() mutable {
      handle_enroll_session(*ctx, std::move(c));
    }).detach();
  }
}

void handle_session(ServerContext& ctx, cipheator::Socket client) {
  cipheator::TlsStream stream;
  std::string err;
  if (!stream.accept(std::move(client), ctx.tls_ctx, &err)) {
    std::cerr << "TLS accept failed: " << err << std::endl;
    return;
  }

  cipheator::Header req;
  if (!cipheator::read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, ctx.max_header_bytes, &req)) {
    return;
  }

  std::string op = req.get("op");
  if (op.rfind("admin_", 0) == 0) {
    if (ctx.admin_token.empty() || req.get("admin_token") != ctx.admin_token) {
      send_error(stream, "Unauthorized");
      return;
    }
    if (!ctx.admin_enabled.load()) {
      send_error(stream, "Admin role removed", "admin_disabled");
      return;
    }

    if (op == "admin_get_alerts") {
      uint64_t since_id = 0;
      size_t limit = 100;
      try {
        if (!req.get("since_id").empty()) {
          since_id = std::stoull(req.get("since_id"));
        }
        if (!req.get("limit").empty()) {
          limit = static_cast<size_t>(std::stoull(req.get("limit")));
        }
      } catch (...) {
        send_error(stream, "Invalid parameters");
        return;
      }

      std::ostringstream payload;
      uint64_t last_id = since_id;
      auto alerts = ctx.audit ? ctx.audit->get_alerts_since(since_id, limit)
                              : std::vector<cipheator::AlertRecord>();
      for (const auto& alert : alerts) {
        payload << cipheator::format_alert_line(alert) << "\n";
        if (alert.id > last_id) last_id = alert.id;
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("payload_size", std::to_string(payload.str().size()));
      resp.set("last_id", std::to_string(last_id));
      send_payload(stream, resp, payload.str());
      return;
    }

    if (op == "admin_get_logs") {
      size_t limit = 200;
      try {
        if (!req.get("limit").empty()) {
          limit = static_cast<size_t>(std::stoull(req.get("limit")));
        }
      } catch (...) {
        send_error(stream, "Invalid parameters");
        return;
      }
      std::ostringstream payload;
      auto lines = ctx.audit ? ctx.audit->tail_logs(limit) : std::vector<std::string>();
      for (const auto& line : lines) {
        payload << line << "\n";
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("payload_size", std::to_string(payload.str().size()));
      send_payload(stream, resp, payload.str());
      return;
    }

    if (op == "admin_get_stats") {
      size_t limit = 200;
      try {
        if (!req.get("limit").empty()) {
          limit = static_cast<size_t>(std::stoull(req.get("limit")));
        }
      } catch (...) {
        send_error(stream, "Invalid parameters");
        return;
      }
      std::ostringstream payload;
      auto lines = ctx.monitor ? ctx.monitor->dump_stats(limit) : std::vector<std::string>();
      for (const auto& line : lines) {
        payload << line << "\n";
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("payload_size", std::to_string(payload.str().size()));
      send_payload(stream, resp, payload.str());
      return;
    }

    if (op == "admin_get_policy") {
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("password_max_age_days", std::to_string(ctx.password_max_age_days));
      resp.set("proactive_enabled", ctx.proactive_enabled ? "1" : "0");
      resp.set("admin_enabled", ctx.admin_enabled.load() ? "1" : "0");
      resp.set("admin_created_ts", std::to_string(ctx.admin_created_ts));
      resp.set("last_config_change_ts", std::to_string(ctx.last_config_change_ts));
      resp.set("policy_version", std::to_string(ctx.policy_version));
      resp.set("work_hours_start", std::to_string(ctx.monitor_cfg.work_hours_start));
      resp.set("work_hours_end", std::to_string(ctx.monitor_cfg.work_hours_end));
      resp.set("failed_login_threshold", std::to_string(ctx.monitor_cfg.failed_login_threshold));
      resp.set("failed_login_window_sec", std::to_string(ctx.monitor_cfg.failed_login_window_sec));
      resp.set("bulk_files_threshold", std::to_string(ctx.monitor_cfg.bulk_files_threshold));
      resp.set("bulk_files_window_sec", std::to_string(ctx.monitor_cfg.bulk_files_window_sec));
      resp.set("decrypt_burst_threshold", std::to_string(ctx.monitor_cfg.decrypt_burst_threshold));
      resp.set("decrypt_burst_window_sec", std::to_string(ctx.monitor_cfg.decrypt_burst_window_sec));
      resp.set("decrypt_volume_threshold_mb", std::to_string(ctx.monitor_cfg.decrypt_volume_threshold_mb));
      resp.set("decrypt_volume_window_sec", std::to_string(ctx.monitor_cfg.decrypt_volume_window_sec));
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    if (op == "admin_set_policy") {
      std::string limit_reason;
      if (!can_change_config(ctx, &limit_reason)) {
        send_error(stream, "Config change limit reached");
        return;
      }
      bool changed = false;
      if (!req.get("password_max_age_days").empty()) {
        try {
          ctx.password_max_age_days = std::stoi(req.get("password_max_age_days"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid password_max_age_days");
          return;
        }
      }
      if (!req.get("proactive_enabled").empty()) {
        std::string val = req.get("proactive_enabled");
        ctx.proactive_enabled = (val == "1" || val == "true");
        changed = true;
      }
      if (!req.get("work_hours_start").empty()) {
        try {
          ctx.monitor_cfg.work_hours_start = std::stoi(req.get("work_hours_start"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid work_hours_start");
          return;
        }
      }
      if (!req.get("work_hours_end").empty()) {
        try {
          ctx.monitor_cfg.work_hours_end = std::stoi(req.get("work_hours_end"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid work_hours_end");
          return;
        }
      }
      if (!req.get("failed_login_threshold").empty()) {
        try {
          ctx.monitor_cfg.failed_login_threshold = static_cast<size_t>(std::stoull(req.get("failed_login_threshold")));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid failed_login_threshold");
          return;
        }
      }
      if (!req.get("failed_login_window_sec").empty()) {
        try {
          ctx.monitor_cfg.failed_login_window_sec = std::stoll(req.get("failed_login_window_sec"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid failed_login_window_sec");
          return;
        }
      }
      if (!req.get("bulk_files_threshold").empty()) {
        try {
          ctx.monitor_cfg.bulk_files_threshold = static_cast<size_t>(std::stoull(req.get("bulk_files_threshold")));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid bulk_files_threshold");
          return;
        }
      }
      if (!req.get("bulk_files_window_sec").empty()) {
        try {
          ctx.monitor_cfg.bulk_files_window_sec = std::stoll(req.get("bulk_files_window_sec"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid bulk_files_window_sec");
          return;
        }
      }
      if (!req.get("decrypt_burst_threshold").empty()) {
        try {
          ctx.monitor_cfg.decrypt_burst_threshold = static_cast<size_t>(std::stoull(req.get("decrypt_burst_threshold")));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid decrypt_burst_threshold");
          return;
        }
      }
      if (!req.get("decrypt_burst_window_sec").empty()) {
        try {
          ctx.monitor_cfg.decrypt_burst_window_sec = std::stoll(req.get("decrypt_burst_window_sec"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid decrypt_burst_window_sec");
          return;
        }
      }
      if (!req.get("decrypt_volume_threshold_mb").empty()) {
        try {
          ctx.monitor_cfg.decrypt_volume_threshold_mb = static_cast<size_t>(std::stoull(req.get("decrypt_volume_threshold_mb")));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid decrypt_volume_threshold_mb");
          return;
        }
      }
      if (!req.get("decrypt_volume_window_sec").empty()) {
        try {
          ctx.monitor_cfg.decrypt_volume_window_sec = std::stoll(req.get("decrypt_volume_window_sec"));
          changed = true;
        } catch (...) {
          send_error(stream, "Invalid decrypt_volume_window_sec");
          return;
        }
      }
      if (changed) {
        record_policy_change(ctx);
        save_security_policy(ctx);
        if (ctx.monitor) {
          ctx.monitor->update_config(ctx.monitor_cfg);
        }
        if (ctx.audit) {
          std::ostringstream detail;
          detail << "password_max_age_days=" << ctx.password_max_age_days
                 << " proactive_enabled=" << (ctx.proactive_enabled ? "1" : "0")
                 << " work_hours=" << ctx.monitor_cfg.work_hours_start << "-" << ctx.monitor_cfg.work_hours_end;
          ctx.audit->log_event("admin_set_policy", "admin", detail.str());
        }
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("message", "Policy updated");
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    if (op == "admin_get_locks") {
      size_t limit = 200;
      try {
        if (!req.get("limit").empty()) {
          limit = static_cast<size_t>(std::stoull(req.get("limit")));
        }
      } catch (...) {
        send_error(stream, "Invalid parameters");
        return;
      }
      std::ostringstream payload;
      auto lines = ctx.monitor ? ctx.monitor->dump_locks(limit) : std::vector<std::string>();
      for (const auto& line : lines) {
        payload << line << "\n";
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("payload_size", std::to_string(payload.str().size()));
      send_payload(stream, resp, payload.str());
      return;
    }

    if (op == "admin_unlock_user") {
      std::string username = req.get("username");
      if (username.empty()) {
        send_error(stream, "Missing username");
        return;
      }
      bool ok = false;
      bool reduced_only = false;
      if (ctx.monitor) {
        const int64_t now = cipheator::now_epoch_sec();
        if (is_first_day(ctx, now)) {
          ok = ctx.monitor->unlock_user(username);
        } else {
          ok = ctx.monitor->reduce_lock(username, 3 * 60 * 60);
          reduced_only = ok;
        }
      }
      if (!ok) {
        send_error(stream, "User not found");
        return;
      }
      if (ctx.audit) {
        ctx.audit->log_event("admin_unlock_user", "admin", username);
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("message", reduced_only ? "Блокировка сокращена (макс. 3 часа)" : "Блокировка снята");
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    if (op == "admin_get_binding") {
      size_t limit = 500;
      try {
        if (!req.get("limit").empty()) {
          limit = static_cast<size_t>(std::stoull(req.get("limit")));
        }
      } catch (...) {
        send_error(stream, "Invalid parameters");
        return;
      }
      std::ostringstream payload;
      {
        std::lock_guard<std::mutex> lock(ctx.binding_mutex);
        size_t n = 0;
        for (const auto& kv : ctx.client_bindings) {
          payload << kv.first << "|"
                  << (kv.second.allowed ? "1" : "0") << "|"
                  << kv.second.first_seen_ts << "|"
                  << kv.second.last_seen_ts << "|"
                  << kv.second.label << "\n";
          ++n;
          if (limit > 0 && n >= limit) break;
        }
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("binding_enabled", ctx.binding_enabled ? "1" : "0");
      resp.set("payload_size", std::to_string(payload.str().size()));
      send_payload(stream, resp, payload.str());
      return;
    }

    if (op == "admin_set_binding") {
      std::string limit_reason;
      if (!can_change_config(ctx, &limit_reason)) {
        send_error(stream, "Config change limit reached");
        return;
      }
      std::string enabled = req.get("enabled");
      bool en = (enabled == "1" || enabled == "true");
      {
        std::lock_guard<std::mutex> lock(ctx.binding_mutex);
        ctx.binding_enabled = en;
        save_binding_policy(ctx);
      }
      record_policy_change(ctx);
      save_security_policy(ctx);
      if (ctx.audit) {
        ctx.audit->log_event("admin_set_binding", "admin", en ? "enabled" : "disabled");
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("message", en ? "Binding enabled" : "Binding disabled");
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    if (op == "admin_set_client_allowed") {
      std::string limit_reason;
      if (!can_change_config(ctx, &limit_reason)) {
        send_error(stream, "Config change limit reached");
        return;
      }
      std::string client_id = req.get("client_id");
      if (client_id.empty()) {
        send_error(stream, "Missing client_id");
        return;
      }
      bool allowed = (req.get("allowed") == "1" || req.get("allowed") == "true");
      {
        std::lock_guard<std::mutex> lock(ctx.binding_mutex);
        auto& rec = ctx.client_bindings[client_id];
        if (rec.first_seen_ts == 0) {
          rec.first_seen_ts = cipheator::now_epoch_sec();
          rec.last_seen_ts = rec.first_seen_ts;
          rec.label = "manual";
        }
        rec.allowed = allowed;
        save_binding_policy(ctx);
      }
      record_policy_change(ctx);
      save_security_policy(ctx);
      if (ctx.audit) {
        ctx.audit->log_event("admin_set_client_allowed", "admin",
                             client_id + "=" + (allowed ? "1" : "0"));
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("message", allowed ? "Client allowed" : "Client blocked");
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    if (op == "admin_delete_role") {
      const int64_t now = cipheator::now_epoch_sec();
      int64_t reference = ctx.last_config_change_ts > 0 ? ctx.last_config_change_ts : ctx.admin_created_ts;
      if (reference == 0) reference = now;
      if ((now - reference) < 3 * 24 * 60 * 60) {
        send_error(stream, "Admin role can be removed only after 3 days without config changes");
        return;
      }
      ctx.admin_enabled.store(false);
      save_security_policy(ctx);
      if (ctx.audit) {
        ctx.audit->log_event("admin_role_removed", "admin", "irreversible");
      }
      cipheator::Header resp;
      resp.set("status", "ok");
      resp.set("message", "Admin role removed");
      cipheator::write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, resp);
      return;
    }

    send_error(stream, "Unknown admin operation");
    return;
  } else if (op == "encrypt") {
    handle_encrypt(ctx, stream, req);
  } else if (op == "decrypt") {
    handle_decrypt(ctx, stream, req);
  } else if (op == "change_password") {
    handle_change_password(ctx, stream, req);
  } else if (op == "auth_check") {
    handle_auth_check(ctx, stream, req);
  } else {
    send_error(stream, "Unknown operation");
  }
}

} // namespace

int main(int argc, char** argv) {
  cipheator::Config config;
  std::string config_path = "config/server.conf";
  bool loaded = config.load(config_path);
  if (!loaded) {
    fs::path exe = fs::absolute(argv[0]);
    std::vector<fs::path> candidates = {
        exe.parent_path() / "config" / "server.conf",
        exe.parent_path() / ".." / "config" / "server.conf",
        fs::current_path() / ".." / "config" / "server.conf",
    };
    for (const auto& path : candidates) {
      if (config.load(path.string())) {
        loaded = true;
        config_path = path.string();
        break;
      }
    }
  }
  if (!loaded) {
    std::cerr << "Failed to load config/server.conf" << std::endl;
    return 1;
  }

  cipheator::NetInit net_init;
  if (!net_init.ok()) {
    std::cerr << "Network init failed" << std::endl;
    return 1;
  }

  fs::path exe_path = fs::absolute(argv[0]);
  cipheator::GostCliConfig gost_cfg;
  gost_cfg.enc_magma = resolve_relative_path(config.get("enc_magma"), config_path, exe_path);
  gost_cfg.dec_magma = resolve_relative_path(config.get("dec_magma"), config_path, exe_path);
  gost_cfg.enc_kuznechik = resolve_relative_path(config.get("enc_kuznechik"), config_path, exe_path);
  gost_cfg.dec_kuznechik = resolve_relative_path(config.get("dec_kuznechik"), config_path, exe_path);
  gost_cfg.enc_suffix = config.get("gost_enc_suffix", ".enc");
  gost_cfg.key_suffix = config.get("gost_key_suffix", ".key");

  ServerContext ctx(gost_cfg);
  ctx.config = config;
  ctx.storage_dir = config.get("storage_dir", "storage");
  ctx.keys_dir = fs::path(ctx.storage_dir) / "keys";
  ctx.hashes_dir = fs::path(ctx.storage_dir) / "hashes";
  ctx.max_header_bytes = static_cast<size_t>(config.get_int("max_header_bytes", 65536));
  ctx.max_file_bytes = static_cast<size_t>(config.get_int("max_file_bytes", 104857600));

  fs::create_directories(ctx.keys_dir);
  fs::create_directories(ctx.hashes_dir);
  fs::create_directories(fs::path(ctx.storage_dir) / "logs");
  fs::path cert_dir = fs::path(ctx.storage_dir) / "certs";
  fs::create_directories(cert_dir);

  std::string cert_file = resolve_relative_path(config.get("cert_file"), config_path, exe_path);
  std::string key_file = resolve_relative_path(config.get("key_file"), config_path, exe_path);
  std::string ca_file = resolve_relative_path(config.get("ca_file"), config_path, exe_path);
  std::string ca_key_file = resolve_relative_path(config.get("ca_key_file"), config_path, exe_path);
  if (cert_file.empty()) cert_file = (cert_dir / "server.crt").string();
  if (key_file.empty()) key_file = (cert_dir / "server.key").string();
  if (ca_file.empty()) ca_file = (cert_dir / "ca.crt").string();
  if (ca_key_file.empty()) ca_key_file = (cert_dir / "ca.key").string();
  ctx.ca_cert_path = ca_file;
  ctx.ca_key_path = ca_key_file;

  bool auto_tls = config.get_bool("auto_tls", true);
  if (auto_tls) {
    std::error_code ec;
    if (!fs::exists(ca_file, ec) || !fs::exists(ca_key_file, ec)) {
      cipheator::CertSubject subject;
      subject.common_name = "Cipheator CA";
      subject.org = "Cipheator";
      std::string pki_err;
      if (!cipheator::generate_ca(ca_key_file, ca_file, subject, 3650, &pki_err)) {
        std::cerr << "CA generate failed: " << pki_err << std::endl;
        return 1;
      }
    }
    if (!fs::exists(cert_file, ec) || !fs::exists(key_file, ec)) {
      cipheator::CertSubject subject;
      subject.common_name = "Cipheator Server";
      subject.org = "Cipheator";
      std::string pki_err;
      if (!cipheator::generate_signed_cert(ca_key_file, ca_file,
                                           key_file, cert_file,
                                           subject, 3650, false, &pki_err)) {
        std::cerr << "Server cert generate failed: " << pki_err << std::endl;
        return 1;
      }
    }
  }

  ctx.users_db_path = (fs::path(ctx.storage_dir) / "users.db").string();
  ctx.users.load(ctx.users_db_path);
  ctx.password_max_age_days = config.get_int("password_max_age_days", 90);
  ctx.proactive_enabled = config.get_bool("proactive_protection_enabled", true);
  ctx.policy_path = (fs::path(ctx.storage_dir) / "security_policy.conf").string();

  std::string log_path = (fs::path(ctx.storage_dir) / "logs" / "events.log").string();
  std::string alert_path = (fs::path(ctx.storage_dir) / "logs" / "alerts.log").string();
  ctx.audit = std::make_unique<cipheator::AuditService>(log_path, alert_path);

  cipheator::MonitorConfig monitor_cfg;
  monitor_cfg.failed_login_threshold = static_cast<size_t>(config.get_int("anomaly_failed_login_threshold", 3));
  monitor_cfg.failed_login_window_sec = static_cast<int64_t>(config.get_int("anomaly_failed_login_window_sec", 600));
  monitor_cfg.bulk_files_threshold = static_cast<size_t>(config.get_int("anomaly_bulk_files_threshold", 20));
  monitor_cfg.bulk_files_window_sec = static_cast<int64_t>(config.get_int("anomaly_bulk_files_window_sec", 300));
  monitor_cfg.time_min_samples = static_cast<size_t>(config.get_int("anomaly_time_min_samples", 5));
  try {
    monitor_cfg.time_hour_fraction = std::stod(config.get("anomaly_time_hour_fraction", "0.2"));
  } catch (...) {
    monitor_cfg.time_hour_fraction = 0.2;
  }
  monitor_cfg.alert_cooldown_sec = static_cast<int64_t>(config.get_int("anomaly_alert_cooldown_sec", 600));
  monitor_cfg.work_hours_start = config.get_int("anomaly_work_hours_start", -1);
  monitor_cfg.work_hours_end = config.get_int("anomaly_work_hours_end", -1);
  monitor_cfg.lock_failed_login_sec = static_cast<int64_t>(config.get_int("anomaly_failed_login_lock_sec", 0));
  monitor_cfg.lock_bulk_files_sec = static_cast<int64_t>(config.get_int("anomaly_bulk_files_lock_sec", 0));
  monitor_cfg.lock_suspicious_time_sec = static_cast<int64_t>(config.get_int("anomaly_time_lock_sec", 0));
  monitor_cfg.decrypt_burst_threshold = static_cast<size_t>(config.get_int("anomaly_decrypt_burst_threshold", 20));
  monitor_cfg.decrypt_burst_window_sec = static_cast<int64_t>(config.get_int("anomaly_decrypt_burst_window_sec", 60));
  monitor_cfg.decrypt_volume_threshold_mb = static_cast<size_t>(config.get_int("anomaly_decrypt_volume_threshold_mb", 256));
  monitor_cfg.decrypt_volume_window_sec = static_cast<int64_t>(config.get_int("anomaly_decrypt_volume_window_sec", 300));
  monitor_cfg.profile_min_decrypt_samples = static_cast<size_t>(config.get_int("anomaly_profile_min_decrypt_samples", 20));
  try {
    monitor_cfg.profile_decrypt_rate_factor = std::stod(config.get("anomaly_profile_decrypt_rate_factor", "3.0"));
  } catch (...) {
    monitor_cfg.profile_decrypt_rate_factor = 3.0;
  }
  try {
    monitor_cfg.profile_decrypt_bytes_factor = std::stod(config.get("anomaly_profile_decrypt_bytes_factor", "4.0"));
  } catch (...) {
    monitor_cfg.profile_decrypt_bytes_factor = 4.0;
  }

  ctx.monitor_cfg = monitor_cfg;
  load_security_policy(ctx);
  if (ctx.admin_created_ts == 0) {
    ctx.admin_created_ts = cipheator::now_epoch_sec();
  }
  if (!fs::exists(ctx.policy_path)) {
    save_security_policy(ctx);
  }
  std::string stats_path = (fs::path(ctx.storage_dir) / "user_stats.db").string();
  ctx.monitor = std::make_unique<cipheator::SecurityMonitor>(ctx.monitor_cfg, ctx.audit.get(), stats_path);
  ctx.monitor->load_stats();
  ctx.binding_db_path = (fs::path(ctx.storage_dir) / "client_binding.db").string();
  load_binding_policy(ctx);
  if (config.get_bool("client_binding_enabled", false)) {
    ctx.binding_enabled = true;
    save_binding_policy(ctx);
  }

  if (ctx.monitor) {
    ctx.monitor->update_config(ctx.monitor_cfg);
  }

  if (argc == 4 && std::string(argv[1]) == "--init-user") {
    std::string username = argv[2];
    std::string password = argv[3];
    ctx.users.upsert(username, password);
    ctx.users.save(ctx.users_db_path);
    std::cout << "User initialized" << std::endl;
    return 0;
  }

  std::string tls_err;
  ctx.tls_ready = ctx.tls_ctx.init_server(cert_file,
                                          key_file,
                                          ca_file,
                                          ctx.config.get_bool("require_client_cert", false),
                                          &tls_err);
  if (!ctx.tls_ready) {
    std::cerr << "TLS init failed: " << tls_err << std::endl;
    return 1;
  }

  ctx.enroll_host = config.get("enroll_host", "0.0.0.0");
  ctx.enroll_port = config.get_int("enroll_port", 7445);
  ctx.enroll_token = config.get("enroll_token");
  ctx.enroll_open = config.get_bool("enroll_open", ctx.enroll_token.empty());

  if (ctx.enroll_port > 0) {
    ctx.enroll_tls_ctx = std::make_unique<cipheator::TlsContext>();
    std::string enroll_tls_err;
    if (ctx.enroll_tls_ctx->init_server(cert_file, key_file, ca_file, false, &enroll_tls_err)) {
      std::thread(run_enroll_server, &ctx).detach();
    } else if (ctx.audit) {
      ctx.audit->log_event("enroll_tls_failed", "system", enroll_tls_err);
    }
  }

  std::string admin_token = config.get("admin_token");
  ctx.admin_token = admin_token;
  if (admin_token.empty()) {
    ctx.admin_enabled.store(false);
  }
  std::string admin_host = config.get("admin_host", "0.0.0.0");
  int admin_port = config.get_int("admin_port", 7444);
  if (!admin_token.empty() && ctx.admin_enabled.load()) {
    ctx.admin_server = std::make_unique<cipheator::AdminServer>(admin_host, admin_port,
                                                                admin_token, &ctx.tls_ctx,
                                                                ctx.audit.get(), ctx.monitor.get());
    ctx.admin_server->start();
    if (ctx.audit) {
      ctx.audit->log_event("admin_server_start", "system", admin_host + ":" + std::to_string(admin_port));
    }
  } else {
    if (ctx.audit) {
      ctx.audit->log_event("admin_server_disabled", "system", "admin_token not set");
    }
  }

  std::string host = config.get("listen_host", "0.0.0.0");
  int port = config.get_int("listen_port", 7443);

  std::string err;
  cipheator::Socket server = cipheator::Socket::listen_on(host, port, &err);
  if (!server.valid()) {
    std::cerr << "Failed to listen: " << err << std::endl;
    return 1;
  }

  std::cout << "Server listening on " << host << ":" << port << std::endl;
  if (ctx.audit) {
    ctx.audit->log_event("server_start", "system", host + ":" + std::to_string(port));
  }

  while (true) {
    cipheator::Socket client = server.accept(&err);
    if (!client.valid()) {
      std::cerr << "Accept failed: " << err << std::endl;
      continue;
    }
    std::thread([&ctx, c = std::move(client)]() mutable {
      handle_session(ctx, std::move(c));
    }).detach();
  }

  return 0;
}
