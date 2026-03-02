#include "cipheator/auth.h"
#include "cipheator/base64.h"
#include "cipheator/config.h"
#include "cipheator/crypto.h"
#include "cipheator/gost_cli.h"
#include "cipheator/net.h"
#include "cipheator/protocol.h"
#include "cipheator/tls.h"
#include "cipheator/bytes.h"

#include "audit.h"
#include "monitor.h"
#include "admin_server.h"

#include <filesystem>
#include <iostream>
#include <mutex>
#include <thread>
#include <memory>
#include <vector>

#include <openssl/rand.h>

namespace fs = std::filesystem;

namespace {

struct ServerContext {
  cipheator::Config config;
  cipheator::UserStore users;
  std::mutex users_mutex;
  std::string users_db_path;

  std::string storage_dir;
  std::string keys_dir;
  std::string hashes_dir;

  cipheator::GostCli gost;
  cipheator::CryptoEngine crypto;
  cipheator::TlsContext tls_ctx;
  bool tls_ready = false;

  std::unique_ptr<cipheator::AuditService> audit;
  std::unique_ptr<cipheator::SecurityMonitor> monitor;
  std::unique_ptr<cipheator::AdminServer> admin_server;

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

void send_error(cipheator::TlsStream& stream, const std::string& message) {
  cipheator::Header header;
  header.set("status", "error");
  header.set("message", message);
  cipheator::write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, header);
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

  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "encrypt remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "encrypt");
      send_error(stream, "Authentication failed");
      return;
    }
  }
  if (ctx.monitor) ctx.monitor->record_login_success(username);
  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "encrypt post_login remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
  }

  cipheator::Cipher cipher;
  if (!cipheator::CryptoEngine::cipher_from_string(cipher_str, &cipher)) {
    send_error(stream, "Unknown cipher");
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
  if (ctx.monitor) ctx.monitor->record_file_op(username, "encrypt", 1);
  if (ctx.audit) ctx.audit->log_event("encrypt", username, file_name);
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

  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "decrypt remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "decrypt");
      send_error(stream, "Authentication failed");
      return;
    }
  }
  if (ctx.monitor) ctx.monitor->record_login_success(username);
  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      discard_payload(stream, file_size);
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "decrypt post_login remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
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
  if (ctx.monitor) ctx.monitor->record_file_op(username, "decrypt", 1);
  if (ctx.audit) ctx.audit->log_event("decrypt", username, "ok");
}

void handle_change_password(ServerContext& ctx,
                            cipheator::TlsStream& stream,
                            const cipheator::Header& req) {
  std::string username = req.get("username");
  std::string password = req.get("password");
  std::string new_password = req.get("new_password");

  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "change_password remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
  }

  std::lock_guard<std::mutex> lock(ctx.users_mutex);
  if (!ctx.users.verify(username, password)) {
    if (ctx.monitor) ctx.monitor->record_login_failure(username);
    if (ctx.audit) ctx.audit->log_event("auth_failed", username, "change_password");
    send_error(stream, "Authentication failed");
    return;
  }
  if (ctx.monitor) ctx.monitor->record_login_success(username);
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

  if (ctx.monitor) {
    int64_t remaining = 0;
    if (ctx.monitor->is_locked(username, &remaining)) {
      if (ctx.audit) {
        ctx.audit->log_event("auth_locked", username,
                             "auth_check remaining_sec=" + std::to_string(remaining));
      }
      send_error(stream, "Account locked. Try again in " + std::to_string(remaining) + "s");
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(ctx.users_mutex);
    if (!ctx.users.verify(username, password)) {
      if (ctx.monitor) ctx.monitor->record_login_failure(username);
      if (ctx.audit) ctx.audit->log_event("auth_failed", username, "auth_check");
      send_error(stream, "Authentication failed");
      return;
    }
  }
  if (ctx.monitor) ctx.monitor->record_login_success(username);
  if (ctx.audit) ctx.audit->log_event("auth_ok", username, "auth_check");

  cipheator::Header resp;
  resp.set("status", "ok");
  resp.set("message", "Authentication successful");
  cipheator::write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, resp);
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
  if (op == "encrypt") {
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
  bool loaded = config.load("config/server.conf");
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

  cipheator::GostCliConfig gost_cfg;
  gost_cfg.enc_magma = config.get("enc_magma");
  gost_cfg.dec_magma = config.get("dec_magma");
  gost_cfg.enc_kuznechik = config.get("enc_kuznechik");
  gost_cfg.dec_kuznechik = config.get("dec_kuznechik");
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

  ctx.users_db_path = (fs::path(ctx.storage_dir) / "users.db").string();
  ctx.users.load(ctx.users_db_path);

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

  std::string stats_path = (fs::path(ctx.storage_dir) / "user_stats.db").string();
  ctx.monitor = std::make_unique<cipheator::SecurityMonitor>(monitor_cfg, ctx.audit.get(), stats_path);
  ctx.monitor->load_stats();

  if (argc == 4 && std::string(argv[1]) == "--init-user") {
    std::string username = argv[2];
    std::string password = argv[3];
    ctx.users.upsert(username, password);
    ctx.users.save(ctx.users_db_path);
    std::cout << "User initialized" << std::endl;
    return 0;
  }

  std::string tls_err;
  ctx.tls_ready = ctx.tls_ctx.init_server(ctx.config.get("cert_file"),
                                          ctx.config.get("key_file"),
                                          ctx.config.get("ca_file"),
                                          ctx.config.get_bool("require_client_cert", false),
                                          &tls_err);
  if (!ctx.tls_ready) {
    std::cerr << "TLS init failed: " << tls_err << std::endl;
    return 1;
  }

  std::string admin_token = config.get("admin_token");
  std::string admin_host = config.get("admin_host", "0.0.0.0");
  int admin_port = config.get_int("admin_port", 7444);
  if (!admin_token.empty()) {
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
