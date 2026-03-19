#include "client_core.h"

#include "cipheator/base64.h"
#include "cipheator/bytes.h"
#include "cipheator/config.h"
#include "cipheator/net.h"
#include "cipheator/protocol.h"
#include "cipheator/tls.h"

#include <openssl/sha.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <algorithm>

namespace fs = std::filesystem;

namespace cipheator {

namespace {

constexpr const char* kFileMagic = "CIPHEATOR\n";
constexpr size_t kFileMagicLen = 10;

enum class EmbeddedReadResult {
  kNotEmbedded,
  kOk,
  kError
};

void log_client_error(const std::string& message) {
  using namespace std::chrono;
  auto now = system_clock::now();
  auto secs = duration_cast<seconds>(now.time_since_epoch()).count();
  std::string line = std::to_string(secs) + " " + message;
  std::cerr << line << std::endl;
  std::ofstream out("client.log", std::ios::app);
  if (out) {
    out << line << "\n";
  }
}

bool write_embedded_file(const std::string& path,
                         const EncryptParams& params,
                         const EncryptResult& result,
                         const std::string& key_storage,
                         const std::vector<uint8_t>& enc_data,
                         std::string* err) {
  Header header;
  header.set("version", "1");
  header.set("cipher", CryptoEngine::cipher_to_string(params.cipher));
  header.set("hash", CryptoEngine::hash_to_string(params.hash));
  header.set("key_storage", key_storage);
  if (!result.file_id.empty()) {
    header.set("file_id", result.file_id);
  }
  if (!result.key_id.empty()) {
    header.set("key_id", result.key_id);
  }
  if (!result.hash_value.empty()) {
    header.set("hash_value", result.hash_value);
  }
  if (!result.iv.empty()) {
    header.set("iv", base64_encode(result.iv));
  }
  if (!result.tag.empty()) {
    header.set("tag", base64_encode(result.tag));
  }
  if (key_storage == "client") {
    if (result.key.empty()) {
      if (err) *err = "Missing client key";
      return false;
    }
    header.set("key", base64_encode(result.key));
  }

  std::string header_blob = std::string(kFileMagic) + header.serialize();
  std::vector<uint8_t> file_bytes;
  file_bytes.reserve(header_blob.size() + enc_data.size());
  file_bytes.insert(file_bytes.end(), header_blob.begin(), header_blob.end());
  file_bytes.insert(file_bytes.end(), enc_data.begin(), enc_data.end());
  if (!write_file(path, file_bytes)) {
    if (err) *err = "Failed to write encrypted file";
    return false;
  }
  return true;
}

EmbeddedReadResult read_embedded_file(const std::string& path,
                                      Header* header,
                                      std::vector<uint8_t>* ciphertext,
                                      std::string* err) {
  bool ok = false;
  std::vector<uint8_t> file = read_file(path, &ok);
  if (!ok) {
    if (err) *err = "Failed to read file";
    return EmbeddedReadResult::kError;
  }
  if (file.size() < kFileMagicLen ||
      std::memcmp(file.data(), kFileMagic, kFileMagicLen) != 0) {
    if (ciphertext) *ciphertext = std::move(file);
    return EmbeddedReadResult::kNotEmbedded;
  }

  const uint8_t* start = file.data() + kFileMagicLen;
  const uint8_t kTerminator[] = {'\n', '\n'};
  auto it = std::search(file.begin() + static_cast<std::vector<uint8_t>::difference_type>(kFileMagicLen),
                        file.end(),
                        kTerminator,
                        kTerminator + 2);
  if (it == file.end()) {
    if (err) *err = "Invalid embedded header";
    return EmbeddedReadResult::kError;
  }
  size_t header_end = static_cast<size_t>(it - file.begin()) + 2;
  std::string header_str(reinterpret_cast<const char*>(start),
                         header_end - kFileMagicLen);
  Header hdr;
  if (!Header::parse(header_str, &hdr)) {
    if (err) *err = "Failed to parse embedded header";
    return EmbeddedReadResult::kError;
  }
  if (header) *header = hdr;
  if (ciphertext) {
    ciphertext->assign(file.begin() + static_cast<long>(header_end), file.end());
  }
  return EmbeddedReadResult::kOk;
}

bool extract_metadata_from_header(const Header& hdr,
                                  std::string* key_storage,
                                  std::string* file_id,
                                  std::string* key_id,
                                  std::string* hash_value,
                                  Cipher* cipher,
                                  HashAlg* hash,
                                  std::vector<uint8_t>* key,
                                  std::vector<uint8_t>* iv,
                                  std::vector<uint8_t>* tag,
                                  std::string* err) {
  std::string cipher_str = hdr.get("cipher");
  if (!CryptoEngine::cipher_from_string(cipher_str, cipher)) {
    if (err) *err = "Invalid cipher in embedded header";
    return false;
  }
  std::string hash_str = hdr.get("hash");
  if (!CryptoEngine::hash_from_string(hash_str, hash)) {
    if (err) *err = "Invalid hash in embedded header";
    return false;
  }
  if (key_storage) *key_storage = hdr.get("key_storage", "server");
  if (file_id) *file_id = hdr.get("file_id");
  if (key_id) *key_id = hdr.get("key_id");
  if (hash_value) *hash_value = hdr.get("hash_value");

  bool ok = false;
  std::string key_b64 = hdr.get("key");
  if (!key_b64.empty()) {
    if (key) {
      *key = base64_decode(key_b64, &ok);
      if (!ok) {
        if (err) *err = "Invalid key in embedded header";
        return false;
      }
    }
  }
  std::string iv_b64 = hdr.get("iv");
  if (!iv_b64.empty()) {
    if (iv) {
      *iv = base64_decode(iv_b64, &ok);
      if (!ok) {
        if (err) *err = "Invalid iv in embedded header";
        return false;
      }
    }
  }
  std::string tag_b64 = hdr.get("tag");
  if (!tag_b64.empty()) {
    if (tag) {
      *tag = base64_decode(tag_b64, &ok);
      if (!ok) {
        if (err) *err = "Invalid tag in embedded header";
        return false;
      }
    }
  }
  return true;
}

std::string host_label() {
  const char* host = std::getenv("HOSTNAME");
#if defined(_WIN32)
  if (!host || !*host) {
    host = std::getenv("COMPUTERNAME");
  }
#endif
  if (host && *host) return host;
  return "unknown-host";
}

std::string user_label() {
  const char* user = std::getenv("USER");
#if defined(_WIN32)
  if (!user || !*user) {
    user = std::getenv("USERNAME");
  }
#endif
  if (user && *user) return user;
  return "unknown-user";
}

std::string home_label() {
  const char* home = std::getenv("HOME");
#if defined(_WIN32)
  if (!home || !*home) {
    home = std::getenv("USERPROFILE");
  }
#endif
  if (home && *home) return home;
  return "";
}

std::string client_id_value() {
  static std::string cached;
  if (!cached.empty()) return cached;
  std::string seed = host_label() + "|" + user_label() + "|" + home_label();
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(seed.data()),
         seed.size(),
         hash);
  static const char* kHex = "0123456789abcdef";
  cached.reserve(SHA256_DIGEST_LENGTH * 2);
  for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
    cached.push_back(kHex[(hash[i] >> 4) & 0xF]);
    cached.push_back(kHex[hash[i] & 0xF]);
  }
  return cached;
}

} // namespace

ClientCore::ClientCore(ClientConfig config) : config_(std::move(config)) {}

bool ClientCore::send_request(const Header& header,
                              const std::vector<uint8_t>& payload,
                              Header* response,
                              std::vector<uint8_t>* out) {
  NetInit net_init;
  if (!net_init.ok()) {
    log_client_error("net_init failed");
    return false;
  }

  Socket socket;
  std::string err;
  if (!socket.connect_to(config_.host, config_.port, &err)) {
    log_client_error("socket connect failed: " + err);
    return false;
  }

  TlsContext tls_ctx;
  if (!tls_ctx.init_client(config_.ca_file, config_.client_cert,
                           config_.client_key, config_.verify_peer, &err)) {
    log_client_error("tls init failed: " + err);
    return false;
  }

  TlsStream stream;
  if (!stream.connect(std::move(socket), tls_ctx, config_.host, &err)) {
    log_client_error("tls connect failed: " + err);
    return false;
  }

  if (!write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, header)) {
    log_client_error("write header failed");
    return false;
  }

  if (!payload.empty()) {
    size_t total = 0;
    while (total < payload.size()) {
      int n = stream.write(payload.data() + total, payload.size() - total);
      if (n <= 0) {
        log_client_error("write payload failed");
        return false;
      }
      total += static_cast<size_t>(n);
    }
  }

  Header resp;
  if (!read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, 65536, &resp)) {
    log_client_error("read header failed");
    return false;
  }

  if (response) *response = resp;

  if (out) {
    out->clear();
    size_t size = 0;
    std::string enc_size = resp.get("enc_size");
    std::string plain_size = resp.get("plain_size");
    try {
      if (!enc_size.empty()) {
        size = static_cast<size_t>(std::stoull(enc_size));
      } else if (!plain_size.empty()) {
        size = static_cast<size_t>(std::stoull(plain_size));
      }
    } catch (...) {
      return false;
    }
    if (size > 0) {
      out->resize(size);
      size_t total = 0;
      while (total < size) {
        int n = stream.read(out->data() + total, size - total);
        if (n <= 0) {
          log_client_error("read payload failed");
          return false;
        }
        total += static_cast<size_t>(n);
      }
    }
  }

  return true;
}

bool ClientCore::store_key_file(const std::string& path,
                                const std::vector<uint8_t>& key,
                                const std::vector<uint8_t>& iv,
                                const std::vector<uint8_t>& tag) {
  std::vector<uint8_t> blob(12);
  write_be32(static_cast<uint32_t>(key.size()), blob.data());
  write_be32(static_cast<uint32_t>(iv.size()), blob.data() + 4);
  write_be32(static_cast<uint32_t>(tag.size()), blob.data() + 8);
  blob.insert(blob.end(), key.begin(), key.end());
  blob.insert(blob.end(), iv.begin(), iv.end());
  blob.insert(blob.end(), tag.begin(), tag.end());
  return write_file(path, blob);
}

bool ClientCore::load_key_file(const std::string& path,
                               std::vector<uint8_t>* key,
                               std::vector<uint8_t>* iv,
                               std::vector<uint8_t>* tag) {
  bool ok = false;
  std::vector<uint8_t> blob = read_file(path, &ok);
  if (!ok || blob.size() < 12) return false;
  uint32_t key_len = read_be32(blob.data());
  uint32_t iv_len = read_be32(blob.data() + 4);
  uint32_t tag_len = read_be32(blob.data() + 8);
  size_t offset = 12;
  if (blob.size() < offset + key_len + iv_len + tag_len) return false;
  key->assign(blob.begin() + offset, blob.begin() + offset + key_len);
  offset += key_len;
  iv->assign(blob.begin() + offset, blob.begin() + offset + iv_len);
  offset += iv_len;
  tag->assign(blob.begin() + offset, blob.begin() + offset + tag_len);
  return true;
}

bool ClientCore::write_metadata(const std::string& file_path,
                                const EncryptParams& params,
                                const EncryptResult& result) {
  fs::path meta_path = file_path + ".cph";
  std::ofstream out(meta_path, std::ios::trunc);
  if (!out) return false;
  out << "cipher=" << CryptoEngine::cipher_to_string(params.cipher) << "\n";
  out << "hash=" << CryptoEngine::hash_to_string(params.hash) << "\n";
  out << "key_storage=" << params.key_storage << "\n";
  if (!result.file_id.empty()) {
    out << "file_id=" << result.file_id << "\n";
  }
  if (!result.key_id.empty()) {
    out << "key_id=" << result.key_id << "\n";
  }
  if (!result.hash_value.empty()) {
    out << "hash_value=" << result.hash_value << "\n";
  }
  if (!result.iv.empty()) {
    out << "iv=" << base64_encode(result.iv) << "\n";
  }
  if (!result.tag.empty()) {
    out << "tag=" << base64_encode(result.tag) << "\n";
  }
  if (params.key_storage == "client") {
    out << "key_file=" << file_path << ".key" << "\n";
  }
  return true;
}

bool ClientCore::read_metadata(const std::string& file_path,
                               std::string* key_storage,
                               std::string* file_id,
                               std::string* key_id,
                               std::string* hash_value,
                               std::string* key_file,
                               Cipher* cipher,
                               HashAlg* hash,
                               std::vector<uint8_t>* iv,
                               std::vector<uint8_t>* tag,
                               std::string* err) {
  fs::path meta_path = file_path + ".cph";
  std::ifstream in(meta_path);
  if (!in) {
    if (err) *err = "Metadata file not found";
    return false;
  }
  std::string line;
  bool cipher_set = false;
  bool key_storage_set = false;
  if (hash) *hash = HashAlg::SHA256;
  if (key_storage) *key_storage = "server";
  if (file_id) file_id->clear();
  if (key_id) key_id->clear();
  if (hash_value) hash_value->clear();
  if (key_file) key_file->clear();
  if (iv) iv->clear();
  if (tag) tag->clear();
  while (std::getline(in, line)) {
    auto pos = line.find('=');
    if (pos == std::string::npos) continue;
    std::string key = line.substr(0, pos);
    std::string val = line.substr(pos + 1);
    if (key == "cipher") {
      if (!CryptoEngine::cipher_from_string(val, cipher)) {
        if (err) *err = "Invalid cipher in metadata";
        return false;
      }
      cipher_set = true;
    } else if (key == "hash") {
      if (hash && !CryptoEngine::hash_from_string(val, hash)) {
        if (err) *err = "Invalid hash in metadata";
        return false;
      }
    } else if (key == "key_storage") {
      if (key_storage) *key_storage = val;
      key_storage_set = true;
    } else if (key == "file_id") {
      if (file_id) *file_id = val;
    } else if (key == "key_id") {
      if (key_id) *key_id = val;
    } else if (key == "hash_value") {
      if (hash_value) *hash_value = val;
    } else if (key == "key_file") {
      if (key_file) *key_file = val;
    } else if (key == "iv") {
      bool ok = false;
      *iv = base64_decode(val, &ok);
      if (!ok) {
        if (err) *err = "Invalid iv";
        return false;
      }
    } else if (key == "tag") {
      bool ok = false;
      *tag = base64_decode(val, &ok);
      if (!ok) {
        if (err) *err = "Invalid tag";
        return false;
      }
    }
  }
  if (!cipher_set || !key_storage_set) {
    if (err) *err = "Incomplete metadata";
    return false;
  }
  return true;
}

bool ClientCore::encrypt_file(const EncryptParams& params, EncryptResult* result) {
  bool ok = false;
  std::vector<uint8_t> plaintext = read_file(params.file_path, &ok);
  if (!ok) {
    log_client_error("encrypt_file failed to read file: " + params.file_path);
    if (result) result->message = "Failed to read file";
    return false;
  }
  bool success = encrypt_data(params, plaintext, result, true);
  secure_zero(plaintext.data(), plaintext.size());
  return success;
}

bool ClientCore::encrypt_data(const EncryptParams& params,
                              const std::vector<uint8_t>& data,
                              EncryptResult* result,
                              bool write_to_disk) {
  if (!result) return false;
  result->ok = false;

  std::string key_storage = params.key_storage.empty() ? config_.default_key_storage
                                                       : params.key_storage;

  Header header;
  header.set("op", "encrypt");
  header.set("username", params.username);
  header.set("password", params.password);
  header.set("client_id", client_id_value());
  header.set("client_host", host_label());
  header.set("cipher", CryptoEngine::cipher_to_string(params.cipher));
  header.set("hash", CryptoEngine::hash_to_string(params.hash));
  header.set("key_storage", key_storage);
  header.set("file_name", fs::path(params.file_path).filename().string());
  header.set("file_size", std::to_string(data.size()));

  Header resp;
  std::vector<uint8_t> enc_data;
  if (!send_request(header, data, &resp, &enc_data)) {
    log_client_error("encrypt request failed");
    result->message = "Request failed";
    return false;
  }

  if (resp.get("status") != "ok") {
    log_client_error("encrypt server error: " + resp.get("message", "Server error"));
    result->message = resp.get("message", "Server error");
    return false;
  }

  result->file_id = resp.get("file_id");
  result->hash_value = resp.get("hash_value");
  result->key_id = resp.get("key_id");
  std::string key_b64 = resp.get("key");
  std::string iv_b64 = resp.get("iv");
  std::string tag_b64 = resp.get("tag");

  if (!key_b64.empty()) {
    bool ok_key = false;
    result->key = base64_decode(key_b64, &ok_key);
    if (!ok_key) {
      result->message = "Invalid key";
      return false;
    }
  }
  if (!iv_b64.empty()) {
    bool ok_iv = false;
    result->iv = base64_decode(iv_b64, &ok_iv);
    if (!ok_iv) {
      result->message = "Invalid iv";
      return false;
    }
  }
  if (!tag_b64.empty()) {
    bool ok_tag = false;
    result->tag = base64_decode(tag_b64, &ok_tag);
    if (!ok_tag) {
      result->message = "Invalid tag";
      return false;
    }
  }

  if (write_to_disk) {
    std::string write_err;
    EncryptParams meta_params = params;
    meta_params.key_storage = key_storage;
    if (!write_embedded_file(params.file_path, meta_params, *result, key_storage, enc_data, &write_err)) {
      log_client_error("encrypt failed to write embedded file: " + write_err);
      result->message = write_err;
      return false;
    }

    std::error_code ec;
    fs::remove(params.file_path + ".cph", ec);
    fs::remove(params.file_path + ".key", ec);
  }

  result->ok = true;
  return true;
}

bool ClientCore::decrypt_file(const DecryptParams& params, DecryptResult* result) {
  if (!result) return false;
  result->ok = false;

  std::string key_storage;
  std::string file_id;
  std::string key_id;
  std::string hash_value;
  std::string key_file;
  Cipher cipher;
  HashAlg hash;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> tag;
  std::string err;
  std::vector<uint8_t> ciphertext;
  std::vector<uint8_t> embedded_key;

  Header embedded_header;
  EmbeddedReadResult embedded = read_embedded_file(params.file_path, &embedded_header, &ciphertext, &err);
  if (embedded == EmbeddedReadResult::kError) {
    log_client_error("decrypt_file failed to read embedded file: " + err);
    result->message = err;
    return false;
  }
  if (embedded == EmbeddedReadResult::kOk) {
    if (!extract_metadata_from_header(embedded_header, &key_storage, &file_id, &key_id,
                                      &hash_value, &cipher, &hash, &embedded_key, &iv, &tag, &err)) {
      log_client_error("decrypt_file failed to parse embedded metadata: " + err);
      result->message = err;
      return false;
    }
  } else {
    if (!read_metadata(params.file_path, &key_storage, &file_id, &key_id, &hash_value, &key_file,
                       &cipher, &hash, &iv, &tag, &err)) {
      log_client_error("decrypt_file failed to read metadata: " + err);
      result->message = err;
      return false;
    }
  }

  if (key_storage == "server" && key_id.empty()) {
    log_client_error("decrypt_file missing key_id for server storage");
    result->message = "Missing key_id";
    return false;
  }
  bool embedded_mode = (embedded == EmbeddedReadResult::kOk);

  std::vector<uint8_t> key;
  if (key_storage == "client") {
    if (!embedded_key.empty()) {
      key = std::move(embedded_key);
    } else if (embedded_mode) {
      log_client_error("decrypt_file missing embedded key");
      result->message = "Missing embedded key";
      return false;
    } else {
      if (key_file.empty()) {
        key_file = params.file_path + ".key";
      }
      if (!load_key_file(key_file, &key, &iv, &tag)) {
        log_client_error("decrypt_file failed to load key file: " + key_file);
        result->message = "Failed to load key";
        return false;
      }
    }
  } else if (key_storage != "server") {
    log_client_error("decrypt_file unknown key storage: " + key_storage);
    result->message = "Unknown key storage";
    return false;
  }

  Header header;
  header.set("op", "decrypt");
  header.set("username", params.username);
  header.set("password", params.password);
  header.set("client_id", client_id_value());
  header.set("client_host", host_label());
  header.set("cipher", CryptoEngine::cipher_to_string(cipher));
  header.set("hash", CryptoEngine::hash_to_string(hash));
  header.set("file_size", std::to_string(ciphertext.size()));
  if (!file_id.empty()) {
    header.set("file_id", file_id);
  }

  if (key_storage == "server") {
    header.set("key_id", key_id);
  } else {
    header.set("key", base64_encode(key));
    if (!iv.empty()) {
      header.set("iv", base64_encode(iv));
    }
    if (!tag.empty()) {
      header.set("tag", base64_encode(tag));
    }
  }

  Header resp;
  std::vector<uint8_t> plaintext;
  if (!send_request(header, ciphertext, &resp, &plaintext)) {
    log_client_error("decrypt request failed");
    result->message = "Request failed";
    return false;
  }

  if (resp.get("status") != "ok") {
    log_client_error("decrypt server error: " + resp.get("message", "Server error"));
    result->message = resp.get("message", "Server error");
    return false;
  }

  result->data = SecureBuffer(plaintext.size());
  if (!plaintext.empty()) {
    std::memcpy(result->data.data(), plaintext.data(), plaintext.size());
    secure_zero(plaintext.data(), plaintext.size());
  }
  result->original_name = fs::path(params.file_path).filename().string();
  result->cipher = cipher;
  result->hash = hash;
  result->key_storage = key_storage;
  result->file_id = file_id;
  result->ok = true;
  return true;
}

bool ClientCore::change_password(const std::string& username,
                                 const std::string& password,
                                 const std::string& new_password,
                                 std::string* err) {
  Header header;
  header.set("op", "change_password");
  header.set("username", username);
  header.set("password", password);
  header.set("client_id", client_id_value());
  header.set("client_host", host_label());
  header.set("new_password", new_password);

  Header resp;
  std::vector<uint8_t> out;
  if (!send_request(header, {}, &resp, &out)) {
    if (err) *err = "Request failed";
    return false;
  }

  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  return true;
}

bool ClientCore::authenticate(const std::string& username,
                              const std::string& password,
                              std::string* err) {
  Header header;
  header.set("op", "auth_check");
  header.set("username", username);
  header.set("password", password);
  header.set("client_id", client_id_value());
  header.set("client_host", host_label());

  Header resp;
  std::vector<uint8_t> out;
  if (!send_request(header, {}, &resp, &out)) {
    if (err) *err = "Request failed";
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Authentication failed");
    return false;
  }
  return true;
}

} // namespace cipheator
