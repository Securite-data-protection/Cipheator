#pragma once

#include "cipheator/crypto.h"
#include "cipheator/secure_memory.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cipheator {

struct Header;

struct ClientConfig {
  std::string host;
  int port = 7443;
  std::string ca_file;
  std::string client_cert;
  std::string client_key;
  bool verify_peer = true;
  std::string default_key_storage = "server";
  size_t clipboard_max_bytes = 0;
  bool decrypt_to_temp = false;
  bool demo_mode = false;
};

struct EncryptParams {
  std::string username;
  std::string password;
  std::string file_path;
  Cipher cipher;
  HashAlg hash;
  std::string key_storage; // server or client
};

struct EncryptResult {
  bool ok = false;
  std::string message;
  std::string error_code;
  std::string file_id;
  std::string key_id;
  std::string hash_value;
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> tag;
};

struct DecryptParams {
  std::string username;
  std::string password;
  std::string file_path;
};

struct DecryptResult {
  bool ok = false;
  std::string message;
  std::string error_code;
  SecureBuffer data;
  std::string original_name;
  Cipher cipher = Cipher::AES_256_GCM;
  HashAlg hash = HashAlg::SHA256;
  std::string key_storage;
  std::string file_id;
};

struct EnrollResult {
  bool ok = false;
  std::string message;
  std::string ca_pem;
  std::string cert_pem;
};

class ClientCore {
 public:
  explicit ClientCore(ClientConfig config);

  bool encrypt_file(const EncryptParams& params, EncryptResult* result);
  bool encrypt_data(const EncryptParams& params,
                    const std::vector<uint8_t>& data,
                    EncryptResult* result,
                    bool write_to_disk);
  bool decrypt_file(const DecryptParams& params, DecryptResult* result);
  bool authenticate(const std::string& username,
                    const std::string& password,
                    std::string* err,
                    std::string* code = nullptr,
                    uint64_t* policy_version = nullptr);
  bool enroll_certificate(const std::string& role,
                          const std::string& enroll_token,
                          const std::string& csr_pem,
                          EnrollResult* result);
  bool change_password(const std::string& username,
                       const std::string& password,
                       const std::string& new_password,
                       std::string* err);

 private:
  ClientConfig config_;

  bool send_request(const Header& header,
                    const std::vector<uint8_t>& payload,
                    Header* response,
                    std::vector<uint8_t>* out);

  bool write_metadata(const std::string& file_path,
                      const EncryptParams& params,
                      const EncryptResult& result);

  bool read_metadata(const std::string& file_path,
                     std::string* key_storage,
                     std::string* file_id,
                     std::string* key_id,
                     std::string* hash_value,
                     std::string* key_file,
                     Cipher* cipher,
                     HashAlg* hash,
                     std::vector<uint8_t>* iv,
                     std::vector<uint8_t>* tag,
                     std::string* err);

  bool store_key_file(const std::string& path,
                      const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& tag);

  bool load_key_file(const std::string& path,
                     std::vector<uint8_t>* key,
                     std::vector<uint8_t>* iv,
                     std::vector<uint8_t>* tag);
};

} // namespace cipheator
