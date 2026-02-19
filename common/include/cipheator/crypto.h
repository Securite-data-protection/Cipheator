#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipheator {

class GostCli;

enum class Cipher {
  AES_256_GCM,
  AES_256_CBC,
  DES_CBC,
  DES_ECB,
  KUZNECHIK,
  MAGMA
};

enum class HashAlg {
  SHA256,
  STREEBOG
};

struct CryptoResult {
  std::vector<uint8_t> data;
  std::vector<uint8_t> key;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> tag;
};

struct HashResult {
  std::vector<uint8_t> bytes;
  std::string hex;
};

class CryptoEngine {
 public:
  explicit CryptoEngine(GostCli* gost = nullptr);

  bool encrypt(Cipher cipher,
               const std::vector<uint8_t>& plaintext,
               CryptoResult* out,
               std::string* err);

  bool decrypt(Cipher cipher,
               const std::vector<uint8_t>& ciphertext,
               const std::vector<uint8_t>& key,
               const std::vector<uint8_t>& iv,
               const std::vector<uint8_t>& tag,
               CryptoResult* out,
               std::string* err);

  bool hash(HashAlg alg,
            const std::vector<uint8_t>& data,
            HashResult* out,
            std::string* err);

  static std::string cipher_to_string(Cipher cipher);
  static bool cipher_from_string(const std::string& value, Cipher* out);
  static std::string hash_to_string(HashAlg alg);
  static bool hash_from_string(const std::string& value, HashAlg* out);

 private:
  GostCli* gost_ = nullptr;
};

} // namespace cipheator
