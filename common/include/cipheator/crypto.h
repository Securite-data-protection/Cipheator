#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipheator {

class GostCli;

enum class Cipher {
  KUZNECHIK,
  MAGMA,
  CHACHA20,
  CHACHA20_POLY1305,
  AES_128_ECB,
  AES_128_CBC,
  AES_128_CFB,
  AES_128_OFB,
  AES_128_CTR,
  AES_128_GCM,
  AES_128_CCM,
  AES_128_XTS,
  AES_128_OCB,
  AES_192_ECB,
  AES_192_CBC,
  AES_192_CFB,
  AES_192_OFB,
  AES_192_CTR,
  AES_192_GCM,
  AES_192_CCM,
  AES_192_OCB,
  AES_256_ECB,
  AES_256_CBC,
  AES_256_CFB,
  AES_256_OFB,
  AES_256_CTR,
  AES_256_GCM,
  AES_256_CCM,
  AES_256_XTS,
  AES_256_OCB,
  TWOFISH_128_ECB,
  TWOFISH_128_CBC,
  TWOFISH_128_CFB,
  TWOFISH_128_OFB,
  TWOFISH_128_CTR,
  TWOFISH_192_ECB,
  TWOFISH_192_CBC,
  TWOFISH_192_CFB,
  TWOFISH_192_OFB,
  TWOFISH_192_CTR,
  TWOFISH_256_ECB,
  TWOFISH_256_CBC,
  TWOFISH_256_CFB,
  TWOFISH_256_OFB,
  TWOFISH_256_CTR,
  DES_ECB,
  DES_CBC,
  DES_CFB,
  DES_OFB,
  DES_CTR,
  RC4,
  RC4_40,
  RC4_128
};

enum class HashAlg {
  SHA256,
  SHA512,
  SHA3_256,
  SHA3_512,
  BLAKE2B_512,
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
