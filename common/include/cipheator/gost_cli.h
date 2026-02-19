#pragma once

#include <string>
#include <vector>

#include "cipheator/crypto.h"

namespace cipheator {

struct GostCliConfig {
  std::string enc_magma;
  std::string dec_magma;
  std::string enc_kuznechik;
  std::string dec_kuznechik;
  std::string enc_suffix = ".enc";
  std::string key_suffix = ".key";
};

class GostCli {
 public:
  explicit GostCli(GostCliConfig config);

  bool encrypt(Cipher cipher,
               const std::vector<uint8_t>& plaintext,
               CryptoResult* out,
               std::string* err);

  bool decrypt(Cipher cipher,
               const std::vector<uint8_t>& ciphertext,
               const std::vector<uint8_t>& key,
               CryptoResult* out,
               std::string* err);

 private:
  GostCliConfig config_;

  bool run_command(const std::string& cmd, std::string* err);
};

} // namespace cipheator
