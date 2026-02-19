#pragma once

#include <string>
#include <unordered_map>

namespace cipheator {

struct UserRecord {
  std::string username;
  std::string salt_hex;
  std::string hash_hex;
};

class UserStore {
 public:
  bool load(const std::string& path);
  bool save(const std::string& path) const;

  bool verify(const std::string& username, const std::string& password) const;
  bool upsert(const std::string& username, const std::string& password);

 private:
  static std::string pbkdf2_hash(const std::string& password,
                                const std::string& salt_hex,
                                int iterations);
  static std::string random_salt_hex(size_t bytes);

  std::unordered_map<std::string, UserRecord> users_;
};

} // namespace cipheator
