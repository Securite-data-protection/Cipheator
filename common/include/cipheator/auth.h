#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace cipheator {

struct UserRecord {
  std::string username;
  std::string salt_hex;
  std::string hash_hex;
  int64_t last_change_ts = 0;
};

class UserStore {
 public:
  bool load(const std::string& path);
  bool save(const std::string& path) const;

  bool verify(const std::string& username, const std::string& password) const;
  bool upsert(const std::string& username, const std::string& password);
  bool is_password_expired(const std::string& username, int64_t max_age_days) const;

 private:
  static std::string pbkdf2_hash(const std::string& password,
                                const std::string& salt_hex,
                                int iterations);
  static std::string random_salt_hex(size_t bytes);
  static int64_t now_epoch_sec();

  std::unordered_map<std::string, UserRecord> users_;
};

} // namespace cipheator
