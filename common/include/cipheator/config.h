#pragma once

#include <string>
#include <unordered_map>

namespace cipheator {

class Config {
 public:
  bool load(const std::string& path);
  std::string get(const std::string& key, const std::string& def = "") const;
  int get_int(const std::string& key, int def = 0) const;
  bool get_bool(const std::string& key, bool def = false) const;

 private:
  std::unordered_map<std::string, std::string> values_;
};

} // namespace cipheator
