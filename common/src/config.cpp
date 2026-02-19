#include "cipheator/config.h"

#include <fstream>
#include <sstream>

namespace cipheator {

static std::string trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

bool Config::load(const std::string& path) {
  values_.clear();
  std::ifstream file(path);
  if (!file) return false;
  std::string line;
  while (std::getline(file, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#') continue;
    auto pos = line.find('=');
    if (pos == std::string::npos) continue;
    std::string key = trim(line.substr(0, pos));
    std::string val = trim(line.substr(pos + 1));
    values_[key] = val;
  }
  return true;
}

std::string Config::get(const std::string& key, const std::string& def) const {
  auto it = values_.find(key);
  if (it == values_.end()) return def;
  return it->second;
}

int Config::get_int(const std::string& key, int def) const {
  auto it = values_.find(key);
  if (it == values_.end()) return def;
  try {
    return std::stoi(it->second);
  } catch (...) {
    return def;
  }
}

bool Config::get_bool(const std::string& key, bool def) const {
  auto it = values_.find(key);
  if (it == values_.end()) return def;
  std::string v = it->second;
  for (auto& c : v) c = static_cast<char>(tolower(c));
  if (v == "1" || v == "true" || v == "yes") return true;
  if (v == "0" || v == "false" || v == "no") return false;
  return def;
}

} // namespace cipheator
