#pragma once

#include <functional>
#include <string>
#include <unordered_map>

namespace cipheator {

struct Header {
  std::unordered_map<std::string, std::string> fields;

  std::string get(const std::string& key, const std::string& def = "") const;
  void set(const std::string& key, const std::string& value);
  std::string serialize() const;
  static bool parse(const std::string& raw, Header* out);
};

using ReadFn = std::function<int(uint8_t* buf, size_t len)>;
using WriteFn = std::function<int(const uint8_t* buf, size_t len)>;

bool read_header(const ReadFn& read_fn, size_t max_bytes, Header* out);
bool write_header(const WriteFn& write_fn, const Header& header);

} // namespace cipheator
