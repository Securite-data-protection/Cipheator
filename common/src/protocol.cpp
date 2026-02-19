#include "cipheator/protocol.h"

#include <sstream>

namespace cipheator {

std::string Header::get(const std::string& key, const std::string& def) const {
  auto it = fields.find(key);
  if (it == fields.end()) return def;
  return it->second;
}

void Header::set(const std::string& key, const std::string& value) {
  fields[key] = value;
}

std::string Header::serialize() const {
  std::ostringstream ss;
  for (const auto& kv : fields) {
    ss << kv.first << ": " << kv.second << "\n";
  }
  ss << "\n";
  return ss.str();
}

static std::string trim(const std::string& s) {
  size_t start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  size_t end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

bool Header::parse(const std::string& raw, Header* out) {
  if (!out) return false;
  out->fields.clear();
  std::istringstream ss(raw);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.empty() || line == "\r") break;
    auto pos = line.find(':');
    if (pos == std::string::npos) continue;
    std::string key = trim(line.substr(0, pos));
    std::string val = trim(line.substr(pos + 1));
    if (!key.empty()) {
      out->fields[key] = val;
    }
  }
  return true;
}

bool read_header(const ReadFn& read_fn, size_t max_bytes, Header* out) {
  if (!out) return false;
  std::string buffer;
  buffer.reserve(1024);
  uint8_t byte = 0;
  size_t total = 0;
  bool last_was_newline = false;

  while (total < max_bytes) {
    int n = read_fn(&byte, 1);
    if (n <= 0) return false;
    total += static_cast<size_t>(n);
    buffer.push_back(static_cast<char>(byte));

    if (byte == '\n') {
      if (last_was_newline) {
        break;
      }
      last_was_newline = true;
    } else if (byte == '\r') {
      continue;
    } else {
      last_was_newline = false;
    }
  }

  if (total >= max_bytes) {
    return false;
  }
  return Header::parse(buffer, out);
}

bool write_header(const WriteFn& write_fn, const Header& header) {
  std::string raw = header.serialize();
  size_t total = 0;
  const uint8_t* data = reinterpret_cast<const uint8_t*>(raw.data());
  while (total < raw.size()) {
    int n = write_fn(data + total, raw.size() - total);
    if (n <= 0) return false;
    total += static_cast<size_t>(n);
  }
  return true;
}

} // namespace cipheator
