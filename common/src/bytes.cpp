#include "cipheator/bytes.h"

#include <cstring>
#include <fstream>

namespace cipheator {

void secure_zero(void* data, size_t len) {
  if (!data || len == 0) return;
  volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
  while (len--) {
    *p++ = 0;
  }
}

std::vector<uint8_t> read_file(const std::string& path, bool* ok) {
  std::ifstream file(path, std::ios::binary | std::ios::ate);
  if (!file) {
    if (ok) *ok = false;
    return {};
  }
  auto size = file.tellg();
  if (size < 0) {
    if (ok) *ok = false;
    return {};
  }
  std::vector<uint8_t> data(static_cast<size_t>(size));
  file.seekg(0, std::ios::beg);
  if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
    if (ok) *ok = false;
    return {};
  }
  if (ok) *ok = true;
  return data;
}

bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) return false;
  if (!data.empty()) {
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file) return false;
  }
  return true;
}

uint32_t read_be32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         (static_cast<uint32_t>(data[3]));
}

void write_be32(uint32_t value, uint8_t* out) {
  out[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(value & 0xFF);
}

} // namespace cipheator
