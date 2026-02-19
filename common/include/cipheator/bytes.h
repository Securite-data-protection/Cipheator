#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipheator {

void secure_zero(void* data, size_t len);

std::vector<uint8_t> read_file(const std::string& path, bool* ok = nullptr);
bool write_file(const std::string& path, const std::vector<uint8_t>& data);

uint32_t read_be32(const uint8_t* data);
void write_be32(uint32_t value, uint8_t* out);

} // namespace cipheator
