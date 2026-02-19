#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cipheator {

std::string base64_encode(const std::vector<uint8_t>& data);
std::vector<uint8_t> base64_decode(const std::string& text, bool* ok = nullptr);

} // namespace cipheator
