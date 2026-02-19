#include "cipheator/base64.h"

namespace cipheator {

static const char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::vector<uint8_t>& data) {
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);

  size_t i = 0;
  while (i + 2 < data.size()) {
    uint32_t triple = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
    out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
    out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
    out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
    out.push_back(kBase64Alphabet[triple & 0x3F]);
    i += 3;
  }

  if (i < data.size()) {
    uint32_t triple = data[i] << 16;
    if (i + 1 < data.size()) {
      triple |= data[i + 1] << 8;
    }
    out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
    out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
    if (i + 1 < data.size()) {
      out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
      out.push_back('=');
    } else {
      out.push_back('=');
      out.push_back('=');
    }
  }

  return out;
}

static int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

std::vector<uint8_t> base64_decode(const std::string& text, bool* ok) {
  std::vector<uint8_t> out;
  int val = 0;
  int valb = -8;

  bool success = true;
  for (char c : text) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
      continue;
    }
    int v = base64_value(c);
    if (v < 0) {
      success = false;
      continue;
    }
    val = (val << 6) + v;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  if (ok) {
    *ok = success;
  }
  return out;
}

} // namespace cipheator
