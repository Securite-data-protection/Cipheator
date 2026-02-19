#include "cipheator/auth.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <sstream>
#include <vector>

namespace cipheator {

namespace {

std::string bytes_to_hex(const unsigned char* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kHex[(data[i] >> 4) & 0xF]);
    out.push_back(kHex[data[i] & 0xF]);
  }
  return out;
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
  std::vector<unsigned char> out;
  if (hex.size() % 2 != 0) return out;
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned char hi = static_cast<unsigned char>(std::stoi(hex.substr(i, 1), nullptr, 16));
    unsigned char lo = static_cast<unsigned char>(std::stoi(hex.substr(i + 1, 1), nullptr, 16));
    out.push_back((hi << 4) | lo);
  }
  return out;
}

} // namespace

bool UserStore::load(const std::string& path) {
  users_.clear();
  std::ifstream file(path);
  if (!file) return false;
  std::string line;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#') continue;
    std::istringstream ss(line);
    std::string username, salt, hash;
    if (!std::getline(ss, username, ':')) continue;
    if (!std::getline(ss, salt, ':')) continue;
    if (!std::getline(ss, hash, ':')) continue;
    UserRecord rec{username, salt, hash};
    users_[username] = rec;
  }
  return true;
}

bool UserStore::save(const std::string& path) const {
  std::ofstream file(path, std::ios::trunc);
  if (!file) return false;
  for (const auto& kv : users_) {
    file << kv.second.username << ':' << kv.second.salt_hex << ':' << kv.second.hash_hex
         << '\n';
  }
  return true;
}

bool UserStore::verify(const std::string& username, const std::string& password) const {
  auto it = users_.find(username);
  if (it == users_.end()) return false;
  std::string computed = pbkdf2_hash(password, it->second.salt_hex, 120000);
  return computed == it->second.hash_hex;
}

bool UserStore::upsert(const std::string& username, const std::string& password) {
  UserRecord rec;
  rec.username = username;
  rec.salt_hex = random_salt_hex(16);
  rec.hash_hex = pbkdf2_hash(password, rec.salt_hex, 120000);
  users_[username] = rec;
  return true;
}

std::string UserStore::pbkdf2_hash(const std::string& password,
                                  const std::string& salt_hex,
                                  int iterations) {
  std::vector<unsigned char> salt = hex_to_bytes(salt_hex);
  unsigned char out[32];
  if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                        salt.data(), static_cast<int>(salt.size()),
                        iterations, EVP_sha256(), sizeof(out), out) != 1) {
    return {};
  }
  return bytes_to_hex(out, sizeof(out));
}

std::string UserStore::random_salt_hex(size_t bytes) {
  std::vector<unsigned char> salt(bytes);
  RAND_bytes(salt.data(), static_cast<int>(salt.size()));
  return bytes_to_hex(salt.data(), salt.size());
}

} // namespace cipheator
