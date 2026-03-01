#include "cipheator/crypto.h"

#include "cipheator/gost_cli.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>

namespace cipheator {

namespace {

struct CipherSpec {
  Cipher cipher;
  const char* wire_name;
  const char* openssl_name;
  bool gost;
  bool aead;
  bool ccm;
};

constexpr CipherSpec kCipherSpecs[] = {
    {Cipher::KUZNECHIK, "kuznechik", nullptr, true, false, false},
    {Cipher::MAGMA, "magma", nullptr, true, false, false},
    {Cipher::CHACHA20, "chacha20", "chacha20", false, false, false},
    {Cipher::CHACHA20_POLY1305, "chacha20-poly1305", "chacha20-poly1305", false, true, false},

    {Cipher::AES_128_ECB, "aes-128-ecb", "aes-128-ecb", false, false, false},
    {Cipher::AES_128_CBC, "aes-128-cbc", "aes-128-cbc", false, false, false},
    {Cipher::AES_128_CFB, "aes-128-cfb", "aes-128-cfb", false, false, false},
    {Cipher::AES_128_OFB, "aes-128-ofb", "aes-128-ofb", false, false, false},
    {Cipher::AES_128_CTR, "aes-128-ctr", "aes-128-ctr", false, false, false},
    {Cipher::AES_128_GCM, "aes-128-gcm", "aes-128-gcm", false, true, false},
    {Cipher::AES_128_CCM, "aes-128-ccm", "aes-128-ccm", false, true, true},
    {Cipher::AES_128_XTS, "aes-128-xts", "aes-128-xts", false, false, false},
    {Cipher::AES_128_OCB, "aes-128-ocb", "aes-128-ocb", false, true, false},

    {Cipher::AES_192_ECB, "aes-192-ecb", "aes-192-ecb", false, false, false},
    {Cipher::AES_192_CBC, "aes-192-cbc", "aes-192-cbc", false, false, false},
    {Cipher::AES_192_CFB, "aes-192-cfb", "aes-192-cfb", false, false, false},
    {Cipher::AES_192_OFB, "aes-192-ofb", "aes-192-ofb", false, false, false},
    {Cipher::AES_192_CTR, "aes-192-ctr", "aes-192-ctr", false, false, false},
    {Cipher::AES_192_GCM, "aes-192-gcm", "aes-192-gcm", false, true, false},
    {Cipher::AES_192_CCM, "aes-192-ccm", "aes-192-ccm", false, true, true},
    {Cipher::AES_192_OCB, "aes-192-ocb", "aes-192-ocb", false, true, false},

    {Cipher::AES_256_ECB, "aes-256-ecb", "aes-256-ecb", false, false, false},
    {Cipher::AES_256_CBC, "aes-256-cbc", "aes-256-cbc", false, false, false},
    {Cipher::AES_256_CFB, "aes-256-cfb", "aes-256-cfb", false, false, false},
    {Cipher::AES_256_OFB, "aes-256-ofb", "aes-256-ofb", false, false, false},
    {Cipher::AES_256_CTR, "aes-256-ctr", "aes-256-ctr", false, false, false},
    {Cipher::AES_256_GCM, "aes-256-gcm", "aes-256-gcm", false, true, false},
    {Cipher::AES_256_CCM, "aes-256-ccm", "aes-256-ccm", false, true, true},
    {Cipher::AES_256_XTS, "aes-256-xts", "aes-256-xts", false, false, false},
    {Cipher::AES_256_OCB, "aes-256-ocb", "aes-256-ocb", false, true, false},

    {Cipher::TWOFISH_128_ECB, "twofish-128-ecb", "twofish-128-ecb", false, false, false},
    {Cipher::TWOFISH_128_CBC, "twofish-128-cbc", "twofish-128-cbc", false, false, false},
    {Cipher::TWOFISH_128_CFB, "twofish-128-cfb", "twofish-128-cfb", false, false, false},
    {Cipher::TWOFISH_128_OFB, "twofish-128-ofb", "twofish-128-ofb", false, false, false},
    {Cipher::TWOFISH_128_CTR, "twofish-128-ctr", "twofish-128-ctr", false, false, false},

    {Cipher::TWOFISH_192_ECB, "twofish-192-ecb", "twofish-192-ecb", false, false, false},
    {Cipher::TWOFISH_192_CBC, "twofish-192-cbc", "twofish-192-cbc", false, false, false},
    {Cipher::TWOFISH_192_CFB, "twofish-192-cfb", "twofish-192-cfb", false, false, false},
    {Cipher::TWOFISH_192_OFB, "twofish-192-ofb", "twofish-192-ofb", false, false, false},
    {Cipher::TWOFISH_192_CTR, "twofish-192-ctr", "twofish-192-ctr", false, false, false},

    {Cipher::TWOFISH_256_ECB, "twofish-256-ecb", "twofish-256-ecb", false, false, false},
    {Cipher::TWOFISH_256_CBC, "twofish-256-cbc", "twofish-256-cbc", false, false, false},
    {Cipher::TWOFISH_256_CFB, "twofish-256-cfb", "twofish-256-cfb", false, false, false},
    {Cipher::TWOFISH_256_OFB, "twofish-256-ofb", "twofish-256-ofb", false, false, false},
    {Cipher::TWOFISH_256_CTR, "twofish-256-ctr", "twofish-256-ctr", false, false, false},

    {Cipher::DES_ECB, "des-ecb", "des-ecb", false, false, false},
    {Cipher::DES_CBC, "des-cbc", "des-cbc", false, false, false},
    {Cipher::DES_CFB, "des-cfb", "des-cfb", false, false, false},
    {Cipher::DES_OFB, "des-ofb", "des-ofb", false, false, false},
    {Cipher::DES_CTR, "des-ctr", "des-ctr", false, false, false},

    {Cipher::RC4, "rc4", "rc4", false, false, false},
    {Cipher::RC4_40, "rc4-40", "rc4-40", false, false, false},
    {Cipher::RC4_128, "rc4-128", "rc4", false, false, false},
};

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(data.size() * 2);
  for (uint8_t b : data) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

std::string collect_openssl_errors() {
  std::string out;
  unsigned long code = 0;
  while ((code = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    if (!out.empty()) out += " | ";
    out += buf;
  }
  return out;
}

std::string normalize_cipher_name(std::string value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
    value.erase(value.begin());
  }
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
    value.pop_back();
  }
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    if (c == '_') return '-';
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

const CipherSpec* find_cipher_spec(Cipher cipher) {
  for (const auto& spec : kCipherSpecs) {
    if (spec.cipher == cipher) return &spec;
  }
  return nullptr;
}

const CipherSpec* find_cipher_spec(const std::string& value) {
  const std::string normalized = normalize_cipher_name(value);
  for (const auto& spec : kCipherSpecs) {
    if (normalized == spec.wire_name) return &spec;
  }
  return nullptr;
}

bool evp_encrypt_cipher(const EVP_CIPHER* cipher,
                        const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        bool aead,
                        bool ccm,
                        std::vector<uint8_t>* out,
                        std::vector<uint8_t>* tag,
                        std::string* err) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    if (err) *err = "EVP_CIPHER_CTX_new failed";
    return false;
  }

  int ok = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  if (ok != 1) {
    if (err) *err = "EVP_EncryptInit_ex failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (!aead) {
    const int mode = EVP_CIPHER_mode(cipher);
    const bool use_padding = (mode == EVP_CIPH_CBC_MODE || mode == EVP_CIPH_ECB_MODE);
    EVP_CIPHER_CTX_set_padding(ctx, use_padding ? 1 : 0);
  }

  if (ccm) {
    constexpr int kTagLen = 16;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_SET_IVLEN failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, kTagLen, nullptr) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_SET_TAG failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  const uint8_t* iv_ptr = iv.empty() ? nullptr : iv.data();
  ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr);
  if (ok != 1) {
    if (err) *err = "EVP_EncryptInit_ex(key/iv) failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  std::vector<uint8_t> buffer(plaintext.size() + static_cast<size_t>(EVP_CIPHER_block_size(cipher)) + 16);
  int out_len = 0;
  int total = 0;

  if (ccm) {
    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, nullptr, static_cast<int>(plaintext.size())) != 1) {
      if (err) *err = "EVP_EncryptUpdate(length) failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if (!plaintext.empty()) {
      if (EVP_EncryptUpdate(ctx, buffer.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        if (err) *err = "EVP_EncryptUpdate(data) failed: " + collect_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      total = out_len;
    }
  } else {
    if (!plaintext.empty()) {
      if (EVP_EncryptUpdate(ctx, buffer.data(), &out_len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        if (err) *err = "EVP_EncryptUpdate failed: " + collect_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      total += out_len;
    }
  }

  if (EVP_EncryptFinal_ex(ctx, buffer.data() + total, &out_len) != 1) {
    if (err) *err = "EVP_EncryptFinal_ex failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  buffer.resize(static_cast<size_t>(total));

  if (aead && tag) {
    tag->resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(tag->size()), tag->data()) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_GET_TAG failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  } else if (tag) {
    tag->clear();
  }

  *out = std::move(buffer);
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool evp_decrypt_cipher(const EVP_CIPHER* cipher,
                        const std::vector<uint8_t>& ciphertext,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& iv,
                        const std::vector<uint8_t>& tag,
                        bool aead,
                        bool ccm,
                        std::vector<uint8_t>* out,
                        std::string* err) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    if (err) *err = "EVP_CIPHER_CTX_new failed";
    return false;
  }

  int ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  if (ok != 1) {
    if (err) *err = "EVP_DecryptInit_ex failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (!aead) {
    const int mode = EVP_CIPHER_mode(cipher);
    const bool use_padding = (mode == EVP_CIPH_CBC_MODE || mode == EVP_CIPH_ECB_MODE);
    EVP_CIPHER_CTX_set_padding(ctx, use_padding ? 1 : 0);
  }

  if (ccm) {
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_SET_IVLEN failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_SET_TAG failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  const uint8_t* iv_ptr = iv.empty() ? nullptr : iv.data();
  ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr);
  if (ok != 1) {
    if (err) *err = "EVP_DecryptInit_ex(key/iv) failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (aead && !ccm) {
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
      if (err) *err = "EVP_CTRL_AEAD_SET_TAG failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
  }

  std::vector<uint8_t> buffer(ciphertext.size() + static_cast<size_t>(EVP_CIPHER_block_size(cipher)) + 16);
  int out_len = 0;
  int total = 0;

  if (ccm) {
    if (EVP_DecryptUpdate(ctx, nullptr, &out_len, nullptr, static_cast<int>(ciphertext.size())) != 1) {
      if (err) *err = "EVP_DecryptUpdate(length) failed: " + collect_openssl_errors();
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    if (!ciphertext.empty()) {
      if (EVP_DecryptUpdate(ctx, buffer.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        if (err) *err = "EVP_DecryptUpdate(data) failed: " + collect_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      total = out_len;
    }
  } else {
    if (!ciphertext.empty()) {
      if (EVP_DecryptUpdate(ctx, buffer.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        if (err) *err = "EVP_DecryptUpdate failed: " + collect_openssl_errors();
        EVP_CIPHER_CTX_free(ctx);
        return false;
      }
      total += out_len;
    }
  }

  if (EVP_DecryptFinal_ex(ctx, buffer.data() + total, &out_len) != 1) {
    if (err) *err = "EVP_DecryptFinal_ex failed: " + collect_openssl_errors();
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  buffer.resize(static_cast<size_t>(total));

  *out = std::move(buffer);
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

} // namespace

CryptoEngine::CryptoEngine(GostCli* gost) : gost_(gost) {}

bool CryptoEngine::encrypt(Cipher cipher,
                           const std::vector<uint8_t>& plaintext,
                           CryptoResult* out,
                           std::string* err) {
  if (!out) return false;
  out->data.clear();
  out->key.clear();
  out->iv.clear();
  out->tag.clear();

  const CipherSpec* spec = find_cipher_spec(cipher);
  if (!spec) {
    if (err) *err = "Unsupported cipher";
    return false;
  }

  if (spec->gost) {
    if (!gost_) {
      if (err) *err = "GOST CLI adapter not configured";
      return false;
    }
    return gost_->encrypt(cipher, plaintext, out, err);
  }

  const EVP_CIPHER* evp = EVP_get_cipherbyname(spec->openssl_name);
  if (!evp) {
    if (err) *err = "Cipher is not available in OpenSSL: " + std::string(spec->wire_name);
    return false;
  }

  const int key_len = EVP_CIPHER_key_length(evp);
  int iv_len = EVP_CIPHER_iv_length(evp);
  if (key_len <= 0) {
    if (err) *err = "Invalid key length for cipher";
    return false;
  }
  if (iv_len < 0) iv_len = 0;

  out->key.resize(static_cast<size_t>(key_len));
  if (iv_len > 0) out->iv.resize(static_cast<size_t>(iv_len));

  if (RAND_bytes(out->key.data(), static_cast<int>(out->key.size())) != 1) {
    if (err) *err = "RAND_bytes failed (key)";
    return false;
  }
  if (!out->iv.empty() && RAND_bytes(out->iv.data(), static_cast<int>(out->iv.size())) != 1) {
    if (err) *err = "RAND_bytes failed (iv)";
    return false;
  }

  if (!evp_encrypt_cipher(evp, plaintext, out->key, out->iv, spec->aead, spec->ccm,
                          &out->data, spec->aead ? &out->tag : nullptr, err)) {
    return false;
  }

  return true;
}

bool CryptoEngine::decrypt(Cipher cipher,
                           const std::vector<uint8_t>& ciphertext,
                           const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& iv,
                           const std::vector<uint8_t>& tag,
                           CryptoResult* out,
                           std::string* err) {
  if (!out) return false;
  out->data.clear();
  out->key.clear();
  out->iv.clear();
  out->tag.clear();

  const CipherSpec* spec = find_cipher_spec(cipher);
  if (!spec) {
    if (err) *err = "Unsupported cipher";
    return false;
  }

  if (spec->gost) {
    if (!gost_) {
      if (err) *err = "GOST CLI adapter not configured";
      return false;
    }
    return gost_->decrypt(cipher, ciphertext, key, out, err);
  }

  if (spec->aead && tag.empty()) {
    if (err) *err = "Missing authentication tag for AEAD cipher";
    return false;
  }

  const EVP_CIPHER* evp = EVP_get_cipherbyname(spec->openssl_name);
  if (!evp) {
    if (err) *err = "Cipher is not available in OpenSSL: " + std::string(spec->wire_name);
    return false;
  }

  if (!evp_decrypt_cipher(evp, ciphertext, key, iv, tag, spec->aead, spec->ccm, &out->data, err)) {
    return false;
  }

  return true;
}

bool CryptoEngine::hash(HashAlg alg,
                        const std::vector<uint8_t>& data,
                        HashResult* out,
                        std::string* err) {
  if (!out) return false;

  const EVP_MD* md = nullptr;
  if (alg == HashAlg::SHA256) {
    md = EVP_sha256();
  } else if (alg == HashAlg::SHA512) {
    md = EVP_sha512();
  } else if (alg == HashAlg::SHA3_256) {
    md = EVP_get_digestbyname("sha3-256");
    if (!md) md = EVP_get_digestbyname("SHA3-256");
  } else if (alg == HashAlg::SHA3_512) {
    md = EVP_get_digestbyname("sha3-512");
    if (!md) md = EVP_get_digestbyname("SHA3-512");
  } else if (alg == HashAlg::BLAKE2B_512) {
    md = EVP_get_digestbyname("blake2b512");
    if (!md) md = EVP_get_digestbyname("BLAKE2b512");
  } else if (alg == HashAlg::STREEBOG) {
    md = EVP_get_digestbyname("streebog256");
    if (!md) md = EVP_get_digestbyname("md_gost12_256");
  }

  if (!md) {
    if (err) *err = "Digest algorithm not available";
    return false;
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    if (err) *err = "EVP_MD_CTX_new failed";
    return false;
  }
  if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
    EVP_MD_CTX_free(ctx);
    if (err) *err = "EVP_DigestInit_ex failed";
    return false;
  }
  if (!data.empty()) {
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
      EVP_MD_CTX_free(ctx);
      if (err) *err = "EVP_DigestUpdate failed";
      return false;
    }
  }
  unsigned int len = 0;
  out->bytes.resize(EVP_MD_size(md));
  if (EVP_DigestFinal_ex(ctx, out->bytes.data(), &len) != 1) {
    EVP_MD_CTX_free(ctx);
    if (err) *err = "EVP_DigestFinal_ex failed";
    return false;
  }
  out->bytes.resize(len);
  out->hex = bytes_to_hex(out->bytes);
  EVP_MD_CTX_free(ctx);
  return true;
}

std::string CryptoEngine::cipher_to_string(Cipher cipher) {
  const CipherSpec* spec = find_cipher_spec(cipher);
  if (!spec) return "unknown";
  return spec->wire_name;
}

bool CryptoEngine::cipher_from_string(const std::string& value, Cipher* out) {
  if (!out) return false;
  const CipherSpec* spec = find_cipher_spec(value);
  if (!spec) return false;
  *out = spec->cipher;
  return true;
}

std::string CryptoEngine::hash_to_string(HashAlg alg) {
  switch (alg) {
    case HashAlg::SHA256:
      return "sha256";
    case HashAlg::SHA512:
      return "sha512";
    case HashAlg::SHA3_256:
      return "sha3-256";
    case HashAlg::SHA3_512:
      return "sha3-512";
    case HashAlg::BLAKE2B_512:
      return "blake2b-512";
    case HashAlg::STREEBOG:
      return "streebog";
  }
  return "unknown";
}

bool CryptoEngine::hash_from_string(const std::string& value, HashAlg* out) {
  if (!out) return false;
  const std::string v = normalize_cipher_name(value);
  if (v == "sha256") {
    *out = HashAlg::SHA256;
    return true;
  }
  if (v == "sha512") {
    *out = HashAlg::SHA512;
    return true;
  }
  if (v == "sha3-256") {
    *out = HashAlg::SHA3_256;
    return true;
  }
  if (v == "sha3-512") {
    *out = HashAlg::SHA3_512;
    return true;
  }
  if (v == "blake2b-512" || v == "blake2b512") {
    *out = HashAlg::BLAKE2B_512;
    return true;
  }
  if (v == "streebog") {
    *out = HashAlg::STREEBOG;
    return true;
  }
  return false;
}

} // namespace cipheator
