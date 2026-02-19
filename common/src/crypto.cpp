#include "cipheator/crypto.h"

#include "cipheator/gost_cli.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sstream>

namespace cipheator {

namespace {

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

bool evp_encrypt(const EVP_CIPHER* cipher,
                 const std::vector<uint8_t>& plaintext,
                 const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 std::vector<uint8_t>* out,
                 std::vector<uint8_t>* tag) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  int ok = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  const uint8_t* iv_ptr = iv.empty() ? nullptr : iv.data();
  ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr);
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  std::vector<uint8_t> buffer(plaintext.size() + EVP_CIPHER_block_size(cipher));
  int out_len = 0;
  int total = 0;

  if (!plaintext.empty()) {
    ok = EVP_EncryptUpdate(ctx, buffer.data(), &out_len, plaintext.data(),
                           static_cast<int>(plaintext.size()));
    if (!ok) {
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    total += out_len;
  }

  ok = EVP_EncryptFinal_ex(ctx, buffer.data() + total, &out_len);
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  total += out_len;
  buffer.resize(static_cast<size_t>(total));

  if (tag) {
    tag->resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag->data());
  }

  *out = std::move(buffer);
  EVP_CIPHER_CTX_free(ctx);
  return true;
}

bool evp_decrypt(const EVP_CIPHER* cipher,
                 const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 const std::vector<uint8_t>& tag,
                 std::vector<uint8_t>* out) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;

  int ok = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 1);

  const uint8_t* iv_ptr = iv.empty() ? nullptr : iv.data();
  ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_ptr);
  if (!ok) {
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  if (!tag.empty()) {
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                        const_cast<uint8_t*>(tag.data()));
  }

  std::vector<uint8_t> buffer(ciphertext.size() + EVP_CIPHER_block_size(cipher));
  int out_len = 0;
  int total = 0;

  if (!ciphertext.empty()) {
    ok = EVP_DecryptUpdate(ctx, buffer.data(), &out_len, ciphertext.data(),
                           static_cast<int>(ciphertext.size()));
    if (!ok) {
      EVP_CIPHER_CTX_free(ctx);
      return false;
    }
    total += out_len;
  }

  ok = EVP_DecryptFinal_ex(ctx, buffer.data() + total, &out_len);
  if (!ok) {
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

  if (cipher == Cipher::AES_256_GCM) {
    out->key.resize(32);
    out->iv.resize(12);
    if (RAND_bytes(out->key.data(), static_cast<int>(out->key.size())) != 1 ||
        RAND_bytes(out->iv.data(), static_cast<int>(out->iv.size())) != 1) {
      if (err) *err = "RAND_bytes failed";
      return false;
    }
    if (!evp_encrypt(EVP_aes_256_gcm(), plaintext, out->key, out->iv, &out->data,
                     &out->tag)) {
      if (err) *err = "AES-GCM encrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::AES_256_CBC) {
    out->key.resize(32);
    out->iv.resize(16);
    if (RAND_bytes(out->key.data(), static_cast<int>(out->key.size())) != 1 ||
        RAND_bytes(out->iv.data(), static_cast<int>(out->iv.size())) != 1) {
      if (err) *err = "RAND_bytes failed";
      return false;
    }
    if (!evp_encrypt(EVP_aes_256_cbc(), plaintext, out->key, out->iv, &out->data,
                     nullptr)) {
      if (err) *err = "AES-CBC encrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::DES_CBC) {
    out->key.resize(8);
    out->iv.resize(8);
    if (RAND_bytes(out->key.data(), static_cast<int>(out->key.size())) != 1 ||
        RAND_bytes(out->iv.data(), static_cast<int>(out->iv.size())) != 1) {
      if (err) *err = "RAND_bytes failed";
      return false;
    }
    if (!evp_encrypt(EVP_des_cbc(), plaintext, out->key, out->iv, &out->data,
                     nullptr)) {
      if (err) *err = "DES-CBC encrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::DES_ECB) {
    out->key.resize(8);
    out->iv.clear();
    if (RAND_bytes(out->key.data(), static_cast<int>(out->key.size())) != 1) {
      if (err) *err = "RAND_bytes failed";
      return false;
    }
    if (!evp_encrypt(EVP_des_ecb(), plaintext, out->key, {}, &out->data, nullptr)) {
      if (err) *err = "DES-ECB encrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::KUZNECHIK || cipher == Cipher::MAGMA) {
    if (!gost_) {
      if (err) *err = "GOST CLI adapter not configured";
      return false;
    }
    return gost_->encrypt(cipher, plaintext, out, err);
  }

  if (err) *err = "Unsupported cipher";
  return false;
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

  if (cipher == Cipher::AES_256_GCM) {
    if (!evp_decrypt(EVP_aes_256_gcm(), ciphertext, key, iv, tag, &out->data)) {
      if (err) *err = "AES-GCM decrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::AES_256_CBC) {
    if (!evp_decrypt(EVP_aes_256_cbc(), ciphertext, key, iv, {}, &out->data)) {
      if (err) *err = "AES-CBC decrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::DES_CBC) {
    if (!evp_decrypt(EVP_des_cbc(), ciphertext, key, iv, {}, &out->data)) {
      if (err) *err = "DES-CBC decrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::DES_ECB) {
    if (!evp_decrypt(EVP_des_ecb(), ciphertext, key, {}, {}, &out->data)) {
      if (err) *err = "DES-ECB decrypt failed";
      return false;
    }
    return true;
  }

  if (cipher == Cipher::KUZNECHIK || cipher == Cipher::MAGMA) {
    if (!gost_) {
      if (err) *err = "GOST CLI adapter not configured";
      return false;
    }
    return gost_->decrypt(cipher, ciphertext, key, out, err);
  }

  if (err) *err = "Unsupported cipher";
  return false;
}

bool CryptoEngine::hash(HashAlg alg,
                        const std::vector<uint8_t>& data,
                        HashResult* out,
                        std::string* err) {
  if (!out) return false;

  const EVP_MD* md = nullptr;
  if (alg == HashAlg::SHA256) {
    md = EVP_sha256();
  } else if (alg == HashAlg::STREEBOG) {
    md = EVP_get_digestbyname("streebog256");
    if (!md) {
      md = EVP_get_digestbyname("md_gost12_256");
    }
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
  switch (cipher) {
    case Cipher::AES_256_GCM:
      return "aes-256-gcm";
    case Cipher::AES_256_CBC:
      return "aes-256-cbc";
    case Cipher::DES_CBC:
      return "des-cbc";
    case Cipher::DES_ECB:
      return "des-ecb";
    case Cipher::KUZNECHIK:
      return "kuznechik";
    case Cipher::MAGMA:
      return "magma";
  }
  return "unknown";
}

bool CryptoEngine::cipher_from_string(const std::string& value, Cipher* out) {
  if (!out) return false;
  if (value == "aes-256-gcm") {
    *out = Cipher::AES_256_GCM;
    return true;
  }
  if (value == "aes-256-cbc") {
    *out = Cipher::AES_256_CBC;
    return true;
  }
  if (value == "des-cbc") {
    *out = Cipher::DES_CBC;
    return true;
  }
  if (value == "des-ecb") {
    *out = Cipher::DES_ECB;
    return true;
  }
  if (value == "kuznechik") {
    *out = Cipher::KUZNECHIK;
    return true;
  }
  if (value == "magma") {
    *out = Cipher::MAGMA;
    return true;
  }
  return false;
}

std::string CryptoEngine::hash_to_string(HashAlg alg) {
  switch (alg) {
    case HashAlg::SHA256:
      return "sha256";
    case HashAlg::STREEBOG:
      return "streebog";
  }
  return "unknown";
}

bool CryptoEngine::hash_from_string(const std::string& value, HashAlg* out) {
  if (!out) return false;
  if (value == "sha256") {
    *out = HashAlg::SHA256;
    return true;
  }
  if (value == "streebog") {
    *out = HashAlg::STREEBOG;
    return true;
  }
  return false;
}

} // namespace cipheator
