#include "cipheator/pki.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace cipheator {

namespace {

std::string collect_ssl_errors(const char* prefix) {
  std::ostringstream ss;
  ss << prefix;
  unsigned long code = 0;
  bool first = true;
  while ((code = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    ss << (first ? ": " : " | ") << buf;
    first = false;
  }
  return ss.str();
}

template <typename T, void (*F)(T*)>
struct Scoped {
  T* ptr = nullptr;
  ~Scoped() {
    if (ptr) F(ptr);
  }
  T* get() const { return ptr; }
  T* release() {
    T* tmp = ptr;
    ptr = nullptr;
    return tmp;
  }
};

template <typename T, int (*F)(T*)>
struct ScopedInt {
  T* ptr = nullptr;
  ~ScopedInt() {
    if (ptr) F(ptr);
  }
  T* get() const { return ptr; }
  T* release() {
    T* tmp = ptr;
    ptr = nullptr;
    return tmp;
  }
};

uint64_t next_serial() {
  static std::mt19937_64 rng(std::random_device{}());
  uint64_t value = rng();
  if (value == 0) value = 1;
  return value & 0x7fffffffffffffffULL;
}

X509_NAME* build_subject_name(const CertSubject& subject) {
  X509_NAME* name = X509_NAME_new();
  if (!name) return nullptr;
  if (!subject.country.empty()) {
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subject.country.c_str()),
                               -1, -1, 0);
  }
  if (!subject.org.empty()) {
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subject.org.c_str()),
                               -1, -1, 0);
  }
  if (!subject.org_unit.empty()) {
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subject.org_unit.c_str()),
                               -1, -1, 0);
  }
  if (!subject.common_name.empty()) {
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subject.common_name.c_str()),
                               -1, -1, 0);
  }
  return name;
}

bool add_ext(X509* cert, X509* issuer, int nid, const char* value, std::string* err) {
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
  if (!ex) {
    if (err) *err = collect_ssl_errors("X509V3_EXT_conf_nid failed");
    return false;
  }
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return true;
}

bool write_key_file(const std::string& path, EVP_PKEY* pkey, std::string* err) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) {
    if (err) *err = "Failed to open key file for writing";
    return false;
  }
  bool ok = PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
  std::fclose(f);
  if (!ok && err) *err = collect_ssl_errors("PEM_write_PrivateKey failed");
  return ok;
}

bool write_cert_file(const std::string& path, X509* cert, std::string* err) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) {
    if (err) *err = "Failed to open cert file for writing";
    return false;
  }
  bool ok = PEM_write_X509(f, cert) == 1;
  std::fclose(f);
  if (!ok && err) *err = collect_ssl_errors("PEM_write_X509 failed");
  return ok;
}

bool write_csr_file(const std::string& path, X509_REQ* req, std::string* err) {
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) {
    if (err) *err = "Failed to open CSR file for writing";
    return false;
  }
  bool ok = PEM_write_X509_REQ(f, req) == 1;
  std::fclose(f);
  if (!ok && err) *err = collect_ssl_errors("PEM_write_X509_REQ failed");
  return ok;
}

EVP_PKEY* load_key(const std::string& path, std::string* err) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    if (err) *err = "Failed to open key file";
    return nullptr;
  }
  EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
  std::fclose(f);
  if (!pkey && err) *err = collect_ssl_errors("PEM_read_PrivateKey failed");
  return pkey;
}

X509* load_cert(const std::string& path, std::string* err) {
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) {
    if (err) *err = "Failed to open cert file";
    return nullptr;
  }
  X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr);
  std::fclose(f);
  if (!cert && err) *err = collect_ssl_errors("PEM_read_X509 failed");
  return cert;
}

} // namespace

bool generate_rsa_key(const std::string& key_path, int bits, std::string* err) {
  Scoped<EVP_PKEY, EVP_PKEY_free> pkey;
  Scoped<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx;

  ctx.ptr = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!ctx.get()) {
    if (err) *err = "Failed to allocate key context";
    return false;
  }
  if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
    if (err) *err = collect_ssl_errors("EVP_PKEY_keygen_init failed");
    return false;
  }
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) <= 0) {
    if (err) *err = collect_ssl_errors("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    return false;
  }
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) {
    if (err) *err = collect_ssl_errors("EVP_PKEY_keygen failed");
    return false;
  }
  pkey.ptr = raw;

  return write_key_file(key_path, pkey.get(), err);
}

bool generate_csr(const std::string& key_path,
                  const std::string& csr_path,
                  const CertSubject& subject,
                  std::string* err) {
  Scoped<EVP_PKEY, EVP_PKEY_free> pkey;
  pkey.ptr = load_key(key_path, err);
  if (!pkey.get()) return false;

  Scoped<X509_REQ, X509_REQ_free> req;
  req.ptr = X509_REQ_new();
  if (!req.get()) {
    if (err) *err = "Failed to allocate CSR";
    return false;
  }

  X509_REQ_set_version(req.get(), 0);
  Scoped<X509_NAME, X509_NAME_free> name;
  name.ptr = build_subject_name(subject);
  if (!name.get()) {
    if (err) *err = "Failed to build CSR subject";
    return false;
  }
  X509_REQ_set_subject_name(req.get(), name.get());
  X509_REQ_set_pubkey(req.get(), pkey.get());

  if (X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()) <= 0) {
    if (err) *err = collect_ssl_errors("X509_REQ_sign failed");
    return false;
  }

  return write_csr_file(csr_path, req.get(), err);
}

bool generate_ca(const std::string& ca_key_path,
                 const std::string& ca_cert_path,
                 const CertSubject& subject,
                 int days,
                 std::string* err) {
  if (!generate_rsa_key(ca_key_path, 2048, err)) {
    return false;
  }

  Scoped<EVP_PKEY, EVP_PKEY_free> ca_key;
  ca_key.ptr = load_key(ca_key_path, err);
  if (!ca_key.get()) return false;

  Scoped<X509, X509_free> cert;
  cert.ptr = X509_new();
  if (!cert.get()) {
    if (err) *err = "Failed to allocate CA cert";
    return false;
  }
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(next_serial()));
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), static_cast<long>(days) * 24 * 60 * 60);
  X509_set_pubkey(cert.get(), ca_key.get());

  Scoped<X509_NAME, X509_NAME_free> name;
  name.ptr = build_subject_name(subject);
  if (!name.get()) {
    if (err) *err = "Failed to build CA subject";
    return false;
  }
  X509_set_subject_name(cert.get(), name.get());
  X509_set_issuer_name(cert.get(), name.get());

  if (!add_ext(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE", err)) return false;
  if (!add_ext(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign", err)) return false;
  if (!add_ext(cert.get(), cert.get(), NID_subject_key_identifier, "hash", err)) return false;

  if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) <= 0) {
    if (err) *err = collect_ssl_errors("X509_sign failed");
    return false;
  }

  return write_cert_file(ca_cert_path, cert.get(), err);
}

bool generate_signed_cert(const std::string& ca_key_path,
                          const std::string& ca_cert_path,
                          const std::string& key_path,
                          const std::string& cert_path,
                          const CertSubject& subject,
                          int days,
                          bool client_cert,
                          std::string* err) {
  if (!fs::exists(key_path)) {
    if (!generate_rsa_key(key_path, 2048, err)) {
      return false;
    }
  }

  Scoped<EVP_PKEY, EVP_PKEY_free> key;
  key.ptr = load_key(key_path, err);
  if (!key.get()) return false;

  Scoped<X509, X509_free> ca_cert;
  ca_cert.ptr = load_cert(ca_cert_path, err);
  if (!ca_cert.get()) return false;

  Scoped<EVP_PKEY, EVP_PKEY_free> ca_key;
  ca_key.ptr = load_key(ca_key_path, err);
  if (!ca_key.get()) return false;

  Scoped<X509, X509_free> cert;
  cert.ptr = X509_new();
  if (!cert.get()) {
    if (err) *err = "Failed to allocate certificate";
    return false;
  }
  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(next_serial()));
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), static_cast<long>(days) * 24 * 60 * 60);
  X509_set_pubkey(cert.get(), key.get());

  Scoped<X509_NAME, X509_NAME_free> name;
  name.ptr = build_subject_name(subject);
  if (!name.get()) {
    if (err) *err = "Failed to build certificate subject";
    return false;
  }
  X509_set_subject_name(cert.get(), name.get());
  X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert.get()));

  if (!add_ext(cert.get(), ca_cert.get(), NID_basic_constraints, "critical,CA:FALSE", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_ext_key_usage,
               client_cert ? "clientAuth" : "serverAuth", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_subject_key_identifier, "hash", err)) return false;

  if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) <= 0) {
    if (err) *err = collect_ssl_errors("X509_sign failed");
    return false;
  }

  return write_cert_file(cert_path, cert.get(), err);
}

bool sign_csr_pem(const std::string& ca_key_path,
                  const std::string& ca_cert_path,
                  const std::string& csr_pem,
                  int days,
                  bool client_cert,
                  std::string* cert_pem,
                  std::string* err) {
  if (!cert_pem) return false;

  ScopedInt<BIO, BIO_free> csr_bio;
  csr_bio.ptr = BIO_new_mem_buf(csr_pem.data(), static_cast<int>(csr_pem.size()));
  if (!csr_bio.get()) {
    if (err) *err = "Failed to create CSR buffer";
    return false;
  }

  Scoped<X509_REQ, X509_REQ_free> req;
  req.ptr = PEM_read_bio_X509_REQ(csr_bio.get(), nullptr, nullptr, nullptr);
  if (!req.get()) {
    if (err) *err = collect_ssl_errors("PEM_read_bio_X509_REQ failed");
    return false;
  }

  Scoped<EVP_PKEY, EVP_PKEY_free> ca_key;
  ca_key.ptr = load_key(ca_key_path, err);
  if (!ca_key.get()) return false;

  Scoped<X509, X509_free> ca_cert;
  ca_cert.ptr = load_cert(ca_cert_path, err);
  if (!ca_cert.get()) return false;

  Scoped<X509, X509_free> cert;
  cert.ptr = X509_new();
  if (!cert.get()) {
    if (err) *err = "Failed to allocate certificate";
    return false;
  }

  X509_set_version(cert.get(), 2);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), static_cast<long>(next_serial()));
  X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(cert.get()), static_cast<long>(days) * 24 * 60 * 60);

  X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get()));
  X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert.get()));

  Scoped<EVP_PKEY, EVP_PKEY_free> req_key;
  req_key.ptr = X509_REQ_get_pubkey(req.get());
  if (!req_key.get()) {
    if (err) *err = collect_ssl_errors("X509_REQ_get_pubkey failed");
    return false;
  }
  X509_set_pubkey(cert.get(), req_key.get());

  if (!add_ext(cert.get(), ca_cert.get(), NID_basic_constraints, "critical,CA:FALSE", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_ext_key_usage,
               client_cert ? "clientAuth" : "serverAuth", err)) return false;
  if (!add_ext(cert.get(), ca_cert.get(), NID_subject_key_identifier, "hash", err)) return false;

  if (X509_sign(cert.get(), ca_key.get(), EVP_sha256()) <= 0) {
    if (err) *err = collect_ssl_errors("X509_sign failed");
    return false;
  }

  ScopedInt<BIO, BIO_free> out_bio;
  out_bio.ptr = BIO_new(BIO_s_mem());
  if (!out_bio.get()) {
    if (err) *err = "Failed to allocate output buffer";
    return false;
  }
  if (PEM_write_bio_X509(out_bio.get(), cert.get()) != 1) {
    if (err) *err = collect_ssl_errors("PEM_write_bio_X509 failed");
    return false;
  }
  char* data = nullptr;
  long len = BIO_get_mem_data(out_bio.get(), &data);
  if (len <= 0 || !data) {
    if (err) *err = "Failed to read cert data";
    return false;
  }
  cert_pem->assign(data, static_cast<size_t>(len));
  return true;
}

bool read_text_file(const std::string& path, std::string* out, std::string* err) {
  if (!out) return false;
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (err) *err = "Failed to open file: " + path;
    return false;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  *out = ss.str();
  return true;
}

bool write_text_file(const std::string& path, const std::string& data, std::string* err) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    if (err) *err = "Failed to write file: " + path;
    return false;
  }
  out << data;
  return true;
}

} // namespace cipheator
