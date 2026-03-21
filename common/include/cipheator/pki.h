#pragma once

#include <string>

namespace cipheator {

struct CertSubject {
  std::string common_name;
  std::string org;
  std::string org_unit;
  std::string country;
};

bool generate_rsa_key(const std::string& key_path, int bits, std::string* err);

bool generate_csr(const std::string& key_path,
                  const std::string& csr_path,
                  const CertSubject& subject,
                  std::string* err);

bool generate_ca(const std::string& ca_key_path,
                 const std::string& ca_cert_path,
                 const CertSubject& subject,
                 int days,
                 std::string* err);

bool generate_signed_cert(const std::string& ca_key_path,
                          const std::string& ca_cert_path,
                          const std::string& key_path,
                          const std::string& cert_path,
                          const CertSubject& subject,
                          int days,
                          bool client_cert,
                          std::string* err);

bool sign_csr_pem(const std::string& ca_key_path,
                  const std::string& ca_cert_path,
                  const std::string& csr_pem,
                  int days,
                  bool client_cert,
                  std::string* cert_pem,
                  std::string* err);

bool read_text_file(const std::string& path, std::string* out, std::string* err);
bool write_text_file(const std::string& path, const std::string& data, std::string* err);

} // namespace cipheator
