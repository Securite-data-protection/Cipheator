#include "cipheator/tls.h"

#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include <sstream>

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

std::string verify_result_to_string(long result) {
  const char* msg = X509_verify_cert_error_string(result);
  if (!msg) return "unknown";
  return msg;
}

} // namespace

TlsContext::TlsContext() {
  OPENSSL_init_ssl(0, nullptr);
}

TlsContext::~TlsContext() {
  if (ctx_) {
    SSL_CTX_free(ctx_);
    ctx_ = nullptr;
  }
}

bool TlsContext::init_server(const std::string& cert_file,
                             const std::string& key_file,
                             const std::string& ca_file,
                             bool require_client_cert,
                             std::string* err) {
  ctx_ = SSL_CTX_new(TLS_server_method());
  if (!ctx_) {
    if (err) *err = "SSL_CTX_new failed";
    return false;
  }

  if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
    if (err) *err = "Failed to load server certificate";
    return false;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
    if (err) *err = "Failed to load server key";
    return false;
  }

  if (!ca_file.empty()) {
    if (SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr) != 1) {
      if (err) *err = "Failed to load CA file";
      return false;
    }
  }

  if (require_client_cert) {
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  }

  SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
  return true;
}

bool TlsContext::init_client(const std::string& ca_file,
                             const std::string& cert_file,
                             const std::string& key_file,
                             bool verify_peer,
                             std::string* err) {
  ctx_ = SSL_CTX_new(TLS_client_method());
  if (!ctx_) {
    if (err) *err = "SSL_CTX_new failed";
    return false;
  }

  if (!ca_file.empty()) {
    if (SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr) != 1) {
      if (err) *err = "Failed to load CA file";
      return false;
    }
  }

  if (!cert_file.empty() && !key_file.empty()) {
    if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
      if (err) *err = "Failed to load client certificate";
      return false;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
      if (err) *err = "Failed to load client key";
      return false;
    }
  }

  SSL_CTX_set_verify(ctx_, verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, nullptr);
  SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
  return true;
}

TlsStream::TlsStream() = default;

TlsStream::~TlsStream() {
  close();
}

bool TlsStream::accept(Socket&& socket, TlsContext& ctx, std::string* err) {
  socket_ = std::move(socket);
  ssl_ = SSL_new(ctx.raw());
  if (!ssl_) {
    if (err) *err = "SSL_new failed";
    return false;
  }
  SSL_set_fd(ssl_, static_cast<int>(socket_.native()));
  int rc = SSL_accept(ssl_);
  if (rc != 1) {
    if (err) {
      int ssl_err = SSL_get_error(ssl_, rc);
      std::ostringstream ss;
      ss << "SSL_accept failed (SSL_get_error=" << ssl_err << ")";
      std::string openssl = collect_ssl_errors(ss.str().c_str());
      *err = openssl;
    }
    close();
    return false;
  }
  return true;
}

bool TlsStream::connect(Socket&& socket, TlsContext& ctx, const std::string& host, std::string* err) {
  socket_ = std::move(socket);
  ssl_ = SSL_new(ctx.raw());
  if (!ssl_) {
    if (err) *err = "SSL_new failed";
    return false;
  }
  SSL_set_fd(ssl_, static_cast<int>(socket_.native()));
  SSL_set_tlsext_host_name(ssl_, host.c_str());
  int rc = SSL_connect(ssl_);
  if (rc != 1) {
    if (err) {
      int ssl_err = SSL_get_error(ssl_, rc);
      std::ostringstream ss;
      ss << "SSL_connect failed (SSL_get_error=" << ssl_err << ")";
      long verify = SSL_get_verify_result(ssl_);
      if (verify != X509_V_OK) {
        ss << " verify=" << verify_result_to_string(verify);
      }
      std::string openssl = collect_ssl_errors(ss.str().c_str());
      *err = openssl;
    }
    close();
    return false;
  }
  return true;
}

int TlsStream::read(uint8_t* buf, size_t len) {
  if (!ssl_) return -1;
  return SSL_read(ssl_, buf, static_cast<int>(len));
}

int TlsStream::write(const uint8_t* buf, size_t len) {
  if (!ssl_) return -1;
  return SSL_write(ssl_, buf, static_cast<int>(len));
}

void TlsStream::close() {
  if (ssl_) {
    SSL_shutdown(ssl_);
    SSL_free(ssl_);
    ssl_ = nullptr;
  }
  socket_.close();
}

} // namespace cipheator
