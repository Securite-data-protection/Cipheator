#pragma once

#include <string>

#include "cipheator/net.h"

#include <openssl/ssl.h>

namespace cipheator {

class TlsContext {
 public:
  TlsContext();
  ~TlsContext();
  TlsContext(const TlsContext&) = delete;
  TlsContext& operator=(const TlsContext&) = delete;

  bool init_server(const std::string& cert_file,
                   const std::string& key_file,
                   const std::string& ca_file,
                   bool require_client_cert,
                   std::string* err);

  bool init_client(const std::string& ca_file,
                   const std::string& cert_file,
                   const std::string& key_file,
                   bool verify_peer,
                   std::string* err);

  SSL_CTX* raw() const { return ctx_; }

 private:
  SSL_CTX* ctx_ = nullptr;
};

class TlsStream {
 public:
  TlsStream();
  ~TlsStream();
  TlsStream(const TlsStream&) = delete;
  TlsStream& operator=(const TlsStream&) = delete;

  bool accept(Socket&& socket, TlsContext& ctx, std::string* err);
  bool connect(Socket&& socket, TlsContext& ctx, const std::string& host, std::string* err);

  int read(uint8_t* buf, size_t len);
  int write(const uint8_t* buf, size_t len);

  void close();
  bool valid() const { return ssl_ != nullptr; }

 private:
  SSL* ssl_ = nullptr;
  Socket socket_;
};

} // namespace cipheator
