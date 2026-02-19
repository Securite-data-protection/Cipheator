#pragma once

#include "audit.h"
#include "monitor.h"

#include "cipheator/net.h"
#include "cipheator/protocol.h"
#include "cipheator/tls.h"

#include <atomic>
#include <string>
#include <thread>

namespace cipheator {

class AdminServer {
 public:
  AdminServer(std::string host,
              int port,
              std::string token,
              TlsContext* tls,
              AuditService* audit,
              SecurityMonitor* monitor);
  ~AdminServer();

  void start();

 private:
  void run();
  void handle_client(Socket client);
  bool authorize(const Header& header) const;
  void send_error(TlsStream& stream, const std::string& message);
  void send_payload(TlsStream& stream, const Header& header, const std::string& payload);

  std::string host_;
  int port_ = 0;
  std::string token_;
  TlsContext* tls_ = nullptr;
  AuditService* audit_ = nullptr;
  SecurityMonitor* monitor_ = nullptr;

  std::thread thread_;
  std::atomic<bool> running_{false};
};

} // namespace cipheator
