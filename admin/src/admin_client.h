#pragma once

#include "cipheator/protocol.h"

#include <string>
#include <vector>

namespace cipheator {

struct AdminConfig {
  std::string ca_file;
  std::string client_cert;
  std::string client_key;
  bool verify_peer = true;
};

struct AdminDevice {
  std::string name;
  std::string host;
  int port = 7444;
  std::string token;
};

class AdminClient {
 public:
  explicit AdminClient(AdminConfig config);

  bool get_alerts(const AdminDevice& device,
                  uint64_t since_id,
                  size_t limit,
                  std::vector<std::string>* lines,
                  uint64_t* last_id,
                  std::string* err);

  bool get_logs(const AdminDevice& device,
                size_t limit,
                std::vector<std::string>* lines,
                std::string* err);

  bool get_stats(const AdminDevice& device,
                 size_t limit,
                 std::vector<std::string>* lines,
                 std::string* err);

  bool get_locks(const AdminDevice& device,
                 size_t limit,
                 std::vector<std::string>* lines,
                 std::string* err);

  bool get_binding(const AdminDevice& device,
                   size_t limit,
                   bool* enabled,
                   std::vector<std::string>* lines,
                   std::string* err);

  bool set_binding(const AdminDevice& device, bool enabled, std::string* err);
  bool set_client_allowed(const AdminDevice& device,
                          const std::string& client_id,
                          bool allowed,
                          std::string* err);
  bool unlock_user(const AdminDevice& device,
                   const std::string& username,
                   std::string* err);

 private:
  bool send_request(const AdminDevice& device,
                    const Header& header,
                    Header* response,
                    std::string* payload,
                    std::string* err);

  AdminConfig config_;
};

} // namespace cipheator
