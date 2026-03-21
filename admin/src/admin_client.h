#pragma once

#include "cipheator/protocol.h"

#include <cstdint>
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

struct SecurityPolicy {
  int password_max_age_days = 90;
  bool proactive_enabled = true;
  bool admin_enabled = true;
  int64_t admin_created_ts = 0;
  int64_t last_config_change_ts = 0;
  uint64_t policy_version = 0;
  int work_hours_start = -1;
  int work_hours_end = -1;
  size_t failed_login_threshold = 3;
  int64_t failed_login_window_sec = 600;
  size_t bulk_files_threshold = 20;
  int64_t bulk_files_window_sec = 300;
  size_t decrypt_burst_threshold = 20;
  int64_t decrypt_burst_window_sec = 60;
  size_t decrypt_volume_threshold_mb = 256;
  int64_t decrypt_volume_window_sec = 300;
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

  bool get_policy(const AdminDevice& device,
                  SecurityPolicy* out,
                  std::string* err);

  bool set_policy(const AdminDevice& device,
                  const SecurityPolicy& policy,
                  std::string* err);

  bool delete_admin_role(const AdminDevice& device,
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
                   std::string* message,
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
