#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace cipheator {

struct AlertRecord {
  uint64_t id = 0;
  int64_t ts = 0;
  std::string type;
  std::string username;
  std::string detail;
};

class AuditService {
 public:
  AuditService(std::string log_path, std::string alert_path);

  void log_event(const std::string& type,
                 const std::string& username,
                 const std::string& detail);

  AlertRecord log_alert(const std::string& type,
                        const std::string& username,
                        const std::string& detail);

  std::vector<AlertRecord> get_alerts_since(uint64_t since_id, size_t limit);
  std::vector<std::string> tail_logs(size_t limit);

 private:
  uint64_t load_last_alert_id();

  std::mutex mutex_;
  std::string log_path_;
  std::string alert_path_;
  uint64_t next_alert_id_ = 1;
};

int64_t now_epoch_sec();
std::string format_event_line(int64_t ts,
                              const std::string& type,
                              const std::string& username,
                              const std::string& detail);
std::string format_alert_line(const AlertRecord& alert);

} // namespace cipheator
