#pragma once

#include "audit.h"

#include <array>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

namespace cipheator {

struct MonitorConfig {
  size_t failed_login_threshold = 3;
  int64_t failed_login_window_sec = 600;
  size_t bulk_files_threshold = 20;
  int64_t bulk_files_window_sec = 300;
  size_t time_min_samples = 5;
  double time_hour_fraction = 0.2;
  int64_t alert_cooldown_sec = 600;
  int work_hours_start = -1; // 0-23, -1 to disable
  int work_hours_end = -1;   // 0-23, -1 to disable
  int64_t lock_failed_login_sec = 0;
  int64_t lock_bulk_files_sec = 0;
  int64_t lock_suspicious_time_sec = 0;
  size_t decrypt_burst_threshold = 20;
  int64_t decrypt_burst_window_sec = 60;
  size_t decrypt_volume_threshold_mb = 256;
  int64_t decrypt_volume_window_sec = 300;
  size_t profile_min_decrypt_samples = 20;
  double profile_decrypt_rate_factor = 3.0;
  double profile_decrypt_bytes_factor = 4.0;
};

struct UserStats {
  std::array<uint32_t, 24> hour_counts{};
  uint32_t total_logins = 0;
  std::deque<int64_t> failed_login_times;
  std::deque<int64_t> file_op_times;
  std::deque<int64_t> decrypt_times;
  std::deque<std::pair<int64_t, size_t>> decrypt_size_times;
  uint64_t total_decrypt_ops = 0;
  uint64_t total_decrypt_bytes = 0;
  int64_t last_failed_alert_ts = 0;
  int64_t last_bulk_alert_ts = 0;
  int64_t last_time_alert_ts = 0;
  int64_t last_decrypt_rate_alert_ts = 0;
  int64_t last_decrypt_volume_alert_ts = 0;
  uint32_t strike_level = 0;
  int64_t lock_until_ts = 0;
};

class SecurityMonitor {
 public:
  SecurityMonitor(MonitorConfig cfg, AuditService* audit, std::string stats_path);

  void record_login_success(const std::string& username);
  void record_login_failure(const std::string& username);
  void record_file_op(const std::string& username,
                      const std::string& op,
                      size_t count,
                      size_t bytes);
  bool is_locked(const std::string& username, int64_t* remaining_sec);
  bool unlock_user(const std::string& username);
  bool reduce_lock(const std::string& username, int64_t max_remaining_sec);
  void update_config(const MonitorConfig& cfg);
  MonitorConfig current_config();

  std::vector<std::string> dump_stats(size_t limit);
  std::vector<std::string> dump_locks(size_t limit);
  bool load_stats();

 private:
  void save_stats();
  bool is_suspicious_hour(const UserStats& stats, int hour) const;
  bool is_outside_work_hours(int hour) const;

  MonitorConfig cfg_;
  AuditService* audit_ = nullptr;
  std::string stats_path_;

  std::mutex mutex_;
  std::unordered_map<std::string, UserStats> stats_;
};

} // namespace cipheator
