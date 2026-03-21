#include "monitor.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <ctime>

namespace cipheator {

namespace {

int64_t lock_ladder_sec(uint32_t strike_level) {
  static const int64_t kLadder[] = {60, 300, 600, 1800, 3600, 7200};
  size_t idx = (strike_level == 0) ? 0 : static_cast<size_t>(strike_level - 1);
  if (idx >= sizeof(kLadder) / sizeof(kLadder[0])) {
    idx = sizeof(kLadder) / sizeof(kLadder[0]) - 1;
  }
  return kLadder[idx];
}

int64_t choose_lock_duration(UserStats& stats, int64_t configured_sec) {
  if (configured_sec > 0) return configured_sec;
  if (stats.strike_level < 1000) {
    stats.strike_level += 1;
  }
  return lock_ladder_sec(stats.strike_level);
}

} // namespace

SecurityMonitor::SecurityMonitor(MonitorConfig cfg, AuditService* audit, std::string stats_path)
    : cfg_(cfg), audit_(audit), stats_path_(std::move(stats_path)) {}

bool SecurityMonitor::load_stats() {
  std::lock_guard<std::mutex> lock(mutex_);
  stats_.clear();
  std::ifstream in(stats_path_);
  if (!in) return false;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::istringstream ss(line);
    std::string username;
    if (!std::getline(ss, username, '|')) continue;
    std::string total_str;
    if (!std::getline(ss, total_str, '|')) continue;
    std::string hours_str;
    if (!std::getline(ss, hours_str, '|')) continue;
    std::string lock_str;
    std::getline(ss, lock_str, '|');

    UserStats stats;
    try {
      stats.total_logins = static_cast<uint32_t>(std::stoul(total_str));
    } catch (...) {
      continue;
    }

    std::istringstream hs(hours_str);
    std::string part;
    int idx = 0;
    while (std::getline(hs, part, ',') && idx < 24) {
      try {
        stats.hour_counts[idx] = static_cast<uint32_t>(std::stoul(part));
      } catch (...) {
        stats.hour_counts[idx] = 0;
      }
      ++idx;
    }

    if (!lock_str.empty()) {
      try {
        stats.lock_until_ts = std::stoll(lock_str);
      } catch (...) {
        stats.lock_until_ts = 0;
      }
    }

    stats_[username] = stats;
  }
  return true;
}

void SecurityMonitor::save_stats() {
  std::ofstream out(stats_path_, std::ios::trunc);
  if (!out) return;
  for (const auto& kv : stats_) {
    out << kv.first << "|" << kv.second.total_logins << "|";
    for (size_t i = 0; i < kv.second.hour_counts.size(); ++i) {
      out << kv.second.hour_counts[i];
      if (i + 1 < kv.second.hour_counts.size()) out << ",";
    }
    out << "|" << kv.second.lock_until_ts << "\n";
  }
}

bool SecurityMonitor::is_outside_work_hours(int hour) const {
  if (cfg_.work_hours_start < 0 || cfg_.work_hours_end < 0) return false;
  if (hour < 0 || hour > 23) return false;
  if (cfg_.work_hours_start <= cfg_.work_hours_end) {
    return hour < cfg_.work_hours_start || hour > cfg_.work_hours_end;
  }
  return hour > cfg_.work_hours_end && hour < cfg_.work_hours_start;
}

bool SecurityMonitor::is_suspicious_hour(const UserStats& stats, int hour) const {
  if (is_outside_work_hours(hour)) return true;
  if (stats.total_logins < cfg_.time_min_samples) return false;
  if (hour < 0 || hour > 23) return false;
  double threshold = static_cast<double>(stats.total_logins) * cfg_.time_hour_fraction;
  return static_cast<double>(stats.hour_counts[hour]) < threshold;
}

void SecurityMonitor::record_login_success(const std::string& username) {
  int64_t now = now_epoch_sec();
  std::lock_guard<std::mutex> lock(mutex_);
  auto& stats = stats_[username];

  std::time_t t = static_cast<time_t>(now);
  std::tm tm_val{};
#if defined(_WIN32)
  localtime_s(&tm_val, &t);
#else
  localtime_r(&t, &tm_val);
#endif
  int hour = tm_val.tm_hour;

  bool suspicious = is_suspicious_hour(stats, hour);
  stats.total_logins += 1;
  if (hour >= 0 && hour < 24) {
    stats.hour_counts[hour] += 1;
  }

  stats.failed_login_times.clear();
  if (stats.strike_level > 0) {
    stats.strike_level -= 1;
  }

  if (suspicious && (now - stats.last_time_alert_ts) > cfg_.alert_cooldown_sec) {
    stats.last_time_alert_ts = now;
    if (audit_) {
      std::ostringstream detail;
      detail << "suspicious-hour=" << hour << " total=" << stats.total_logins;
      audit_->log_alert("suspicious_time", username, detail.str());
    }
    int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_suspicious_time_sec);
    stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
    if (audit_) {
      std::ostringstream detail;
      detail << "locked_until=" << stats.lock_until_ts << " reason=suspicious_time"
             << " lock_sec=" << lock_sec;
      audit_->log_event("user_locked", username, detail.str());
    }
  }

  save_stats();
}

void SecurityMonitor::record_login_failure(const std::string& username) {
  int64_t now = now_epoch_sec();
  std::lock_guard<std::mutex> lock(mutex_);
  auto& stats = stats_[username];

  stats.failed_login_times.push_back(now);
  while (!stats.failed_login_times.empty() &&
         now - stats.failed_login_times.front() > cfg_.failed_login_window_sec) {
    stats.failed_login_times.pop_front();
  }

  if (stats.failed_login_times.size() >= cfg_.failed_login_threshold &&
      (now - stats.last_failed_alert_ts) > cfg_.alert_cooldown_sec) {
    stats.last_failed_alert_ts = now;
    if (audit_) {
      std::ostringstream detail;
      detail << "failed-logins=" << stats.failed_login_times.size() << " window="
             << cfg_.failed_login_window_sec << "s";
      audit_->log_alert("failed_logins", username, detail.str());
    }
    int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_failed_login_sec);
    stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
    if (audit_) {
      std::ostringstream detail;
      detail << "locked_until=" << stats.lock_until_ts << " reason=failed_logins"
             << " lock_sec=" << lock_sec;
      audit_->log_event("user_locked", username, detail.str());
    }
  }
  save_stats();
}

void SecurityMonitor::record_file_op(const std::string& username,
                                     const std::string& op,
                                     size_t count,
                                     size_t bytes) {
  int64_t now = now_epoch_sec();
  std::lock_guard<std::mutex> lock(mutex_);
  auto& stats = stats_[username];

  size_t repeats = count == 0 ? 1 : count;
  for (size_t i = 0; i < repeats; ++i) {
    stats.file_op_times.push_back(now);
  }
  while (!stats.file_op_times.empty() &&
         now - stats.file_op_times.front() > cfg_.bulk_files_window_sec) {
    stats.file_op_times.pop_front();
  }

  if (stats.file_op_times.size() >= cfg_.bulk_files_threshold &&
      (now - stats.last_bulk_alert_ts) > cfg_.alert_cooldown_sec) {
    stats.last_bulk_alert_ts = now;
    if (audit_) {
      std::ostringstream detail;
      detail << "op=" << op << " count=" << stats.file_op_times.size()
             << " window=" << cfg_.bulk_files_window_sec << "s";
      audit_->log_alert("bulk_files", username, detail.str());
    }
    int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_bulk_files_sec);
    stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
    if (audit_) {
      std::ostringstream detail;
      detail << "locked_until=" << stats.lock_until_ts << " reason=bulk_files"
             << " lock_sec=" << lock_sec;
      audit_->log_event("user_locked", username, detail.str());
    }
  }

  if (op == "decrypt") {
    stats.total_decrypt_ops += repeats;
    stats.total_decrypt_bytes += static_cast<uint64_t>(bytes);

    for (size_t i = 0; i < repeats; ++i) {
      stats.decrypt_times.push_back(now);
    }
    while (!stats.decrypt_times.empty() &&
           now - stats.decrypt_times.front() > cfg_.decrypt_burst_window_sec) {
      stats.decrypt_times.pop_front();
    }

    stats.decrypt_size_times.emplace_back(now, bytes);
    while (!stats.decrypt_size_times.empty() &&
           now - stats.decrypt_size_times.front().first > cfg_.decrypt_volume_window_sec) {
      stats.decrypt_size_times.pop_front();
    }

    if (stats.decrypt_times.size() >= cfg_.decrypt_burst_threshold &&
        (now - stats.last_decrypt_rate_alert_ts) > cfg_.alert_cooldown_sec) {
      stats.last_decrypt_rate_alert_ts = now;
      if (audit_) {
        std::ostringstream detail;
        detail << "decrypt-burst=" << stats.decrypt_times.size()
               << " window=" << cfg_.decrypt_burst_window_sec << "s";
        audit_->log_alert("decrypt_burst", username, detail.str());
      }
      int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_bulk_files_sec);
      stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
      if (audit_) {
        std::ostringstream detail;
        detail << "locked_until=" << stats.lock_until_ts << " reason=decrypt_burst"
               << " lock_sec=" << lock_sec;
        audit_->log_event("user_locked", username, detail.str());
      }
    }

    uint64_t window_bytes = 0;
    for (const auto& item : stats.decrypt_size_times) {
      window_bytes += static_cast<uint64_t>(item.second);
    }
    uint64_t threshold_bytes = static_cast<uint64_t>(cfg_.decrypt_volume_threshold_mb) * 1024ULL * 1024ULL;
    if (threshold_bytes > 0 && window_bytes >= threshold_bytes &&
        (now - stats.last_decrypt_volume_alert_ts) > cfg_.alert_cooldown_sec) {
      stats.last_decrypt_volume_alert_ts = now;
      if (audit_) {
        std::ostringstream detail;
        detail << "decrypt-volume-bytes=" << window_bytes
               << " window=" << cfg_.decrypt_volume_window_sec << "s";
        audit_->log_alert("decrypt_volume", username, detail.str());
      }
      int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_bulk_files_sec);
      stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
      if (audit_) {
        std::ostringstream detail;
        detail << "locked_until=" << stats.lock_until_ts << " reason=decrypt_volume"
               << " lock_sec=" << lock_sec;
        audit_->log_event("user_locked", username, detail.str());
      }
    }

    if (stats.total_decrypt_ops >= cfg_.profile_min_decrypt_samples) {
      double avg_bytes = static_cast<double>(stats.total_decrypt_bytes) /
                         static_cast<double>(std::max<uint64_t>(1, stats.total_decrypt_ops));
      double avg_rate = static_cast<double>(stats.total_decrypt_ops) /
                        static_cast<double>(std::max<uint32_t>(1, stats.total_logins));
      double curr_rate = static_cast<double>(stats.decrypt_times.size());
      bool rate_anomaly = curr_rate > avg_rate * cfg_.profile_decrypt_rate_factor;
      bool bytes_anomaly = static_cast<double>(bytes) > avg_bytes * cfg_.profile_decrypt_bytes_factor;
      if ((rate_anomaly || bytes_anomaly) &&
          (now - stats.last_decrypt_rate_alert_ts) > cfg_.alert_cooldown_sec) {
        stats.last_decrypt_rate_alert_ts = now;
        if (audit_) {
          std::ostringstream detail;
          detail << "rate_anomaly=" << (rate_anomaly ? 1 : 0)
                 << " bytes_anomaly=" << (bytes_anomaly ? 1 : 0)
                 << " curr_rate=" << curr_rate
                 << " avg_rate=" << avg_rate
                 << " bytes=" << bytes
                 << " avg_bytes=" << static_cast<uint64_t>(avg_bytes);
          audit_->log_alert("behavior_deviation", username, detail.str());
        }
        int64_t lock_sec = choose_lock_duration(stats, cfg_.lock_suspicious_time_sec);
        stats.lock_until_ts = std::max(stats.lock_until_ts, now + lock_sec);
        if (audit_) {
          std::ostringstream detail;
          detail << "locked_until=" << stats.lock_until_ts << " reason=behavior_deviation"
                 << " lock_sec=" << lock_sec;
          audit_->log_event("user_locked", username, detail.str());
        }
      }
    }
  }
  save_stats();
}

bool SecurityMonitor::is_locked(const std::string& username, int64_t* remaining_sec) {
  int64_t now = now_epoch_sec();
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = stats_.find(username);
  if (it == stats_.end()) return false;
  if (it->second.lock_until_ts <= now) {
    return false;
  }
  if (remaining_sec) {
    *remaining_sec = it->second.lock_until_ts - now;
  }
  return true;
}

bool SecurityMonitor::unlock_user(const std::string& username) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = stats_.find(username);
  if (it == stats_.end()) return false;
  it->second.lock_until_ts = 0;
  it->second.strike_level = 0;
  if (audit_) {
    audit_->log_event("user_unlocked", username, "admin_reset");
  }
  save_stats();
  return true;
}

bool SecurityMonitor::reduce_lock(const std::string& username, int64_t max_remaining_sec) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = stats_.find(username);
  if (it == stats_.end()) return false;
  const int64_t now = now_epoch_sec();
  if (it->second.lock_until_ts <= now) return false;

  int64_t remaining = it->second.lock_until_ts - now;
  if (remaining > max_remaining_sec) {
    it->second.lock_until_ts = now + max_remaining_sec;
  }
  if (audit_) {
    audit_->log_event("user_lock_reduced", username,
                      "remaining=" + std::to_string(remaining) +
                      " max=" + std::to_string(max_remaining_sec));
  }
  save_stats();
  return true;
}

void SecurityMonitor::update_config(const MonitorConfig& cfg) {
  std::lock_guard<std::mutex> lock(mutex_);
  cfg_ = cfg;
}

MonitorConfig SecurityMonitor::current_config() {
  std::lock_guard<std::mutex> lock(mutex_);
  return cfg_;
}

std::vector<std::string> SecurityMonitor::dump_stats(size_t limit) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> out;
  for (const auto& kv : stats_) {
    std::ostringstream ss;
    ss << kv.first << "|" << kv.second.total_logins << "|";
    for (size_t i = 0; i < kv.second.hour_counts.size(); ++i) {
      ss << kv.second.hour_counts[i];
      if (i + 1 < kv.second.hour_counts.size()) ss << ",";
    }
    ss << "|" << kv.second.lock_until_ts;
    out.push_back(ss.str());
  }
  if (limit > 0 && out.size() > limit) {
    out.resize(limit);
  }
  return out;
}

std::vector<std::string> SecurityMonitor::dump_locks(size_t limit) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> out;
  const int64_t now = now_epoch_sec();
  for (const auto& kv : stats_) {
    if (kv.second.lock_until_ts <= now) continue;
    std::ostringstream ss;
    ss << kv.first << "|" << kv.second.lock_until_ts << "|" << (kv.second.lock_until_ts - now);
    out.push_back(ss.str());
    if (limit > 0 && out.size() >= limit) break;
  }
  return out;
}

} // namespace cipheator
