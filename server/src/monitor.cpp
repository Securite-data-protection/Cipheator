#include "monitor.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <ctime>

namespace cipheator {

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

  if (suspicious && (now - stats.last_time_alert_ts) > cfg_.alert_cooldown_sec) {
    stats.last_time_alert_ts = now;
    if (audit_) {
      std::ostringstream detail;
      detail << "suspicious-hour=" << hour << " total=" << stats.total_logins;
      audit_->log_alert("suspicious_time", username, detail.str());
    }
    if (cfg_.lock_suspicious_time_sec > 0) {
      stats.lock_until_ts = std::max(stats.lock_until_ts, now + cfg_.lock_suspicious_time_sec);
      if (audit_) {
        std::ostringstream detail;
        detail << "locked_until=" << stats.lock_until_ts << " reason=suspicious_time";
        audit_->log_event("user_locked", username, detail.str());
      }
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
    if (cfg_.lock_failed_login_sec > 0) {
      stats.lock_until_ts = std::max(stats.lock_until_ts, now + cfg_.lock_failed_login_sec);
      if (audit_) {
        std::ostringstream detail;
        detail << "locked_until=" << stats.lock_until_ts << " reason=failed_logins";
        audit_->log_event("user_locked", username, detail.str());
      }
    }
  }
  save_stats();
}

void SecurityMonitor::record_file_op(const std::string& username,
                                     const std::string& op,
                                     size_t count) {
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
    if (cfg_.lock_bulk_files_sec > 0) {
      stats.lock_until_ts = std::max(stats.lock_until_ts, now + cfg_.lock_bulk_files_sec);
      if (audit_) {
        std::ostringstream detail;
        detail << "locked_until=" << stats.lock_until_ts << " reason=bulk_files";
        audit_->log_event("user_locked", username, detail.str());
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

} // namespace cipheator
