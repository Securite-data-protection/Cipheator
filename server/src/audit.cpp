#include "audit.h"

#include <chrono>
#include <fstream>
#include <sstream>

namespace cipheator {

int64_t now_epoch_sec() {
  using namespace std::chrono;
  return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string format_event_line(int64_t ts,
                              const std::string& type,
                              const std::string& username,
                              const std::string& detail) {
  std::ostringstream ss;
  ss << ts << "|" << type << "|" << username << "|" << detail;
  return ss.str();
}

std::string format_alert_line(const AlertRecord& alert) {
  std::ostringstream ss;
  ss << alert.id << "|" << alert.ts << "|" << alert.type << "|" << alert.username
     << "|" << alert.detail;
  return ss.str();
}

static bool parse_alert_line(const std::string& line, AlertRecord* out) {
  if (!out) return false;
  size_t p1 = line.find('|');
  if (p1 == std::string::npos) return false;
  size_t p2 = line.find('|', p1 + 1);
  size_t p3 = line.find('|', p2 + 1);
  size_t p4 = line.find('|', p3 + 1);
  if (p2 == std::string::npos || p3 == std::string::npos || p4 == std::string::npos) {
    return false;
  }
  try {
    out->id = std::stoull(line.substr(0, p1));
    out->ts = std::stoll(line.substr(p1 + 1, p2 - p1 - 1));
  } catch (...) {
    return false;
  }
  out->type = line.substr(p2 + 1, p3 - p2 - 1);
  out->username = line.substr(p3 + 1, p4 - p3 - 1);
  out->detail = line.substr(p4 + 1);
  return true;
}

AuditService::AuditService(std::string log_path, std::string alert_path)
    : log_path_(std::move(log_path)), alert_path_(std::move(alert_path)) {
  next_alert_id_ = load_last_alert_id() + 1;
}

uint64_t AuditService::load_last_alert_id() {
  std::ifstream in(alert_path_);
  if (!in) return 0;
  std::string line;
  uint64_t last_id = 0;
  AlertRecord record;
  while (std::getline(in, line)) {
    if (parse_alert_line(line, &record)) {
      if (record.id > last_id) last_id = record.id;
    }
  }
  return last_id;
}

void AuditService::log_event(const std::string& type,
                             const std::string& username,
                             const std::string& detail) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::ofstream out(log_path_, std::ios::app);
  if (!out) return;
  out << format_event_line(now_epoch_sec(), type, username, detail) << "\n";
}

AlertRecord AuditService::log_alert(const std::string& type,
                                    const std::string& username,
                                    const std::string& detail) {
  std::lock_guard<std::mutex> lock(mutex_);
  AlertRecord alert;
  alert.id = next_alert_id_++;
  alert.ts = now_epoch_sec();
  alert.type = type;
  alert.username = username;
  alert.detail = detail;

  {
    std::ofstream out(alert_path_, std::ios::app);
    if (out) {
      out << format_alert_line(alert) << "\n";
    }
  }

  {
    std::ofstream out(log_path_, std::ios::app);
    if (out) {
      out << format_event_line(alert.ts, "alert:" + type, username, detail) << "\n";
    }
  }

  return alert;
}

std::vector<AlertRecord> AuditService::get_alerts_since(uint64_t since_id, size_t limit) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<AlertRecord> out;
  std::ifstream in(alert_path_);
  if (!in) return out;
  std::string line;
  AlertRecord record;
  while (std::getline(in, line)) {
    if (!parse_alert_line(line, &record)) continue;
    if (record.id <= since_id) continue;
    out.push_back(record);
  }
  if (limit > 0 && out.size() > limit) {
    out.erase(out.begin(), out.end() - static_cast<long>(limit));
  }
  return out;
}

std::vector<std::string> AuditService::tail_logs(size_t limit) {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<std::string> buffer;
  std::ifstream in(log_path_);
  if (!in) return buffer;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    buffer.push_back(line);
    if (limit > 0 && buffer.size() > limit) {
      buffer.erase(buffer.begin());
    }
  }
  return buffer;
}

} // namespace cipheator
