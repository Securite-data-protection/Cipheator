#include "admin_client.h"

#include "cipheator/net.h"
#include "cipheator/tls.h"

#include <sstream>

namespace cipheator {

namespace {

std::string normalize_host(const std::string& host) {
  if (host == "0.0.0.0" || host == "::") {
    return "127.0.0.1";
  }
  return host;
}

} // namespace

AdminClient::AdminClient(AdminConfig config) : config_(std::move(config)) {}

bool AdminClient::send_request(const AdminDevice& device,
                               const Header& header,
                               Header* response,
                               std::string* payload,
                               std::string* err) {
  NetInit net_init;
  if (!net_init.ok()) {
    if (err) *err = "Network init failed";
    return false;
  }

  Socket socket;
  std::string conn_err;
  const std::string target_host = normalize_host(device.host);
  if (!socket.connect_to(target_host, device.port, &conn_err)) {
    if (err) *err = "Connect failed: " + conn_err;
    return false;
  }

  TlsContext tls_ctx;
  if (!tls_ctx.init_client(config_.ca_file, config_.client_cert,
                           config_.client_key, config_.verify_peer, &conn_err)) {
    if (err) *err = "TLS init failed: " + conn_err;
    return false;
  }

  TlsStream stream;
  if (!stream.connect(std::move(socket), tls_ctx, target_host, &conn_err)) {
    if (err) *err = "TLS connect failed: " + conn_err;
    return false;
  }

  if (!write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, header)) {
    if (err) *err = "Failed to send header";
    return false;
  }

  Header resp;
  if (!read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, 65536, &resp)) {
    if (err) *err = "Failed to read response";
    return false;
  }

  if (response) *response = resp;

  if (payload) {
    payload->clear();
    size_t size = 0;
    try {
      if (!resp.get("payload_size").empty()) {
        size = static_cast<size_t>(std::stoull(resp.get("payload_size")));
      }
    } catch (...) {
      if (err) *err = "Invalid payload_size";
      return false;
    }

    if (size > 0) {
      payload->resize(size);
      size_t total = 0;
      while (total < size) {
        int n = stream.read(reinterpret_cast<uint8_t*>(&(*payload)[0]) + total,
                            size - total);
        if (n <= 0) {
          if (err) *err = "Failed to read payload";
          return false;
        }
        total += static_cast<size_t>(n);
      }
    }
  }

  return true;
}

bool AdminClient::get_alerts(const AdminDevice& device,
                             uint64_t since_id,
                             size_t limit,
                             std::vector<std::string>* lines,
                             uint64_t* last_id,
                             std::string* err) {
  Header header;
  header.set("op", "admin_get_alerts");
  header.set("admin_token", device.token);
  header.set("since_id", std::to_string(since_id));
  header.set("limit", std::to_string(limit));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }

  if (last_id && !resp.get("last_id").empty()) {
    try {
      *last_id = std::stoull(resp.get("last_id"));
    } catch (...) {
    }
  }

  if (lines) {
    lines->clear();
    std::istringstream ss(payload);
    std::string line;
    while (std::getline(ss, line)) {
      if (!line.empty()) lines->push_back(line);
    }
  }
  return true;
}

bool AdminClient::get_logs(const AdminDevice& device,
                           size_t limit,
                           std::vector<std::string>* lines,
                           std::string* err) {
  Header header;
  header.set("op", "admin_get_logs");
  header.set("admin_token", device.token);
  header.set("limit", std::to_string(limit));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }

  if (lines) {
    lines->clear();
    std::istringstream ss(payload);
    std::string line;
    while (std::getline(ss, line)) {
      if (!line.empty()) lines->push_back(line);
    }
  }
  return true;
}

bool AdminClient::get_stats(const AdminDevice& device,
                            size_t limit,
                            std::vector<std::string>* lines,
                            std::string* err) {
  Header header;
  header.set("op", "admin_get_stats");
  header.set("admin_token", device.token);
  header.set("limit", std::to_string(limit));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }

  if (lines) {
    lines->clear();
    std::istringstream ss(payload);
    std::string line;
    while (std::getline(ss, line)) {
      if (!line.empty()) lines->push_back(line);
    }
  }
  return true;
}

bool AdminClient::get_policy(const AdminDevice& device,
                             SecurityPolicy* out,
                             std::string* err) {
  Header header;
  header.set("op", "admin_get_policy");
  header.set("admin_token", device.token);

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }

  if (out) {
    try {
      out->password_max_age_days = std::stoi(resp.get("password_max_age_days", "90"));
    } catch (...) {
      out->password_max_age_days = 90;
    }
    std::string val = resp.get("proactive_enabled", "1");
    out->proactive_enabled = (val == "1" || val == "true");
    std::string admin_val = resp.get("admin_enabled", "1");
    out->admin_enabled = (admin_val == "1" || admin_val == "true");
    try {
      out->admin_created_ts = std::stoll(resp.get("admin_created_ts", "0"));
    } catch (...) {
      out->admin_created_ts = 0;
    }
    try {
      out->last_config_change_ts = std::stoll(resp.get("last_config_change_ts", "0"));
    } catch (...) {
      out->last_config_change_ts = 0;
    }
    try {
      out->policy_version = static_cast<uint64_t>(std::stoull(resp.get("policy_version", "0")));
    } catch (...) {
      out->policy_version = 0;
    }
    try {
      out->work_hours_start = std::stoi(resp.get("work_hours_start", "-1"));
      out->work_hours_end = std::stoi(resp.get("work_hours_end", "-1"));
      out->failed_login_threshold = static_cast<size_t>(std::stoull(resp.get("failed_login_threshold", "3")));
      out->failed_login_window_sec = std::stoll(resp.get("failed_login_window_sec", "600"));
      out->bulk_files_threshold = static_cast<size_t>(std::stoull(resp.get("bulk_files_threshold", "20")));
      out->bulk_files_window_sec = std::stoll(resp.get("bulk_files_window_sec", "300"));
      out->decrypt_burst_threshold = static_cast<size_t>(std::stoull(resp.get("decrypt_burst_threshold", "20")));
      out->decrypt_burst_window_sec = std::stoll(resp.get("decrypt_burst_window_sec", "60"));
      out->decrypt_volume_threshold_mb = static_cast<size_t>(std::stoull(resp.get("decrypt_volume_threshold_mb", "256")));
      out->decrypt_volume_window_sec = std::stoll(resp.get("decrypt_volume_window_sec", "300"));
    } catch (...) {
    }
  }
  return true;
}

bool AdminClient::set_policy(const AdminDevice& device,
                             const SecurityPolicy& policy,
                             std::string* err) {
  Header header;
  header.set("op", "admin_set_policy");
  header.set("admin_token", device.token);
  header.set("password_max_age_days", std::to_string(policy.password_max_age_days));
  header.set("proactive_enabled", policy.proactive_enabled ? "1" : "0");
  header.set("work_hours_start", std::to_string(policy.work_hours_start));
  header.set("work_hours_end", std::to_string(policy.work_hours_end));
  header.set("failed_login_threshold", std::to_string(policy.failed_login_threshold));
  header.set("failed_login_window_sec", std::to_string(policy.failed_login_window_sec));
  header.set("bulk_files_threshold", std::to_string(policy.bulk_files_threshold));
  header.set("bulk_files_window_sec", std::to_string(policy.bulk_files_window_sec));
  header.set("decrypt_burst_threshold", std::to_string(policy.decrypt_burst_threshold));
  header.set("decrypt_burst_window_sec", std::to_string(policy.decrypt_burst_window_sec));
  header.set("decrypt_volume_threshold_mb", std::to_string(policy.decrypt_volume_threshold_mb));
  header.set("decrypt_volume_window_sec", std::to_string(policy.decrypt_volume_window_sec));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  return true;
}

bool AdminClient::delete_admin_role(const AdminDevice& device,
                                    std::string* err) {
  Header header;
  header.set("op", "admin_delete_role");
  header.set("admin_token", device.token);

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  return true;
}

bool AdminClient::get_locks(const AdminDevice& device,
                            size_t limit,
                            std::vector<std::string>* lines,
                            std::string* err) {
  Header header;
  header.set("op", "admin_get_locks");
  header.set("admin_token", device.token);
  header.set("limit", std::to_string(limit));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  if (lines) {
    lines->clear();
    std::istringstream ss(payload);
    std::string line;
    while (std::getline(ss, line)) {
      if (!line.empty()) lines->push_back(line);
    }
  }
  return true;
}

bool AdminClient::get_binding(const AdminDevice& device,
                              size_t limit,
                              bool* enabled,
                              std::vector<std::string>* lines,
                              std::string* err) {
  Header header;
  header.set("op", "admin_get_binding");
  header.set("admin_token", device.token);
  header.set("limit", std::to_string(limit));

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  if (enabled) {
    *enabled = (resp.get("binding_enabled") == "1" || resp.get("binding_enabled") == "true");
  }
  if (lines) {
    lines->clear();
    std::istringstream ss(payload);
    std::string line;
    while (std::getline(ss, line)) {
      if (!line.empty()) lines->push_back(line);
    }
  }
  return true;
}

bool AdminClient::set_binding(const AdminDevice& device, bool enabled, std::string* err) {
  Header header;
  header.set("op", "admin_set_binding");
  header.set("admin_token", device.token);
  header.set("enabled", enabled ? "1" : "0");

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  return true;
}

bool AdminClient::set_client_allowed(const AdminDevice& device,
                                     const std::string& client_id,
                                     bool allowed,
                                     std::string* err) {
  Header header;
  header.set("op", "admin_set_client_allowed");
  header.set("admin_token", device.token);
  header.set("client_id", client_id);
  header.set("allowed", allowed ? "1" : "0");

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  return true;
}

bool AdminClient::unlock_user(const AdminDevice& device,
                              const std::string& username,
                              std::string* message,
                              std::string* err) {
  Header header;
  header.set("op", "admin_unlock_user");
  header.set("admin_token", device.token);
  header.set("username", username);

  Header resp;
  std::string payload;
  if (!send_request(device, header, &resp, &payload, err)) {
    return false;
  }
  if (resp.get("status") != "ok") {
    if (err) *err = resp.get("message", "Server error");
    return false;
  }
  if (message) {
    *message = resp.get("message");
  }
  return true;
}

} // namespace cipheator
