#include "admin_client.h"

#include "cipheator/net.h"
#include "cipheator/tls.h"

#include <sstream>

namespace cipheator {

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
  if (!socket.connect_to(device.host, device.port, &conn_err)) {
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
  if (!stream.connect(std::move(socket), tls_ctx, device.host, &conn_err)) {
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

} // namespace cipheator
