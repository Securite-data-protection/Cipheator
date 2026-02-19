#include "admin_server.h"

#include <sstream>
#include <vector>

namespace cipheator {

AdminServer::AdminServer(std::string host,
                         int port,
                         std::string token,
                         TlsContext* tls,
                         AuditService* audit,
                         SecurityMonitor* monitor)
    : host_(std::move(host)),
      port_(port),
      token_(std::move(token)),
      tls_(tls),
      audit_(audit),
      monitor_(monitor) {}

AdminServer::~AdminServer() {
  running_ = false;
  if (thread_.joinable()) {
    thread_.join();
  }
}

void AdminServer::start() {
  if (running_) return;
  running_ = true;
  thread_ = std::thread([this]() { run(); });
}

bool AdminServer::authorize(const Header& header) const {
  return header.get("admin_token") == token_;
}

void AdminServer::send_error(TlsStream& stream, const std::string& message) {
  Header resp;
  resp.set("status", "error");
  resp.set("message", message);
  write_header([&](const uint8_t* buf, size_t len) {
    return stream.write(buf, len);
  }, resp);
}

void AdminServer::send_payload(TlsStream& stream, const Header& header, const std::string& payload) {
  if (!write_header([&](const uint8_t* buf, size_t len) {
        return stream.write(buf, len);
      }, header)) {
    return;
  }
  size_t total = 0;
  while (total < payload.size()) {
    int n = stream.write(reinterpret_cast<const uint8_t*>(payload.data()) + total,
                         payload.size() - total);
    if (n <= 0) return;
    total += static_cast<size_t>(n);
  }
}

void AdminServer::handle_client(Socket client) {
  if (!tls_) return;
  TlsStream stream;
  std::string err;
  if (!stream.accept(std::move(client), *tls_, &err)) {
    return;
  }

  Header req;
  if (!read_header([&](uint8_t* buf, size_t len) {
        return stream.read(buf, len);
      }, 65536, &req)) {
    return;
  }

  if (!authorize(req)) {
    send_error(stream, "Unauthorized");
    return;
  }

  std::string op = req.get("op");
  if (op == "admin_get_alerts") {
    uint64_t since_id = 0;
    size_t limit = 100;
    try {
      if (!req.get("since_id").empty()) {
        since_id = std::stoull(req.get("since_id"));
      }
      if (!req.get("limit").empty()) {
        limit = static_cast<size_t>(std::stoull(req.get("limit")));
      }
    } catch (...) {
      send_error(stream, "Invalid parameters");
      return;
    }

    std::ostringstream payload;
    auto alerts = audit_ ? audit_->get_alerts_since(since_id, limit) : std::vector<AlertRecord>();
    uint64_t last_id = since_id;
    for (const auto& alert : alerts) {
      payload << format_alert_line(alert) << "\n";
      if (alert.id > last_id) last_id = alert.id;
    }

    Header resp;
    resp.set("status", "ok");
    resp.set("payload_size", std::to_string(payload.str().size()));
    resp.set("last_id", std::to_string(last_id));
    send_payload(stream, resp, payload.str());
    return;
  }

  if (op == "admin_get_logs") {
    size_t limit = 200;
    try {
      if (!req.get("limit").empty()) {
        limit = static_cast<size_t>(std::stoull(req.get("limit")));
      }
    } catch (...) {
      send_error(stream, "Invalid parameters");
      return;
    }

    std::ostringstream payload;
    auto lines = audit_ ? audit_->tail_logs(limit) : std::vector<std::string>();
    for (const auto& line : lines) {
      payload << line << "\n";
    }

    Header resp;
    resp.set("status", "ok");
    resp.set("payload_size", std::to_string(payload.str().size()));
    send_payload(stream, resp, payload.str());
    return;
  }

  if (op == "admin_get_stats") {
    size_t limit = 200;
    try {
      if (!req.get("limit").empty()) {
        limit = static_cast<size_t>(std::stoull(req.get("limit")));
      }
    } catch (...) {
      send_error(stream, "Invalid parameters");
      return;
    }

    std::ostringstream payload;
    auto lines = monitor_ ? monitor_->dump_stats(limit) : std::vector<std::string>();
    for (const auto& line : lines) {
      payload << line << "\n";
    }

    Header resp;
    resp.set("status", "ok");
    resp.set("payload_size", std::to_string(payload.str().size()));
    send_payload(stream, resp, payload.str());
    return;
  }

  send_error(stream, "Unknown op");
}

void AdminServer::run() {
  NetInit net_init;
  if (!net_init.ok()) return;

  std::string err;
  Socket server = Socket::listen_on(host_, port_, &err);
  if (!server.valid()) {
    if (audit_) {
      audit_->log_event("admin_listen_error", "system", err);
    }
    return;
  }

  while (running_) {
    Socket client = server.accept(&err);
    if (!client.valid()) {
      continue;
    }
    std::thread([this, c = std::move(client)]() mutable {
      handle_client(std::move(c));
    }).detach();
  }
}

} // namespace cipheator
