#pragma once

#include <cstdint>
#include <string>

namespace cipheator {

class NetInit {
 public:
  NetInit();
  ~NetInit();
  bool ok() const { return ok_; }

 private:
  bool ok_ = false;
};

class Socket {
 public:
#if defined(_WIN32)
  using Handle = uintptr_t; // SOCKET
#else
  using Handle = int;
#endif

  Socket();
  explicit Socket(Handle handle);
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;
  ~Socket();

  bool valid() const;
  Handle native() const { return handle_; }
  void close();

  bool connect_to(const std::string& host, int port, std::string* err);
  static Socket listen_on(const std::string& host, int port, std::string* err);
  Socket accept(std::string* err) const;

  int read(uint8_t* buf, size_t len) const;
  int write(const uint8_t* buf, size_t len) const;

 private:
  Handle handle_;
};

} // namespace cipheator
