#include "cipheator/net.h"

#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace cipheator {

NetInit::NetInit() {
#if defined(_WIN32)
  WSADATA wsa;
  ok_ = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
#else
  ok_ = true;
#endif
}

NetInit::~NetInit() {
#if defined(_WIN32)
  if (ok_) {
    WSACleanup();
  }
#endif
}

Socket::Socket() : handle_(static_cast<Handle>(-1)) {}

Socket::Socket(Handle handle) : handle_(handle) {}

Socket::Socket(Socket&& other) noexcept {
  handle_ = other.handle_;
  other.handle_ = static_cast<Handle>(-1);
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this == &other) return *this;
  close();
  handle_ = other.handle_;
  other.handle_ = static_cast<Handle>(-1);
  return *this;
}

Socket::~Socket() {
  close();
}

bool Socket::valid() const {
#if defined(_WIN32)
  return handle_ != INVALID_SOCKET;
#else
  return handle_ >= 0;
#endif
}

void Socket::close() {
  if (!valid()) return;
#if defined(_WIN32)
  closesocket(static_cast<SOCKET>(handle_));
  handle_ = INVALID_SOCKET;
#else
  ::close(handle_);
  handle_ = -1;
#endif
}

bool Socket::connect_to(const std::string& host, int port, std::string* err) {
  close();

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo* result = nullptr;
  std::string port_str = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
    if (err) *err = "getaddrinfo failed";
    return false;
  }

  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
    Handle sock = static_cast<Handle>(::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
#if defined(_WIN32)
    if (sock == INVALID_SOCKET) continue;
#else
    if (sock < 0) continue;
#endif
#if defined(_WIN32)
    if (::connect(static_cast<SOCKET>(sock), rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
#else
    if (::connect(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0) {
#endif
      handle_ = sock;
      freeaddrinfo(result);
      return true;
    }
#if defined(_WIN32)
    closesocket(static_cast<SOCKET>(sock));
#else
    ::close(sock);
#endif
  }

  freeaddrinfo(result);
  if (err) *err = "Unable to connect";
  return false;
}

Socket Socket::listen_on(const std::string& host, int port, std::string* err) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  addrinfo* result = nullptr;
  std::string port_str = std::to_string(port);
  if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0) {
    if (err) *err = "getaddrinfo failed";
    return Socket();
  }

  Socket listen_sock;
  for (addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
    Handle sock = static_cast<Handle>(::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol));
#if defined(_WIN32)
    if (sock == INVALID_SOCKET) continue;
#else
    if (sock < 0) continue;
#endif

    int opt = 1;
#if defined(_WIN32)
    setsockopt(static_cast<SOCKET>(sock), SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));
#else
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

#if defined(_WIN32)
    if (::bind(static_cast<SOCKET>(sock), rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0 &&
        ::listen(static_cast<SOCKET>(sock), 16) == 0) {
#else
    if (::bind(sock, rp->ai_addr, static_cast<int>(rp->ai_addrlen)) == 0 &&
        ::listen(sock, 16) == 0) {
#endif
      listen_sock = Socket(sock);
      break;
    }
#if defined(_WIN32)
    closesocket(static_cast<SOCKET>(sock));
#else
    ::close(sock);
#endif
  }

  freeaddrinfo(result);
  if (!listen_sock.valid() && err) {
    *err = "Unable to bind";
  }
  return listen_sock;
}

Socket Socket::accept(std::string* err) const {
  if (!valid()) {
    if (err) *err = "Invalid listen socket";
    return Socket();
  }
#if defined(_WIN32)
  SOCKET client = ::accept(static_cast<SOCKET>(handle_), nullptr, nullptr);
  if (client == INVALID_SOCKET) {
    if (err) *err = "accept failed";
    return Socket();
  }
  return Socket(static_cast<Handle>(client));
#else
  int client = ::accept(handle_, nullptr, nullptr);
  if (client < 0) {
    if (err) *err = "accept failed";
    return Socket();
  }
  return Socket(client);
#endif
}

int Socket::read(uint8_t* buf, size_t len) const {
  if (!valid()) return -1;
#if defined(_WIN32)
  return ::recv(static_cast<SOCKET>(handle_), reinterpret_cast<char*>(buf),
                static_cast<int>(len), 0);
#else
  return ::recv(handle_, buf, len, 0);
#endif
}

int Socket::write(const uint8_t* buf, size_t len) const {
  if (!valid()) return -1;
#if defined(_WIN32)
  return ::send(static_cast<SOCKET>(handle_), reinterpret_cast<const char*>(buf),
                static_cast<int>(len), 0);
#else
  return ::send(handle_, buf, len, 0);
#endif
}

} // namespace cipheator
