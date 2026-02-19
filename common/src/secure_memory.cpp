#include "cipheator/secure_memory.h"

#include "cipheator/bytes.h"

#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace cipheator {

SecureBuffer::SecureBuffer() = default;

SecureBuffer::SecureBuffer(size_t size) {
  allocate(size);
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept {
  data_ = other.data_;
  size_ = other.size_;
  other.data_ = nullptr;
  other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
  if (this == &other) return *this;
  release();
  data_ = other.data_;
  size_ = other.size_;
  other.data_ = nullptr;
  other.size_ = 0;
  return *this;
}

SecureBuffer::~SecureBuffer() {
  release();
}

void SecureBuffer::resize(size_t size) {
  release();
  allocate(size);
}

std::vector<uint8_t> SecureBuffer::to_vector() const {
  return std::vector<uint8_t>(data_, data_ + size_);
}

void SecureBuffer::allocate(size_t size) {
  if (size == 0) return;
  data_ = new uint8_t[size];
  size_ = size;
  std::memset(data_, 0, size_);
  lock_pages();
}

void SecureBuffer::release() {
  if (!data_) return;
  secure_zero(data_, size_);
  unlock_pages();
  delete[] data_;
  data_ = nullptr;
  size_ = 0;
}

void SecureBuffer::lock_pages() {
#if defined(_WIN32)
  VirtualLock(data_, size_);
#else
  mlock(data_, size_);
#if defined(__linux__)
  madvise(data_, size_, MADV_DONTDUMP);
#endif
#endif
}

void SecureBuffer::unlock_pages() {
#if defined(_WIN32)
  VirtualUnlock(data_, size_);
#else
  munlock(data_, size_);
#endif
}

} // namespace cipheator
