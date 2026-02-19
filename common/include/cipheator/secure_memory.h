#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace cipheator {

class SecureBuffer {
 public:
  SecureBuffer();
  explicit SecureBuffer(size_t size);
  SecureBuffer(const SecureBuffer&) = delete;
  SecureBuffer& operator=(const SecureBuffer&) = delete;
  SecureBuffer(SecureBuffer&& other) noexcept;
  SecureBuffer& operator=(SecureBuffer&& other) noexcept;
  ~SecureBuffer();

  void resize(size_t size);
  size_t size() const { return size_; }
  uint8_t* data() { return data_; }
  const uint8_t* data() const { return data_; }
  std::vector<uint8_t> to_vector() const;

 private:
  void allocate(size_t size);
  void release();
  void lock_pages();
  void unlock_pages();

  uint8_t* data_ = nullptr;
  size_t size_ = 0;
};

} // namespace cipheator
