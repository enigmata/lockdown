#ifndef __SHA256_HPP__
#define __SHA256_HPP__ 1

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace crypto::sha256 {

const std::size_t BLOCK_SIZE_BYTES = 64;

class hash_algorithm {
public:
  static const std::size_t digest_size_bytes = 32;

  using digest_t = std::array<std::byte, digest_size_bytes>;

  void hash_data(std::string_view){};

  digest_t get_digest(void);

  void reset(){};

private:
  std::array<std::byte, BLOCK_SIZE_BYTES> _underflow;
  std::array<std::uint32_t, digest_size_bytes / sizeof(std::uint32_t)>
      _digest_wip;
};

} // namespace crypto::sha256

#endif
