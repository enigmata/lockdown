#ifndef __SHA256_HPP__
#define __SHA256_HPP__ 1

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace crypto::sha256 {

const std::size_t BLOCK_SIZE_BYTES = 64;
const std::size_t DIGEST_SIZE_BYTES = 32;
const std::size_t DIGEST_SIZE_UINT32 =
    DIGEST_SIZE_BYTES / sizeof(std::uint32_t);
const std::array<std::uint32_t, DIGEST_SIZE_UINT32> DIGEST_INITIAL_VALS{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

class hash_algorithm {
public:
  static const std::size_t digest_size_bytes = DIGEST_SIZE_BYTES;

  using digest_t = std::array<std::byte, digest_size_bytes>;

  hash_algorithm(void) { reset(); };

  void hash_data(std::string_view){};

  digest_t get_digest(void);

  void reset(void) { _digest_wip = DIGEST_INITIAL_VALS; };

private:
  std::array<std::byte, BLOCK_SIZE_BYTES> _underflow;
  std::array<std::uint32_t, DIGEST_SIZE_UINT32> _digest_wip;
};

} // namespace crypto::sha256

#endif
