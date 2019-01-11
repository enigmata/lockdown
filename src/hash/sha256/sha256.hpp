#ifndef __SHA256_HPP__
#define __SHA256_HPP__ 1

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace crypto::sha256 {

const std::size_t BLOCK_SIZE_BYTES = 64;
const std::size_t UNDERFLOW_MAXSIZE_BYTES = BLOCK_SIZE_BYTES;
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

  void hash_data(std::string_view str) {
    if (str.length() > 0)
      _hash_data((std::byte *)(str.data()),
                 str.length() * sizeof(std::string_view::value_type));
  };

  digest_t get_digest(void);

  void reset(void) {
    _digest_wip = DIGEST_INITIAL_VALS;
    _len_data_hashed = _len_underflow = 0;
  };

private:
  void _hash_blocks(std::byte *, std::size_t);
  void _hash_data(std::byte *, std::size_t);

  std::array<std::byte, UNDERFLOW_MAXSIZE_BYTES> _underflow;
  std::array<std::uint32_t, DIGEST_SIZE_UINT32> _digest_wip;
  std::uint64_t _len_data_hashed;
  std::size_t _len_underflow;
};

} // namespace crypto::sha256

#endif
