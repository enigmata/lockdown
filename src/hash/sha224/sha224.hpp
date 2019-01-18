#ifndef __SHA224_HPP__
#define __SHA224_HPP__ 1

#include <cstring>

#include "../sha256/sha256.hpp"

namespace crypto::sha224 {

const std::size_t DIGEST_SIZE_BYTES = 28;
const std::size_t DIGEST_SIZE_UINT32 =
    crypto::sha256::DIGEST_SIZE_BYTES / sizeof(std::uint32_t);
const std::array<std::uint32_t, DIGEST_SIZE_UINT32> DIGEST_INITIAL_VALS{
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
    0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4};

class hash_algorithm : public crypto::sha256::hash_algorithm {
public:
  static const std::size_t digest_size_bytes = DIGEST_SIZE_BYTES;

  using digest_t = std::array<std::byte, DIGEST_SIZE_BYTES>;
  using digest_sha256_t =
      std::array<std::byte, crypto::sha256::DIGEST_SIZE_BYTES>;

  hash_algorithm(void) { reset(); };

  digest_t get_digest(void) {
    digest_sha256_t d256 = _get_digest();
    digest_t d224;
    std::memcpy(d224.data(), d256.data(), DIGEST_SIZE_BYTES);
    return d224;
  };

  void reset(void) {
    _digest_wip = DIGEST_INITIAL_VALS;
    _len_data_hashed = _len_underflow = 0;
  };
};

} // namespace crypto::sha224

#endif
