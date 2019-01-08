#include "sha256.hpp"

namespace crypto::sha256 {

hash_algorithm::digest_t hash_algorithm::get_digest(void) {
  digest_t digest;

  std::size_t byte_offset = 0;

  for (std::uint32_t hash_uint32 : _digest_wip) {
    digest[byte_offset] = std::byte(hash_uint32 >> 24);
    digest[++byte_offset] = std::byte(hash_uint32 >> 16);
    digest[++byte_offset] = std::byte(hash_uint32 >> 8);
    digest[++byte_offset] = std::byte(hash_uint32);
    byte_offset += 1;
  }
  return digest;
}

} // namespace crypto::sha256
