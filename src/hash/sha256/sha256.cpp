#include "sha256.hpp"

#include <bitset>
#include <cassert>
#include <cstring>

namespace crypto::sha256 {

using bits64 = std::bitset<64>;

hash_algorithm::digest_t hash_algorithm::_get_digest(void) {
  digest_t digest;
  std::byte padding[BLOCK_SIZE_BYTES];
  std::uint64_t len_bits = _len_data_hashed << 3;

  std::memset(padding, 0, BLOCK_SIZE_BYTES);
  padding[0] = std::byte(0x80);

  std::int32_t pad_len = 56 - (_len_data_hashed % BLOCK_SIZE_BYTES);

  if (pad_len <= 0)
    pad_len += BLOCK_SIZE_BYTES;
  _hash_data(padding, pad_len);

  padding[0] = std::byte(len_bits >> 56);
  padding[1] = std::byte(len_bits >> 48);
  padding[2] = std::byte(len_bits >> 40);
  padding[3] = std::byte(len_bits >> 32);
  padding[4] = std::byte(len_bits >> 24);
  padding[5] = std::byte(len_bits >> 16);
  padding[6] = std::byte(len_bits >> 8);
  padding[7] = std::byte(len_bits);

  _hash_data(padding, 8);

  assert(_len_underflow == 0);

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

void hash_algorithm::_hash_data(std::byte *data_ptr, std::size_t data_len) {
  if (data_len == 0)
    return;

  std::size_t bytes_processed = 0;

  _len_data_hashed += data_len;

  if (_len_underflow > 0) {
    std::size_t underflow_capacity = UNDERFLOW_MAXSIZE_BYTES - _len_underflow;
    bytes_processed =
        (data_len >= underflow_capacity) ? underflow_capacity : data_len;

    std::memcpy(_underflow.data() + _len_underflow, data_ptr, bytes_processed);

    _len_underflow += bytes_processed;
    if (_len_underflow == BLOCK_SIZE_BYTES) {
      _hash_blocks(_underflow.data(), BLOCK_SIZE_BYTES, _digest_wip.data());
      _len_underflow = 0;
    }
  }
  if (auto bytes_remaining = data_len - bytes_processed;
      bytes_remaining >= BLOCK_SIZE_BYTES) {
    std::size_t bytes_hashed =
        (bits64(bytes_remaining) & bits64(BLOCK_SIZE_BYTES - 1).flip())
            .to_ulong();
    _hash_blocks(data_ptr + bytes_processed, bytes_hashed, _digest_wip.data());
    bytes_processed += bytes_hashed;
  }
  if (auto bytes_remaining = data_len - bytes_processed; bytes_remaining > 0) {
    std::memcpy(_underflow.data(), data_ptr + bytes_processed, bytes_remaining);

    _len_underflow = bytes_remaining;
  }

  return;
}

} // namespace crypto::sha256
