#ifndef __SHA_HPP__
#define __SHA_HPP__ 1

#include <bitset>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <tuple>

#include "sha_constants.hpp"

namespace crypto::sha {

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
class algorithm {
public:
  using digest_t = std::array<std::byte, digest_size>;

  static const std::size_t digest_size_bytes = digest_size;

  algorithm() { reset(); };

  constexpr std::size_t get_digest_size() const { return digest_size; };

  void hash_data(std::byte *data_ptr, std::size_t data_len);

  digest_t get_digest(void);

  void reset(void) {
    _digest_wip = get_digest_init_vals<uint_t, digest_size, block_size>();
    _len_data_hashed = _len_underflow = 0;
  };

private:
  std::array<std::byte, block_size> _underflow;
  std::array<uint_t, DIGEST_SIZE_UINT> _digest_wip;
  std::uint64_t _len_data_hashed;
  std::size_t _len_underflow;

  void _hash_blocks(std::byte *data_ptr, std::size_t data_len);
};

using sha256_hash =
    algorithm<std::uint32_t, SHA256_DIGEST_SIZE, SHA256FAMILY_BLOCK_SIZE>;
using sha256_224_hash =
    algorithm<std::uint32_t, SHA224_DIGEST_SIZE, SHA256FAMILY_BLOCK_SIZE>;

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
std::array<std::byte, digest_size>
algorithm<uint_t, digest_size, block_size>::get_digest(void) {
  std::byte padding[block_size];
  std::uint64_t len_bits = _len_data_hashed << 3;

  std::memset(padding, 0, block_size);
  padding[0] = std::byte(0x80);

  std::int32_t pad_len = 56 - (_len_data_hashed % block_size);

  if (pad_len <= 0)
    pad_len += block_size;
  hash_data(padding, pad_len);

  padding[0] = std::byte(len_bits >> 56);
  padding[1] = std::byte(len_bits >> 48);
  padding[2] = std::byte(len_bits >> 40);
  padding[3] = std::byte(len_bits >> 32);
  padding[4] = std::byte(len_bits >> 24);
  padding[5] = std::byte(len_bits >> 16);
  padding[6] = std::byte(len_bits >> 8);
  padding[7] = std::byte(len_bits);

  hash_data(padding, 8);

  assert(_len_underflow == 0);

  constexpr std::size_t family_digest_size = block_size / 2;
  std::array<std::byte, family_digest_size> family_digest;
  std::size_t byte_offset = sizeof(uint_t) - 1;

  for (uint_t hash_uint : _digest_wip) {
    family_digest[byte_offset] = std::byte(hash_uint);
    family_digest[byte_offset - 1] = std::byte(hash_uint >> 8);
    family_digest[byte_offset - 2] = std::byte(hash_uint >> 16);
    family_digest[byte_offset - 3] = std::byte(hash_uint >> 24);
    byte_offset += sizeof(uint_t);
  }

  if constexpr (family_digest_size == digest_size) {
    return family_digest;
  } else {
    digest_t digest;
    std::memcpy(digest.data(), family_digest.data(), digest_size);
    return digest;
  }
};

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
void algorithm<uint_t, digest_size, block_size>::hash_data(
    std::byte *data_ptr, std::size_t data_len) {

  if (data_len == 0 || data_ptr == nullptr)
    return;

  using bits64 = std::bitset<64>;

  std::size_t bytes_processed = 0;

  _len_data_hashed += data_len;

  if (_len_underflow > 0) {
    std::size_t underflow_capacity = block_size - _len_underflow;
    bytes_processed =
        (data_len >= underflow_capacity) ? underflow_capacity : data_len;

    std::memcpy(_underflow.data() + _len_underflow, data_ptr, bytes_processed);

    _len_underflow += bytes_processed;
    if (_len_underflow == block_size) {
      _hash_blocks(_underflow.data(), block_size);
      _len_underflow = 0;
    }
  }
  if (auto bytes_remaining = data_len - bytes_processed;
      bytes_remaining >= block_size) {
    std::size_t bytes_hashed =
        (bits64(bytes_remaining) & bits64(block_size - 1).flip()).to_ulong();
    _hash_blocks(data_ptr + bytes_processed, bytes_hashed);
    bytes_processed += bytes_hashed;
  }
  if (auto bytes_remaining = data_len - bytes_processed; bytes_remaining > 0) {
    std::memcpy(_underflow.data(), data_ptr + bytes_processed, bytes_remaining);

    _len_underflow = bytes_remaining;
  }

  return;
};

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
void algorithm<uint_t, digest_size, block_size>::_hash_blocks(
    std::byte *data_ptr, std::size_t data_len) {

  constexpr std::size_t family_digest_size = block_size / 2;
  const auto [_k, num_k] = get_block_constants<uint_t, block_size>();
  uint_t digest[DIGEST_SIZE_UINT];
  uint_t _d[DIGEST_SIZE_UINT];
  uint_t w[num_k];
  std::size_t i = 0, j = 0;
  uint_t v1 = 0, v2 = 0, t1 = 0, t2 = 0;
  enum { a, b, c, d, e, f, g, h };

  std::memcpy(digest, _digest_wip.data(), family_digest_size);

  while (data_len >= block_size) {

    for (i = 0; i < 16; i++) {
      j = i * sizeof(uint_t);
      w[i] = uint_t(data_ptr[j]) << 24 | uint_t(data_ptr[j + 1]) << 16 |
             uint_t(data_ptr[j + 2]) << 8 | uint_t(data_ptr[j + 3]);
    }
    for (i = 16; i < num_k; i++) {
      v1 = w[i - 2];
      t1 = (v1 >> 17 | v1 << 15) ^ (v1 >> 19 | v1 << 13) ^ (v1 >> 10);
      v2 = w[i - 15];
      t2 = (v2 >> 7 | v2 << 25) ^ (v2 >> 18 | v2 << 14) ^ (v2 >> 3);
      w[i] = t1 + w[i - 7] + t2 + w[i - 16];
    }

    std::memcpy(_d, digest, family_digest_size);

    for (i = 0; i < num_k; i++) {
      t1 = _d[h] +
           ((_d[e] >> 6 | _d[e] << 26) ^ (_d[e] >> 11 | _d[e] << 21) ^
            (_d[e] >> 25 | _d[e] << 7)) +
           ((_d[e] & _d[f]) ^ (~_d[e] & _d[g])) + _k[i] + w[i];

      t2 = ((_d[a] >> 2 | _d[a] << 30) ^ (_d[a] >> 13 | _d[a] << 19) ^
            (_d[a] >> 22 | _d[a] << 10)) +
           ((_d[a] & _d[b]) ^ (_d[a] & _d[c]) ^ (_d[b] & _d[c]));

      _d[h] = _d[g];
      _d[g] = _d[f];
      _d[f] = _d[e];
      _d[e] = _d[d] + t1;
      _d[d] = _d[c];
      _d[c] = _d[b];
      _d[b] = _d[a];
      _d[a] = t1 + t2;
    }

    digest[0] += _d[a];
    digest[1] += _d[b];
    digest[2] += _d[c];
    digest[3] += _d[d];
    digest[4] += _d[e];
    digest[5] += _d[f];
    digest[6] += _d[g];
    digest[7] += _d[h];

    data_ptr += block_size;
    data_len -= block_size;
  }

  std::memcpy(_digest_wip.data(), digest, family_digest_size);

  return;
};

}; // namespace crypto::sha
#endif
