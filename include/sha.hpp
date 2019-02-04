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

  algorithm() noexcept { reset(); };

  constexpr std::size_t get_digest_size() const noexcept {
    return digest_size;
  };

  void hash_data(std::byte *data_ptr, std::size_t data_len) noexcept;

  digest_t get_digest(void) noexcept;

  void reset(void) noexcept {
    _digest_wip = get_digest_init_vals<uint_t, digest_size, block_size>();
    _len_data_hashed = _len_underflow = 0;
  };

private:
  std::array<std::byte, block_size> _underflow;
  std::array<uint_t, DIGEST_SIZE_UINT> _digest_wip;
  std::uint64_t _len_data_hashed;
  std::size_t _len_underflow;

  void _hash_blocks(std::byte *data_ptr, std::size_t data_len) noexcept;
};

using sha224_hash = algorithm<SHA256FAMILY_WORD_SIZE, SHA224_DIGEST_SIZE,
                              SHA256FAMILY_BLOCK_SIZE>;
using sha256_hash = algorithm<SHA256FAMILY_WORD_SIZE, SHA256_DIGEST_SIZE,
                              SHA256FAMILY_BLOCK_SIZE>;
using sha384_hash = algorithm<SHA512FAMILY_WORD_SIZE, SHA384_DIGEST_SIZE,
                              SHA512FAMILY_BLOCK_SIZE>;
using sha512_hash = algorithm<SHA512FAMILY_WORD_SIZE, SHA512_DIGEST_SIZE,
                              SHA512FAMILY_BLOCK_SIZE>;
using sha512_224_hash = algorithm<SHA512FAMILY_WORD_SIZE, SHA224_DIGEST_SIZE,
                                  SHA512FAMILY_BLOCK_SIZE>;
using sha512_256_hash = algorithm<SHA512FAMILY_WORD_SIZE, SHA256_DIGEST_SIZE,
                                  SHA512FAMILY_BLOCK_SIZE>;

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
std::array<std::byte, digest_size>
algorithm<uint_t, digest_size, block_size>::get_digest(void) noexcept {
  std::byte padding[block_size];
  std::uint64_t len_bits = _len_data_hashed << 3;

  std::memset(padding, 0, block_size);
  padding[0] = std::byte(0x80);

  constexpr std::int32_t pad_len_placeholder = block_size - (block_size / 8);
  std::int32_t pad_len = pad_len_placeholder - (_len_data_hashed % block_size);

  if (pad_len <= 0)
    pad_len += block_size;
  hash_data(padding, pad_len);

  std::size_t byte_offset = 0;

  if constexpr ((block_size / 8) / sizeof(_len_data_hashed) > 1) {
    std::memset(padding, 0, sizeof(_len_data_hashed));
    byte_offset = sizeof(_len_data_hashed);
  }

  padding[byte_offset] = std::byte(len_bits >> 56);
  padding[++byte_offset] = std::byte(len_bits >> 48);
  padding[++byte_offset] = std::byte(len_bits >> 40);
  padding[++byte_offset] = std::byte(len_bits >> 32);
  padding[++byte_offset] = std::byte(len_bits >> 24);
  padding[++byte_offset] = std::byte(len_bits >> 16);
  padding[++byte_offset] = std::byte(len_bits >> 8);
  padding[++byte_offset] = std::byte(len_bits);

  hash_data(padding, byte_offset + 1);

  assert(_len_underflow == 0);

  constexpr std::size_t family_digest_size = block_size / 2;
  std::array<std::byte, family_digest_size> family_digest;
  byte_offset = sizeof(uint_t) - 1;

  for (uint_t hash_uint : _digest_wip) {
    family_digest[byte_offset] = std::byte(hash_uint);
    family_digest[byte_offset - 1] = std::byte(hash_uint >> 8);
    family_digest[byte_offset - 2] = std::byte(hash_uint >> 16);
    family_digest[byte_offset - 3] = std::byte(hash_uint >> 24);
    if constexpr (sizeof(uint_t) == 8) {
      family_digest[byte_offset - 4] = std::byte(hash_uint >> 32);
      family_digest[byte_offset - 5] = std::byte(hash_uint >> 40);
      family_digest[byte_offset - 6] = std::byte(hash_uint >> 48);
      family_digest[byte_offset - 7] = std::byte(hash_uint >> 56);
    }
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
    std::byte *data_ptr, std::size_t data_len) noexcept {

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
    std::byte *data_ptr, std::size_t data_len) noexcept {

  constexpr std::size_t family_digest_size = block_size / 2;
  const auto [_k, num_rounds] = get_block_constants<uint_t, block_size>();
  uint_t digest[DIGEST_SIZE_UINT];
  uint_t _d[DIGEST_SIZE_UINT];
  uint_t w[num_rounds];
  std::size_t i = 0, j = 0;
  uint_t v1 = 0, v2 = 0, t1 = 0, t2 = 0;
  enum { a, b, c, d, e, f, g, h };

  std::memcpy(digest, _digest_wip.data(), family_digest_size);

  while (data_len >= block_size) {

    for (i = 0; i < 16; i++) {
      j = i * sizeof(uint_t);
      if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE) {
        w[i] = uint_t(data_ptr[j]) << 24 | uint_t(data_ptr[j + 1]) << 16 |
               uint_t(data_ptr[j + 2]) << 8 | uint_t(data_ptr[j + 3]);
      } else if (block_size == SHA512FAMILY_BLOCK_SIZE) {
        w[i] = uint_t(data_ptr[j]) << 56 | uint_t(data_ptr[j + 1]) << 48 |
               uint_t(data_ptr[j + 2]) << 40 | uint_t(data_ptr[j + 3]) << 32 |
               uint_t(data_ptr[j + 4]) << 24 | uint_t(data_ptr[j + 5]) << 16 |
               uint_t(data_ptr[j + 6]) << 8 | uint_t(data_ptr[j + 7]);
      }
    }
    for (i = 16; i < num_rounds; i++) {
      v1 = w[i - 2];
      if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE) {
        t1 = (v1 >> 17 | v1 << (32 - 17)) ^ (v1 >> 19 | v1 << (32 - 19)) ^
             (v1 >> 10);
      } else if (block_size == SHA512FAMILY_BLOCK_SIZE) {
        t1 = (v1 >> 19 | v1 << (64 - 19)) ^ (v1 >> 61 | v1 << (64 - 61)) ^
             (v1 >> 6);
      }
      v2 = w[i - 15];
      if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE) {
        t2 = (v2 >> 7 | v2 << (32 - 7)) ^ (v2 >> 18 | v2 << (32 - 18)) ^
             (v2 >> 3);
      } else if (block_size == SHA512FAMILY_BLOCK_SIZE) {
        t2 =
            (v2 >> 1 | v2 << (64 - 1)) ^ (v2 >> 8 | v2 << (64 - 8)) ^ (v2 >> 7);
      }
      w[i] = t1 + w[i - 7] + t2 + w[i - 16];
    }

    std::memcpy(_d, digest, family_digest_size);

    for (i = 0; i < num_rounds; i++) {
      if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE) {
        t1 = _d[h] +
             ((_d[e] >> 6 | _d[e] << (32 - 6)) ^
              (_d[e] >> 11 | _d[e] << (32 - 11)) ^
              (_d[e] >> 25 | _d[e] << (32 - 25))) +
             ((_d[e] & _d[f]) ^ (~_d[e] & _d[g])) + _k[i] + w[i];

        t2 = ((_d[a] >> 2 | _d[a] << (32 - 2)) ^
              (_d[a] >> 13 | _d[a] << (32 - 13)) ^
              (_d[a] >> 22 | _d[a] << (32 - 22))) +
             ((_d[a] & _d[b]) ^ (_d[a] & _d[c]) ^ (_d[b] & _d[c]));
      } else if (block_size == SHA512FAMILY_BLOCK_SIZE) {
        t1 = _d[h] +
             ((_d[e] >> 14 | _d[e] << (64 - 14)) ^
              (_d[e] >> 18 | _d[e] << (64 - 18)) ^
              (_d[e] >> 41 | _d[e] << (64 - 41))) +
             ((_d[e] & _d[f]) ^ (~_d[e] & _d[g])) + _k[i] + w[i];

        t2 = ((_d[a] >> 28 | _d[a] << (64 - 28)) ^
              (_d[a] >> 34 | _d[a] << (64 - 34)) ^
              (_d[a] >> 39 | _d[a] << (64 - 39))) +
             ((_d[a] & _d[b]) ^ (_d[a] & _d[c]) ^ (_d[b] & _d[c]));
      }

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
