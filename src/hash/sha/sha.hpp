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

  algorithm() { reset(); };

  std::size_t get_digest_size() const { return digest_size; };

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

enum class hash_algorithm { sha256, sha512 };

enum num_constants : std::size_t {
  sha256_num_const = 64,
  sha512_num_const = 80
};

const std::array<std::uint32_t, sha256_num_const> _sha256_constants{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
const std::array<std::uint64_t, sha512_num_const> _sha512_constants{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static const std::tuple<const std::array<std::uint32_t, sha256_num_const> &,
                        const std::array<std::uint64_t, sha512_num_const> &>
    _sha_constants(_sha256_constants, _sha512_constants);

template <typename int_type, hash_algorithm algorithm, std::size_t digest_size,
          std::size_t block_size>
struct hash_blocks {

  void operator()(std::byte *data_ptr, std::size_t data_len,
                  int_type *_digest_wip) {
    int_type digest[digest_size / sizeof(int_type)];
    int_type _d[digest_size / sizeof(int_type)];
    const auto _k = std::get<int(algorithm)>(_sha_constants);
    const std::size_t num_constants = _k.size();
    int_type w[num_constants];
    std::size_t i = 0, j = 0;
    int_type v1 = 0, v2 = 0, t1 = 0, t2 = 0;
    enum { a, b, c, d, e, f, g, h };

    std::memcpy(digest, _digest_wip, digest_size);

    while (data_len >= block_size) {
      for (i = 0; i < 16; i++) {
        j = i * sizeof(int_type);
        if constexpr (algorithm == hash_algorithm::sha256) {
          w[i] = std::uint32_t(data_ptr[j]) << 24 |
                 std::uint32_t(data_ptr[j + 1]) << 16 |
                 std::uint32_t(data_ptr[j + 2]) << 8 |
                 std::uint32_t(data_ptr[j + 3]);
        }
      }
      for (i = 16; i < num_constants; i++) {
        if constexpr (algorithm == hash_algorithm::sha256) {
          v1 = w[i - 2];
          t1 = (v1 >> 17 | v1 << 15) ^ (v1 >> 19 | v1 << 13) ^ (v1 >> 10);
          v2 = w[i - 15];
          t2 = (v2 >> 7 | v2 << 25) ^ (v2 >> 18 | v2 << 14) ^ (v2 >> 3);
          w[i] = t1 + w[i - 7] + t2 + w[i - 16];
        }
      }

      std::memcpy(_d, digest, digest_size);

      for (i = 0; i < num_constants; i++) {
        if constexpr (algorithm == hash_algorithm::sha256) {
          t1 = _d[h] +
               ((_d[e] >> 6 | _d[e] << 26) ^ (_d[e] >> 11 | _d[e] << 21) ^
                (_d[e] >> 25 | _d[e] << 7)) +
               ((_d[e] & _d[f]) ^ (~_d[e] & _d[g])) + _k[i] + w[i];

          t2 = ((_d[a] >> 2 | _d[a] << 30) ^ (_d[a] >> 13 | _d[a] << 19) ^
                (_d[a] >> 22 | _d[a] << 10)) +
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

    std::memcpy(_digest_wip, digest, digest_size);

    return;
  }
};
}; // namespace crypto::sha
#endif
