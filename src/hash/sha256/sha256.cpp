#include "sha256.hpp"

#include <bitset>
#include <cassert>
#include <cstring>

namespace crypto::sha256 {

using bits64 = std::bitset<64>;

hash_algorithm::digest_t hash_algorithm::get_digest(void) {
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
      _hash_blocks(_underflow.data(), BLOCK_SIZE_BYTES);
      _len_underflow = 0;
    }
  }
  if (auto bytes_remaining = data_len - bytes_processed;
      bytes_remaining >= BLOCK_SIZE_BYTES) {
    std::size_t bytes_hashed =
        (bits64(bytes_remaining) & bits64(BLOCK_SIZE_BYTES - 1).flip())
            .to_ulong();
    _hash_blocks(data_ptr + bytes_processed, bytes_hashed);
    bytes_processed += bytes_hashed;
  }
  if (auto bytes_remaining = data_len - bytes_processed; bytes_remaining > 0) {
    std::memcpy(_underflow.data(), data_ptr + bytes_processed, bytes_remaining);

    _len_underflow = bytes_remaining;
  }

  return;
}

const std::uint32_t _k[64]{
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

void hash_algorithm::_hash_blocks(std::byte *data_ptr, std::size_t data_len) {
  std::uint32_t digest[DIGEST_SIZE_UINT32];
  std::uint32_t _d[DIGEST_SIZE_UINT32];
  std::uint32_t w[64];
  std::size_t i = 0, j = 0;
  std::uint32_t v1 = 0, v2 = 0, t1 = 0, t2 = 0;
  enum { a, b, c, d, e, f, g, h };

  std::memcpy(digest, _digest_wip.data(), DIGEST_SIZE_BYTES);

  while (data_len >= BLOCK_SIZE_BYTES) {

    for (i = 0; i < 16; i++) {
      j = i * 4;
      w[i] = std::uint32_t(data_ptr[j]) << 24 |
             std::uint32_t(data_ptr[j + 1]) << 16 |
             std::uint32_t(data_ptr[j + 2]) << 8 |
             std::uint32_t(data_ptr[j + 3]);
    }
    for (i = 16; i < 64; i++) {
      v1 = w[i - 2];
      t1 = (v1 >> 17 | v1 << 15) ^ (v1 >> 19 | v1 << 13) ^ (v1 >> 10);
      v2 = w[i - 15];
      t2 = (v2 >> 7 | v2 << 25) ^ (v2 >> 18 | v2 << 14) ^ (v2 >> 3);
      w[i] = t1 + w[i - 7] + t2 + w[i - 16];
    }

    std::memcpy(_d, digest, DIGEST_SIZE_BYTES);

    for (i = 0; i < 64; i++) {
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

    data_ptr += BLOCK_SIZE_BYTES;
    data_len -= BLOCK_SIZE_BYTES;
  }

  std::memcpy(_digest_wip.data(), digest, DIGEST_SIZE_BYTES);

  return;
}

} // namespace crypto::sha256
