#ifndef __SHA_CONSTANTS_HPP__
#define __SHA_CONSTANTS_HPP__ 1

#include <cstdint>

namespace crypto::sha {

enum block_sizes : std::size_t {
  SHA256FAMILY_BLOCK_SIZE = 64,
  SHA512FAMILY_BLOCK_SIZE = 128
};
enum digest_sizes : std::size_t {
  SHA224_DIGEST_SIZE = 28,
  SHA256_DIGEST_SIZE = 32,
  SHA512_DIGEST_SIZE = 64
};

using SHA256FAMILY_WORD_SIZE = std::uint32_t;
using SHA512FAMILY_WORD_SIZE = std::uint64_t;

constexpr std::size_t DIGEST_SIZE_UINT = 8;
constexpr std::size_t MAX_BLOCK_CONSTANTS = 80;
constexpr std::size_t SHA256FAMILY_ROUNDS = 64;
constexpr std::size_t SHA512FAMILY_ROUNDS = 80;

template <typename uint_t, std::size_t digest_size, std::size_t block_size>
constexpr std::array<uint_t, DIGEST_SIZE_UINT> get_digest_init_vals() {
  if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE &&
                digest_size == SHA256_DIGEST_SIZE) {
    return {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};
  } else if (block_size == SHA256FAMILY_BLOCK_SIZE &&
             digest_size == SHA224_DIGEST_SIZE) {
    return {0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
            0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4};
  } else if (block_size == SHA512FAMILY_BLOCK_SIZE &&
             digest_size == SHA512_DIGEST_SIZE) {
    return {uint_t(0x6a09e667f3bcc908), uint_t(0xbb67ae8584caa73b),
            uint_t(0x3c6ef372fe94f82b), uint_t(0xa54ff53a5f1d36f1),
            uint_t(0x510e527fade682d1), uint_t(0x9b05688c2b3e6c1f),
            uint_t(0x1f83d9abfb41bd6b), uint_t(0x5be0cd19137e2179)};
  } else if (block_size == SHA512FAMILY_BLOCK_SIZE &&
             digest_size == SHA224_DIGEST_SIZE) {
    return {uint_t(0x8c3d37c819544da2), uint_t(0x73e1996689dcd4d6),
            uint_t(0x1dfab7ae32ff9c82), uint_t(0x679dd514582f9fcf),
            uint_t(0x0f6d2b697bd44da8), uint_t(0x77e36f7304c48942),
            uint_t(0x3f9d85a86a1d36c8), uint_t(0x1112e6ad91d692a1)};
  } else if (block_size == SHA512FAMILY_BLOCK_SIZE &&
             digest_size == SHA256_DIGEST_SIZE) {
    return {uint_t(0x22312194fc2bf72c), uint_t(0x9f555fa3c84c64c2),
            uint_t(0x2393b86b6f53b151), uint_t(0x963877195940eabd),
            uint_t(0x96283ee2a88effe3), uint_t(0xbe5e1e2553863992),
            uint_t(0x2b0199fc2c85b8aa), uint_t(0x0eb72ddc81c52ca2)};
  }
};

template <typename uint_t, std::size_t block_size>
constexpr std::tuple<std::array<uint_t, MAX_BLOCK_CONSTANTS>, std::size_t>
get_block_constants() {
  if constexpr (block_size == SHA256FAMILY_BLOCK_SIZE) {
    return {std::array<std::uint32_t, MAX_BLOCK_CONSTANTS>{
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
                0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
                0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
                0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
                0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
                0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
                0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
                0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
                0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 0x0,
                0x0,        0x0,        0x0,        0x0,        0x0,
                0x0,        0x0,        0x0,        0x0,        0x0,
                0x0,        0x0,        0x0,        0x0,        0x0},
            SHA256FAMILY_ROUNDS};
  } else if (block_size == SHA512FAMILY_BLOCK_SIZE) {
    return {std::array<std::uint64_t, MAX_BLOCK_CONSTANTS>{
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
                0x5fcb6fab3ad6faec, 0x6c44198c4a475817},
            SHA512FAMILY_ROUNDS};
  }
};
} // namespace crypto::sha
#endif
