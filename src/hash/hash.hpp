#ifndef __HASH_HPP__
#define __HASH_HPP__ 1

#include <array>
#include <cstddef>
#include <string_view>

#include "sha/sha.hpp"

namespace crypto {

template <class Algorithm> class hash {
public:
  using digest_t = std::array<std::byte, Algorithm::digest_size_bytes>;

  hash &operator<<(std::string_view in_data) {
    _algorithm.hash_data((std::byte *)(in_data.data()),
                         in_data.length() *
                             sizeof(std::string_view::value_type));
    return *this;
  };

  hash &operator>>(digest_t &out_digest) {
    out_digest = get_digest();
    return *this;
  };

  digest_t get_digest() { return _algorithm.get_digest(); }

  void reset() { _algorithm.reset(); };

private:
  Algorithm _algorithm;
};

using sha512_hash = hash<crypto::sha::sha512_hash>;
using sha512_224_hash = hash<crypto::sha::sha512_224_hash>;
using sha512_256_hash = hash<crypto::sha::sha512_256_hash>;
using sha384_hash = hash<crypto::sha::sha384_hash>;
using sha256_hash = hash<crypto::sha::sha256_hash>;
using sha256_224_hash = hash<crypto::sha::sha256_224_hash>;

} // namespace crypto

#endif
