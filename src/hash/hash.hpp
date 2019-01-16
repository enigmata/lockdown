#ifndef __HASH_HPP__
#define __HASH_HPP__ 1

#include <array>
#include <cstddef>
#include <string_view>

namespace crypto {

template <class Algorithm> class hash {
public:
  using digest_t = std::array<std::byte, Algorithm::digest_size_bytes>;

  hash &operator<<(std::string_view in_data) {
    _algorithm.hash_data(in_data);
    return *this;
  };

  hash &operator>>(digest_t &out_digest) {
    out_digest = _algorithm.get_digest();
    return *this;
  };

  digest_t get_digest() { return _algorithm.get_digest(); }

  void reset() { _algorithm.reset(); };

private:
  Algorithm _algorithm;
};

} // namespace crypto

#endif
