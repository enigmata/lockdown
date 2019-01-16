#include <cstdio>
#include <variant>

#include "hash.hpp"
#include "sha256/sha256.hpp"

using namespace crypto;
using B = std::byte;
using hash_algorithms_t = std::variant<hash<sha256::hash_algorithm>>;

struct testcase_t {
  hash_algorithms_t hash_algorithm;
  std::string_view string;
  sha256::hash_algorithm::digest_t digest;
};

hash<sha256::hash_algorithm> sha256_hash;

std::array<testcase_t, 4> testcases{
    {{hash<sha256::hash_algorithm>(),
      "",
      {B{0xe3}, B{0xb0}, B{0xc4}, B{0x42}, B{0x98}, B{0xfc}, B{0x1c}, B{0x14},
       B{0x9a}, B{0xfb}, B{0xf4}, B{0xc8}, B{0x99}, B{0x6f}, B{0xb9}, B{0x24},
       B{0x27}, B{0xae}, B{0x41}, B{0xe4}, B{0x64}, B{0x9b}, B{0x93}, B{0x4c},
       B{0xa4}, B{0x95}, B{0x99}, B{0x1b}, B{0x78}, B{0x52}, B{0xb8}, B{0x55}}},
     {hash<sha256::hash_algorithm>(),
      "a",
      {B{0xca}, B{0x97}, B{0x81}, B{0x12}, B{0xca}, B{0x1b}, B{0xbd}, B{0xca},
       B{0xfa}, B{0xc2}, B{0x31}, B{0xb3}, B{0x9a}, B{0x23}, B{0xdc}, B{0x4d},
       B{0xa7}, B{0x86}, B{0xef}, B{0xf8}, B{0x14}, B{0x7c}, B{0x4e}, B{0x72},
       B{0xb9}, B{0x80}, B{0x77}, B{0x85}, B{0xaf}, B{0xee}, B{0x48}, B{0xbb}}},
     {hash<sha256::hash_algorithm>(),
      "bmWgj6pFf2NWRPGJaZTq naxmTjVYhnJbZbYy9Ux3 pJeNuO3J4dE7b75HkoMM 8",
      {B{0x60}, B{0x16}, B{0x81}, B{0x6b}, B{0xf6}, B{0x7a}, B{0xdd}, B{0x89},
       B{0x75}, B{0x48}, B{0xd5}, B{0xbc}, B{0xa4}, B{0xa8}, B{0xa3}, B{0xef},
       B{0xfc}, B{0x5d}, B{0x21}, B{0x7c}, B{0xdb}, B{0x92}, B{0x79}, B{0x5e},
       B{0x79}, B{0xbe}, B{0xb3}, B{0x5d}, B{0x31}, B{0xe3}, B{0x47}, B{0xf9}}},
     {hash<sha256::hash_algorithm>(),
      "SHe9a6$evjFzdyowF#hzzMmlZwRbclm2!!4oy5j7IdALLY06Abl9VyRjR7H*^"
      "RRlZ0PjgIJQ9sAC_-KoB10YqYjx3HcqvUWF%$@nax8OrRj5KPJ",
      {B{0xaa}, B{0x48}, B{0xc0}, B{0xbb}, B{0x3a}, B{0x04}, B{0xfb},
       B{0x7d}, B{0xa9}, B{0xc6}, B{0x3c}, B{0x6a}, B{0x81}, B{0x05},
       B{0x3b}, B{0xe2}, B{0x25}, B{0x26}, B{0xa6}, B{0xc1}, B{0x2c},
       B{0xd7}, B{0xf4}, B{0x92}, B{0x97}, B{0xa9}, B{0x47}, B{0x45},
       B{0xfe}, B{0x29}, B{0xc3}, B{0x34}}}}};

int main(int argc, char *argv[]) {
  int rc = 0;
  std::size_t tcnum = 0, tctotal = testcases.size();

  if (argc > 1) {
    int requested_tcnum = std::atoi(argv[1]);
    if (requested_tcnum < 1 || std::size_t(requested_tcnum) > tctotal) {
      std::printf("\nERROR: Requested testcase number was out of range. Valid "
                  "range is [1-%lu].\n",
                  tctotal);
      std::printf("USAGE: hash_test [testcase#]\n");
      std::printf("NOTE: Do not provide a testcase number in order to run all "
                  "testcases.\n");
      return -1;
    }
    tctotal = (std::size_t)requested_tcnum;
    tcnum = tctotal - 1;
    std::printf("\nTestcase (selected 1 out of %lu):\n", testcases.size());
  } else {
    std::printf("\nTestcases (%lu):\n", tctotal);
  }

  for (; tcnum < tctotal; ++tcnum) {
    std::visit(
        [&tc = testcases[tcnum], &tcnum, &rc](auto &&algorithm) {
          algorithm << tc.string;

          std::printf("%04lu: ", tcnum + 1);
          if (tc.digest == algorithm.get_digest()) {
            std::printf("passed");
          } else {
            std::printf("failed");
            rc = -1;
          }
          std::printf(" \"%s\"\n", tc.string.data());
        },
        testcases[tcnum].hash_algorithm);
  }

  return rc;
}
