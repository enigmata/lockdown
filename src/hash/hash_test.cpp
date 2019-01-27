#include <algorithm>
#include <cstdio>
#include <variant>
#include <vector>

#include "hash.hpp"

using namespace crypto;
using B = std::byte;
using hash_algorithms_t = std::variant<sha256_hash, sha256_224_hash>;

struct testcase_t {
  hash_algorithms_t hash_algorithm;
  std::string_view string;
  std::vector<std::byte> digest;
};

std::array<testcase_t, 7> testcases{
    {{sha256_hash(),
      "",
      {B{0xe3}, B{0xb0}, B{0xc4}, B{0x42}, B{0x98}, B{0xfc}, B{0x1c}, B{0x14},
       B{0x9a}, B{0xfb}, B{0xf4}, B{0xc8}, B{0x99}, B{0x6f}, B{0xb9}, B{0x24},
       B{0x27}, B{0xae}, B{0x41}, B{0xe4}, B{0x64}, B{0x9b}, B{0x93}, B{0x4c},
       B{0xa4}, B{0x95}, B{0x99}, B{0x1b}, B{0x78}, B{0x52}, B{0xb8}, B{0x55}}},
     {sha256_hash(),
      "a",
      {B{0xca}, B{0x97}, B{0x81}, B{0x12}, B{0xca}, B{0x1b}, B{0xbd}, B{0xca},
       B{0xfa}, B{0xc2}, B{0x31}, B{0xb3}, B{0x9a}, B{0x23}, B{0xdc}, B{0x4d},
       B{0xa7}, B{0x86}, B{0xef}, B{0xf8}, B{0x14}, B{0x7c}, B{0x4e}, B{0x72},
       B{0xb9}, B{0x80}, B{0x77}, B{0x85}, B{0xaf}, B{0xee}, B{0x48}, B{0xbb}}},
     {sha256_hash(),
      "bmWgj6pFf2NWRPGJaZTq naxmTjVYhnJbZbYy9Ux3 pJeNuO3J4dE7b75HkoMM 8",
      {B{0x60}, B{0x16}, B{0x81}, B{0x6b}, B{0xf6}, B{0x7a}, B{0xdd}, B{0x89},
       B{0x75}, B{0x48}, B{0xd5}, B{0xbc}, B{0xa4}, B{0xa8}, B{0xa3}, B{0xef},
       B{0xfc}, B{0x5d}, B{0x21}, B{0x7c}, B{0xdb}, B{0x92}, B{0x79}, B{0x5e},
       B{0x79}, B{0xbe}, B{0xb3}, B{0x5d}, B{0x31}, B{0xe3}, B{0x47}, B{0xf9}}},
     {sha256_hash(),
      "SHe9a6$evjFzdyowF#hzzMmlZwRbclm2!!4oy5j7IdALLY06Abl9VyRjR7H*^"
      "RRlZ0PjgIJQ9sAC_-KoB10YqYjx3HcqvUWF%$@nax8OrRj5KPJ",
      {B{0xaa}, B{0x48}, B{0xc0}, B{0xbb}, B{0x3a}, B{0x04}, B{0xfb}, B{0x7d},
       B{0xa9}, B{0xc6}, B{0x3c}, B{0x6a}, B{0x81}, B{0x05}, B{0x3b}, B{0xe2},
       B{0x25}, B{0x26}, B{0xa6}, B{0xc1}, B{0x2c}, B{0xd7}, B{0xf4}, B{0x92},
       B{0x97}, B{0xa9}, B{0x47}, B{0x45}, B{0xfe}, B{0x29}, B{0xc3}, B{0x34}}},
     {sha256_224_hash(),
      "abcdefghij",
      {B{0xd3}, B{0x5e}, B{0x1e}, B{0x5a}, B{0xf2}, B{0x9d}, B{0xdb},
       B{0x0d}, B{0x7e}, B{0x15}, B{0x43}, B{0x57}, B{0xdf}, B{0x4a},
       B{0xd9}, B{0x84}, B{0x2a}, B{0xfe}, B{0xe5}, B{0x27}, B{0xc6},
       B{0x89}, B{0xee}, B{0x54}, B{0x7f}, B{0x75}, B{0x31}, B{0x88}}},
     {sha256_224_hash(),
      "How can you write a big system without C++?  -Paul Glick",
      {B{0x86}, B{0xed}, B{0x2e}, B{0xaa}, B{0x9c}, B{0x75}, B{0xba},
       B{0x98}, B{0x39}, B{0x6e}, B{0x5c}, B{0x9f}, B{0xb2}, B{0xf6},
       B{0x79}, B{0xec}, B{0xf0}, B{0xea}, B{0x2e}, B{0xd1}, B{0xe0},
       B{0xee}, B{0x9c}, B{0xee}, B{0xcb}, B{0x4a}, B{0x93}, B{0x32}}},
     {sha256_224_hash(),
      "6RT5wsQLCmYRFUn1kkoRV4tc9PEbq3o6hLz4NWlJymG5D9MJ12dUR7FwoPi07a2",
      {B{0x6e}, B{0xa7}, B{0xb2}, B{0xc4}, B{0xac}, B{0xec}, B{0xb2},
       B{0xd3}, B{0x7b}, B{0x16}, B{0x07}, B{0xa8}, B{0x16}, B{0xd6},
       B{0x67}, B{0x1a}, B{0xd2}, B{0x70}, B{0xa5}, B{0x7e}, B{0xfb},
       B{0x62}, B{0x17}, B{0xf9}, B{0xd9}, B{0xe1}, B{0x22}, B{0x47}}}}};

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
          auto digest = algorithm.get_digest();
          if (std::equal(tc.digest.begin(), tc.digest.end(), digest.begin())) {
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
