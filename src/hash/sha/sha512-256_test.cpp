#include <cstdio>
#include <cstdlib>
#include <optional>

#include "sha.hpp"
#include "sha_test.hpp"

using B = std::byte;
const std::size_t NUM_TESTCASES = 16;
const testcases_t<crypto::sha::sha512_256_hash, NUM_TESTCASES> testcases{
    {{"",
      {B{0xc6}, B{0x72}, B{0xb8}, B{0xd1}, B{0xef}, B{0x56}, B{0xed}, B{0x28},
       B{0xab}, B{0x87}, B{0xc3}, B{0x62}, B{0x2c}, B{0x51}, B{0x14}, B{0x06},
       B{0x9b}, B{0xdd}, B{0x3a}, B{0xd7}, B{0xb8}, B{0xf9}, B{0x73}, B{0x74},
       B{0x98}, B{0xd0}, B{0xc0}, B{0x1e}, B{0xce}, B{0xf0}, B{0x96}, B{0x7a}}},
     {"a",
      {B{0x45}, B{0x5e}, B{0x51}, B{0x88}, B{0x24}, B{0xbc}, B{0x06}, B{0x01},
       B{0xf9}, B{0xfb}, B{0x85}, B{0x8f}, B{0xf5}, B{0xc3}, B{0x7d}, B{0x41},
       B{0x7d}, B{0x67}, B{0xc2}, B{0xf8}, B{0xe0}, B{0xdf}, B{0x2b}, B{0xab},
       B{0xe4}, B{0x80}, B{0x88}, B{0x58}, B{0xae}, B{0xa8}, B{0x30}, B{0xf8}}},
     {"ab",
      {B{0x22}, B{0xd4}, B{0xd3}, B{0x7e}, B{0xc6}, B{0x37}, B{0x05}, B{0x71},
       B{0xaf}, B{0x71}, B{0x09}, B{0xfb}, B{0x12}, B{0xea}, B{0xe7}, B{0x96},
       B{0x73}, B{0xd5}, B{0xf7}, B{0xc8}, B{0x3e}, B{0x6e}, B{0x67}, B{0x70},
       B{0x83}, B{0xfa}, B{0xa3}, B{0xcf}, B{0xac}, B{0x3b}, B{0x2c}, B{0x14}}},
     {"abc",
      {B{0x53}, B{0x04}, B{0x8e}, B{0x26}, B{0x81}, B{0x94}, B{0x1e}, B{0xf9},
       B{0x9b}, B{0x2e}, B{0x29}, B{0xb7}, B{0x6b}, B{0x4c}, B{0x7d}, B{0xab},
       B{0xe4}, B{0xc2}, B{0xd0}, B{0xc6}, B{0x34}, B{0xfc}, B{0x6d}, B{0x46},
       B{0xe0}, B{0xe2}, B{0xf1}, B{0x31}, B{0x07}, B{0xe7}, B{0xaf}, B{0x23}}},
     {"abcd",
      {B{0xd2}, B{0x89}, B{0x1c}, B{0x79}, B{0x78}, B{0xbe}, B{0x0e}, B{0x24},
       B{0x94}, B{0x8f}, B{0x37}, B{0xca}, B{0xa4}, B{0x15}, B{0xb8}, B{0x7c},
       B{0xb5}, B{0xcb}, B{0xe2}, B{0xb2}, B{0x6b}, B{0x7b}, B{0xad}, B{0x9d},
       B{0xc6}, B{0x39}, B{0x1b}, B{0x8a}, B{0x6f}, B{0x6d}, B{0xdc}, B{0xc9}}},
     {"abcde",
      {B{0xde}, B{0x83}, B{0x22}, B{0xb4}, B{0x6e}, B{0x78}, B{0xb6}, B{0x7d},
       B{0x44}, B{0x31}, B{0x99}, B{0x70}, B{0x70}, B{0x70}, B{0x3e}, B{0x97},
       B{0x64}, B{0xe0}, B{0x3a}, B{0x12}, B{0x37}, B{0xb8}, B{0x96}, B{0xfd},
       B{0x8b}, B{0x37}, B{0x9e}, B{0xd4}, B{0x57}, B{0x6e}, B{0x83}, B{0x63}}},
     {"abcdef",
      {B{0xe4}, B{0xfd}, B{0xcb}, B{0x11}, B{0xd1}, B{0xac}, B{0x14}, B{0xe6},
       B{0x98}, B{0x74}, B{0x3a}, B{0xcd}, B{0x88}, B{0x05}, B{0x17}, B{0x4c},
       B{0xea}, B{0x5d}, B{0xdc}, B{0x0d}, B{0x31}, B{0x2e}, B{0x3e}, B{0x47},
       B{0xf6}, B{0x37}, B{0x20}, B{0x32}, B{0x57}, B{0x1b}, B{0xad}, B{0x84}}},
     {"abcdefg",
      {B{0xa8}, B{0x11}, B{0x7f}, B{0x68}, B{0x0b}, B{0xdc}, B{0xeb}, B{0x5d},
       B{0x14}, B{0x43}, B{0x61}, B{0x7c}, B{0xbd}, B{0xae}, B{0x92}, B{0x55},
       B{0xf6}, B{0x90}, B{0x00}, B{0x75}, B{0x42}, B{0x23}, B{0x26}, B{0xa9},
       B{0x72}, B{0xfd}, B{0xd2}, B{0xf6}, B{0x5b}, B{0xa9}, B{0xbe}, B{0xe3}}},
     {"abcdefgh",
      {B{0xa2}, B{0x9b}, B{0x96}, B{0x45}, B{0xd2}, B{0xa0}, B{0x2a}, B{0x8b},
       B{0x58}, B{0x28}, B{0x88}, B{0xd0}, B{0x44}, B{0x19}, B{0x97}, B{0x87},
       B{0x22}, B{0x0e}, B{0x31}, B{0x6b}, B{0xf2}, B{0xe8}, B{0x9d}, B{0x14},
       B{0x22}, B{0xd3}, B{0xdf}, B{0x26}, B{0xbf}, B{0x54}, B{0x5b}, B{0xbe}}},
     {"abcdefghi",
      {B{0xb9}, B{0x55}, B{0x09}, B{0x53}, B{0x30}, B{0xf9}, B{0xc8}, B{0x18},
       B{0x8d}, B{0x11}, B{0x88}, B{0x4e}, B{0xc1}, B{0x67}, B{0x9d}, B{0xc4},
       B{0x4c}, B{0x9c}, B{0x5b}, B{0x25}, B{0xff}, B{0x9b}, B{0xda}, B{0x70},
       B{0x04}, B{0x16}, B{0xdf}, B{0x9c}, B{0xdd}, B{0x39}, B{0x18}, B{0x8f}}},
     {"abcdefghij",
      {B{0x55}, B{0x07}, B{0x62}, B{0x91}, B{0x3d}, B{0x51}, B{0xee}, B{0xfb},
       B{0xcd}, B{0x1a}, B{0x55}, B{0x06}, B{0x8f}, B{0xcf}, B{0xc9}, B{0xb1},
       B{0x54}, B{0xfd}, B{0x11}, B{0xc1}, B{0x07}, B{0x8b}, B{0x99}, B{0x6d},
       B{0xf0}, B{0xd9}, B{0x26}, B{0xea}, B{0x59}, B{0xd2}, B{0xa6}, B{0x8d}}},
     {"How can you write a big system without C++?  -Paul Glick",
      {B{0x3f}, B{0xa4}, B{0x6d}, B{0x52}, B{0x09}, B{0x4b}, B{0x01}, B{0x02},
       B{0x1c}, B{0xff}, B{0x5a}, B{0xf9}, B{0xa4}, B{0x38}, B{0x98}, B{0x2b},
       B{0x88}, B{0x7a}, B{0x57}, B{0x93}, B{0xf6}, B{0x24}, B{0xc0}, B{0xa6},
       B{0x64}, B{0x41}, B{0x49}, B{0xb6}, B{0xb7}, B{0xc3}, B{0xf4}, B{0x85}}},
     {"6RT5wsQLCmYRFUn1kkoRV4tc9PEbq3o6hLz4NWlJymG5D9MJ12dUR7FwoPi07a2",
      {B{0x49}, B{0xff}, B{0xc7}, B{0xf3}, B{0xfb}, B{0x03}, B{0x59}, B{0xbd},
       B{0xb5}, B{0xd7}, B{0x59}, B{0xfc}, B{0xa5}, B{0x3a}, B{0x09}, B{0x2d},
       B{0xb1}, B{0xd7}, B{0x24}, B{0x8c}, B{0x28}, B{0xd1}, B{0x93}, B{0xaa},
       B{0xda}, B{0x05}, B{0x5c}, B{0xe3}, B{0xe2}, B{0xd4}, B{0x81}, B{0x41}}},
     {"bmWgj6pFf2NWRPGJaZTq naxmTjVYhnJbZbYy9Ux3 pJeNuO3J4dE7b75HkoMM 8",
      {B{0xf6}, B{0x7f}, B{0xbe}, B{0x7a}, B{0x04}, B{0x8c}, B{0xd2}, B{0x85},
       B{0x08}, B{0x4a}, B{0xc0}, B{0xfb}, B{0xfe}, B{0xf9}, B{0x92}, B{0xfd},
       B{0xd5}, B{0x29}, B{0x23}, B{0x52}, B{0x91}, B{0x18}, B{0x04}, B{0xff},
       B{0x07}, B{0x89}, B{0xa0}, B{0x01}, B{0xca}, B{0x1f}, B{0x1e}, B{0xe9}}},
     {"The fugacity of a constituent in a mixture of gases at a given "
      "temperature is proportional to its mole fraction.  Lewis-Randall Rule",
      {B{0x68}, B{0x8f}, B{0xf0}, B{0x3e}, B{0x36}, B{0x76}, B{0x80}, B{0x75},
       B{0x7a}, B{0xa9}, B{0x90}, B{0x6c}, B{0xb1}, B{0xe2}, B{0xad}, B{0x21},
       B{0x8c}, B{0x51}, B{0xf4}, B{0x52}, B{0x6d}, B{0xc0}, B{0x42}, B{0x6e},
       B{0xa2}, B{0x29}, B{0xa5}, B{0xba}, B{0x9d}, B{0x00}, B{0x2c}, B{0x69}}},
     {"Even if I could be Shakespeare, I think I should still choose to be "
      "Faraday. - A. Huxley",
      {B{0xa7}, B{0xa3}, B{0x84}, B{0x60}, B{0x05}, B{0xf8}, B{0xa9},
       B{0x93}, B{0x5a}, B{0x0a}, B{0x2d}, B{0x43}, B{0xe7}, B{0xfd},
       B{0x56}, B{0xd9}, B{0x51}, B{0x32}, B{0xa9}, B{0xa3}, B{0x60},
       B{0x9b}, B{0xf3}, B{0x29}, B{0x6e}, B{0xf8}, B{0x0b}, B{0x82},
       B{0x18}, B{0xac}, B{0xff}, B{0xa0}}}}};

int main(int argc, char *argv[]) {
  return run_testcases<crypto::sha::sha512_256_hash, NUM_TESTCASES>(
      process_cmdline_args(argc, argv, NUM_TESTCASES), testcases);
}