#ifndef __SHA_TEST_HPP__
#define __SHA_TEST_HPP__ 1

#include <cstdio>
#include <cstdlib>
#include <optional>

template <class algorithm> struct testcase_t {
  std::string_view string;
  typename algorithm::digest_t digest;
};

template <class algorithm, std::size_t num_testcases>
using testcases_t = std::array<testcase_t<algorithm>, num_testcases>;

using requested_tcnum_t = std::optional<std::size_t>;

template <class algorithm, std::size_t max_num_testcases>
int run_testcases(requested_tcnum_t testcase_num,
                  const testcases_t<algorithm, max_num_testcases> &testcases) {
  int rc = 0;
  std::size_t tcnum = 0, tctotal = max_num_testcases;

  if (testcase_num) {
    if (*testcase_num > max_num_testcases) {
      return -1;
    }
    tctotal = *testcase_num;
    tcnum = tctotal - 1;
  }

  std::printf("\n");

  algorithm hash;

  for (; tcnum < tctotal; ++tcnum) {
    const testcase_t<algorithm> &tc = testcases[tcnum];

    hash.hash_data((std::byte *)(tc.string.data()),
                   tc.string.length() * sizeof(std::string_view::value_type));

    std::printf("%04lu: ", tcnum + 1);
    if (tc.digest == hash.get_digest()) {
      std::printf("passed");
    } else {
      std::printf("failed");
      rc = -1;
    }
    std::printf(" \"%s\"\n", tc.string.data());

    hash.reset();
  }
  return rc;
};

requested_tcnum_t process_cmdline_args(int argc, char *argv[],
                                       std::size_t num_testcases) {
  requested_tcnum_t requested_tcnum;
  if (argc > 1) {
    int tcnum = std::atoi(argv[1]);
    if (tcnum < 1 || std::size_t(tcnum) > num_testcases) {
      std::printf("\nERROR: Requested testcase is invalid. Range is [1-%lu].\n",
                  num_testcases);
      std::printf("USAGE: %s [testcase#]\n", argv[0]);
      std::printf("NOTE: No testcase number will run all testcases.\n");
      return -1;
    }
    requested_tcnum = std::size_t(tcnum);
    std::printf("\nTestcase (selected 1 out of %lu):\n", num_testcases);
  } else {
    std::printf("\nTestcases (%lu):\n", num_testcases);
  }
  return requested_tcnum;
};
#endif
