project(lockdown LANGUAGES CXX)

# Unit test driver
add_executable(sha256_test sha256_test.cpp)

add_test(NAME sha256_on_string_null
         COMMAND sha256_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_a
         COMMAND sha256_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_ab
         COMMAND sha256_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abc
         COMMAND sha256_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcd
         COMMAND sha256_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcde
         COMMAND sha256_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcdef
         COMMAND sha256_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcdefg
         COMMAND sha256_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcdefgh
         COMMAND sha256_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcdefghi
         COMMAND sha256_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_abcdefghij
         COMMAND sha256_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_paul_glick_quote
         COMMAND sha256_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_63_chars
         COMMAND sha256_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_64_chars
         COMMAND sha256_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_65_chars
         COMMAND sha256_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha256_on_string_111_chars
         COMMAND sha256_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)

add_executable(sha256-224_test sha256-224_test.cpp)

add_test(NAME sha224_on_string_null
         COMMAND sha256-224_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_a
         COMMAND sha256-224_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_ab
         COMMAND sha256-224_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abc
         COMMAND sha256-224_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcd
         COMMAND sha256-224_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcde
         COMMAND sha256-224_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdef
         COMMAND sha256-224_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefg
         COMMAND sha256-224_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefgh
         COMMAND sha256-224_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefghi
         COMMAND sha256-224_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefghij
         COMMAND sha256-224_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_paul_glick_quote
         COMMAND sha256-224_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_63_chars
         COMMAND sha256-224_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_64_chars
         COMMAND sha256-224_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_65_chars
         COMMAND sha256-224_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_111_chars
         COMMAND sha256-224_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
