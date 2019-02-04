project(lockdown LANGUAGES CXX)

add_executable(sha256_test sha256_test.cpp)
target_include_directories(sha256_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

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

add_executable(sha224_test sha224_test.cpp)
target_include_directories(sha224_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME sha224_on_string_null
         COMMAND sha224_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_a
         COMMAND sha224_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_ab
         COMMAND sha224_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abc
         COMMAND sha224_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcd
         COMMAND sha224_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcde
         COMMAND sha224_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdef
         COMMAND sha224_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefg
         COMMAND sha224_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefgh
         COMMAND sha224_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefghi
         COMMAND sha224_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_abcdefghij
         COMMAND sha224_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_paul_glick_quote
         COMMAND sha224_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_63_chars
         COMMAND sha224_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_64_chars
         COMMAND sha224_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_65_chars
         COMMAND sha224_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha224_on_string_111_chars
         COMMAND sha224_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)

add_executable(sha512_test sha512_test.cpp)
target_include_directories(sha512_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME sha512_on_string_null
         COMMAND sha512_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_a
         COMMAND sha512_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_ab
         COMMAND sha512_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abc
         COMMAND sha512_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcd
         COMMAND sha512_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcde
         COMMAND sha512_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcdef
         COMMAND sha512_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcdefg
         COMMAND sha512_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcdefgh
         COMMAND sha512_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcdefghi
         COMMAND sha512_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_abcdefghij
         COMMAND sha512_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_paul_glick_quote
         COMMAND sha512_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_63_chars
         COMMAND sha512_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_64_chars
         COMMAND sha512_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_65_chars
         COMMAND sha512_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512_on_string_111_chars
         COMMAND sha512_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)

add_executable(sha512-224_test sha512-224_test.cpp)
target_include_directories(sha512-224_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME sha512-224_on_string_null
         COMMAND sha512-224_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_a
         COMMAND sha512-224_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_ab
         COMMAND sha512-224_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abc
         COMMAND sha512-224_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcd
         COMMAND sha512-224_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcde
         COMMAND sha512-224_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcdef
         COMMAND sha512-224_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcdefg
         COMMAND sha512-224_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcdefgh
         COMMAND sha512-224_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcdefghi
         COMMAND sha512-224_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_abcdefghij
         COMMAND sha512-224_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_paul_glick_quote
         COMMAND sha512-224_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_63_chars
         COMMAND sha512-224_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_64_chars
         COMMAND sha512-224_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_lewis-randall_rule
         COMMAND sha512-224_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-224_on_string_aldus_huxley_quote
         COMMAND sha512-224_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)

add_executable(sha512-256_test sha512-256_test.cpp)
target_include_directories(sha512-256_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME sha512-256_on_string_null
         COMMAND sha512-256_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_a
         COMMAND sha512-256_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_ab
         COMMAND sha512-256_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abc
         COMMAND sha512-256_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcd
         COMMAND sha512-256_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcde
         COMMAND sha512-256_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcdef
         COMMAND sha512-256_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcdefg
         COMMAND sha512-256_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcdefgh
         COMMAND sha512-256_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcdefghi
         COMMAND sha512-256_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_abcdefghij
         COMMAND sha512-256_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_paul_glick_quote
         COMMAND sha512-256_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_63_chars
         COMMAND sha512-256_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_64_chars
         COMMAND sha512-256_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_lewis-randall_rule
         COMMAND sha512-256_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha512-256_on_string_aldus_huxley_quote
         COMMAND sha512-256_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)

add_executable(sha384_test sha384_test.cpp)
target_include_directories(sha384_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME sha384_on_string_null
         COMMAND sha384_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_a
         COMMAND sha384_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_ab
         COMMAND sha384_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abc
         COMMAND sha384_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcd
         COMMAND sha384_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcde
         COMMAND sha384_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcdef
         COMMAND sha384_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcdefg
         COMMAND sha384_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcdefgh
         COMMAND sha384_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcdefghi
         COMMAND sha384_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_abcdefghij
         COMMAND sha384_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_paul_glick_quote
         COMMAND sha384_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_63_chars
         COMMAND sha384_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_64_chars
         COMMAND sha384_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_lewis-randall_rule
         COMMAND sha384_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
add_test(NAME sha384_on_string_aldus_huxley_quote
         COMMAND sha384_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha)
