project(lockdown LANGUAGES CXX)

add_library(sha256 OBJECT sha256.cpp)

# Unit test driver
add_executable(sha256_test sha256_test.cpp $<TARGET_OBJECTS:sha256>)

add_test(NAME string_null
         COMMAND sha256_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_a
         COMMAND sha256_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_ab
         COMMAND sha256_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abc
         COMMAND sha256_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcd
         COMMAND sha256_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcde
         COMMAND sha256_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcdef
         COMMAND sha256_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcdefg
         COMMAND sha256_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcdefgh
         COMMAND sha256_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcdefghi
         COMMAND sha256_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
add_test(NAME string_abcdefghij
         COMMAND sha256_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha256)
