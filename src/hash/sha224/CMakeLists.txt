project(lockdown LANGUAGES CXX)

add_library(sha224 OBJECT sha224.cpp)

# Unit test driver
add_executable(sha224_test sha224_test.cpp $<TARGET_OBJECTS:sha224> $<TARGET_OBJECTS:sha256>)

add_test(NAME sha224_on_string_null
         COMMAND sha224_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_a
         COMMAND sha224_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_ab
         COMMAND sha224_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abc
         COMMAND sha224_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcd
         COMMAND sha224_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcde
         COMMAND sha224_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcdef
         COMMAND sha224_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcdefg
         COMMAND sha224_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcdefgh
         COMMAND sha224_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcdefghi
         COMMAND sha224_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_abcdefghij
         COMMAND sha224_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_paul_glick_quote
         COMMAND sha224_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_63_chars
         COMMAND sha224_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_64_chars
         COMMAND sha224_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_65_chars
         COMMAND sha224_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
add_test(NAME sha224_on_string_111_chars
         COMMAND sha224_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash/sha224)
