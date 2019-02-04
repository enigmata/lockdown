project(lockdown LANGUAGES CXX)

add_subdirectory(sha)

add_executable(hash_test hash_test.cpp)
target_include_directories(hash_test PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_test(NAME hash<sha256>_on_string_null
         COMMAND hash_test 1
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha256>_on_string_a
         COMMAND hash_test 2
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha256>_on_string_64_chars
         COMMAND hash_test 3
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha256>_on_string_111_chars
         COMMAND hash_test 4
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha224>_on_string_abcdefghij
         COMMAND hash_test 5
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha224>_on_string_paul_glick_quote
         COMMAND hash_test 6
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha224>_on_string_63_chars
         COMMAND hash_test 7
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512>_on_string_null
         COMMAND hash_test 8
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512>_on_string_a
         COMMAND hash_test 9
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512>_on_string_63_chars
         COMMAND hash_test 10
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512>_on_string_111_chars
         COMMAND hash_test 11
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512>_on_string_64_chars
         COMMAND hash_test 12
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-224>_on_string_abcdefghij
         COMMAND hash_test 13
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-224>_on_string_lewis-randall_rule
         COMMAND hash_test 14
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-224>_on_string_aldus_huxley_quote
         COMMAND hash_test 15
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-256>_on_string_abcdefghij
         COMMAND hash_test 16
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-256>_on_string_lewis-randall_rule
         COMMAND hash_test 17
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha512-256>_on_string_aldus_huxley_quote
         COMMAND hash_test 18
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha384>_on_string_abcdefghij
         COMMAND hash_test 19
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha384>_on_string_lewis-randall_rule
         COMMAND hash_test 20
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
add_test(NAME hash<sha384>_on_string_aldus_huxley_quote
         COMMAND hash_test 21
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/hash)
