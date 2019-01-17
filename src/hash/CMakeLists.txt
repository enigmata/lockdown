project(lockdown LANGUAGES CXX)

add_subdirectory(sha256)
add_subdirectory(sha224)

add_library(hash STATIC)
target_link_libraries(hash sha256)
target_link_libraries(hash sha224)

# Unit test driver
add_executable(hash_test hash_test.cpp)
target_link_libraries(hash_test hash)

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
