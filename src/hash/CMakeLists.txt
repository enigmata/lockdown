project(lockdown LANGUAGES CXX)

add_subdirectory(sha256)

add_library(hash STATIC hash.cpp)
target_link_libraries(hash sha256)
