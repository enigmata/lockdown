cmake_minimum_required(VERSION 3.13.1)

project(lockdown LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)

add_compile_options("-Wall" "-Wextra" "-Werror" "-O2")

add_subdirectory(src)
