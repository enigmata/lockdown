cmake_minimum_required(VERSION 3.13.1)

project(lockdown LANGUAGES CXX)

enable_testing()

set(CMAKE_CXX_STANDARD 17)

add_compile_options("-Wall" "-Wextra" "-Werror" "-O2")

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "-stdlib=libc++")
    message("Compiler is Clang++")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message("Compiler is g++")
else(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "Compiler is not supported: ${CMAKE_CXX_COMPILER_ID}")
endif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")

add_subdirectory(src)
