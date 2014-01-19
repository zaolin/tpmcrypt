cmake_minimum_required(VERSION 2.6)
enable_testing()

find_path(gtest_INCLUDE_DIR gtest/gtest.h)
find_library(gtest_LIBRARIES gtest)
find_package_handle_standard_args(GTEST REQUIRED_VARS
    gtest_LIBRARIES gtest_INCLUDE_DIR)

add_executable( runUnitTests CryptoNamespace.cpp )
target_link_libraries(runUnitTests gtest gtest_main)
add_test( runUnitTests runUnitTests )