cmake_minimum_required(VERSION 2.8)
project(TpmCrypt CXX)
include(CheckCXXCompilerFlag)
include(FindPackageHandleStandardArgs)
 
set(PROJECT_BINARY_DIR bin)
set(TpmCrypt_MAJOR_VERSION 0)
set(TpmCrypt_MINOR_VERSION 0)
set(TpmCrypt_PATCH_VERSION 1)
set(TpmCrypt_VERSION
  ${TpmCrypt_MAJOR_VERSION}.${TpmCrypt_MINOR_VERSION}.${TpmCrypt_PATCH_VERSION})

option(TpmCrypt_BUILD "Build TpmCrypt Tool (tpmcrypt-console)" ON)

# C++ & Compiler Flags
add_definitions("-O2 -Wall -pedantic -Wextra")
add_definitions("-fprofile-arcs -ftest-coverage")

# Security Flags
add_definitions("-Wformat -Wformat-security -Werror=format-security 
-fstack-protector-all --param ssp-buffer-size=4 -fpic -pie")

# Security Linking Flags
set(CMAKE_SHARED_LINKER_FLAGS "-z,relro,-z,now")

# Dependencies
CHECK_CXX_COMPILER_FLAG("-std=c++0x" CXXFLAG_CPP0X)
CHECK_CXX_COMPILER_FLAG("-std=c++11" CXXFLAG_CPP11)

# Release mode is default
if(NOT DEFINED "CMAKE_BUILD_TYPE" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Release")
	add_definitions("-Werror")
	message("Build release")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
	include(CTest)
	message("Build debug")
endif()

#find_package(PkgConfig)
#pkg_check_modules(redland REQUIRED redland)
#pkg_check_modules(raptor REQUIRED raptor2)
#pkg_check_modules(minizip REQUIRED minizip)

find_path(blkid_INCLUDE_DIRS blkid/blkid.h)
find_library(blkid_LIBRARIES blkid)
find_package_handle_standard_args(BLKID REQUIRED_VARS
	blkid_LIBRARIES blkid_INCLUDE_DIRS)

find_path(tspi_INCLUDE_DIRS trousers/trousers.h)
find_library(tspi_LIBRARIES tspi)
find_package_handle_standard_args(TROUSERS REQUIRED_VARS
	tspi_LIBRARIES tspi_INCLUDE_DIRS)

find_path(cryptopp_INCLUDE_DIRS crypto++/default.h)
find_library(cryptopp_LIBRARIES crypto++)
find_package_handle_standard_args(CRYPTOPP REQUIRED_VARS
	cryptopp_LIBRARIES cryptopp_INCLUDE_DIRS)

# C++11 flags
if(CXXFLAG_CPP11)
	add_definitions("-std=c++11")
elseif(CXXFLAG_CPP0X)
	add_definitions("-std=c++0x")
else()
	message(FATAL_ERROR "Your compiler does not support C++11. Please use clang
       3.0 or GCC 4.7.")
endif()

file(GLOB TpmCrypt_SOURCES crypto/*.cpp externals/*.cpp management/*.cpp protocol/*.cpp tools/*.cpp utils/*.cpp tpm/*.cpp)
file(GLOB TpmCrypt_HEADERS crypto/*.h externals/*.h management/*.h protocol/*.h tools/*.h utils/*.h tpm/*.h)

add_subdirectory("cli")
