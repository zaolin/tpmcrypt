cmake_minimum_required(VERSION 2.8)
project(tpmcrypt-console CXX)

set(TpmCrypt_INCLUDE_DIRS ../)
file(GLOB tpmcrypt-console_SOURCES console.cpp)

include_directories(include ${tspi_INCLUDE_DIRS} ${blkid_INCLUDE_DIRS} ${cryptopp_INCLUDE_DIRS} ${TpmCrypt_INCLUDE_DIRS})

add_executable(tpmcrypt-console ${TpmCrypt_SOURCES} ${tpmcrypt-console_SOURCES} ${TpmCrypt_HEADERS})
target_link_libraries(tpmcrypt-console ${tspi_LIBRARIES} ${blkid_LIBRARIES} ${cryptopp_LIBRARIES})
install(TARGETS tpmcrypt-console RUNTIME DESTINATION bin)

if(NOT DEFINED "CMAKE_BUILD_TYPE" OR "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_custom_command(TARGET tpmcrypt-console
    POST_BUILD
    COMMAND paxctl -perms tpmcrypt-console
    WORKING_DIRECTORY .)
endif()