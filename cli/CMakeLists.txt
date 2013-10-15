cmake_minimum_required(VERSION 2.8)
project(tpmcrypt-console CXX)

set(TpmCrypt_INCLUDE_DIRS ../)
file(GLOB tpmcrypt-console_SOURCES console.cpp)

include_directories(include ${tspi_INCLUDE_DIRS} ${blkid_INCLUDE_DIRS} ${TpmCrypt_INCLUDE_DIRS})

add_executable(tpmcrypt-console ${TpmCrypt_SOURCES} ${tpmcrypt-console_SOURCES} ${TpmCrypt_HEADERS})
target_link_libraries(tpmcrypt-console ${tspi_LIBRARIES} ${blkid_LIBRARIES})
set_target_properties(tpmcrypt-console PROPERTIES VERSION
	${TpmCrypt_MAJOR_VERSION}.${TpmCrypt_MINOR_VERSION}.${TpmCrypt_PATCH_VERSION})
install(TARGETS tpmcrypt-console RUNTIME DESTINATION bin)