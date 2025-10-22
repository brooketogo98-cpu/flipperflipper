cmake_minimum_required(VERSION 3.10)
project(StealthPayload C)

# Advanced compiler flags for minimal size and maximum stealth
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Optimization flags for size
set(CMAKE_C_FLAGS_RELEASE "-Os -ffunction-sections -fdata-sections -fno-ident -fno-asynchronous-unwind-tables")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none")

# Security flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -z now -z relro")

# Disable runtime type information and exceptions for smaller size
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-unwind-tables -fno-exceptions")
endif()

# Platform detection
if(WIN32)
    add_definitions(-D_WIN32)
    set(PLATFORM_DIR "windows")
    # Windows specific optimizations
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mwindows")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static")
elseif(APPLE)
    add_definitions(-D_MACOS)
    set(PLATFORM_DIR "macos")
else()
    add_definitions(-D_LINUX)
    set(PLATFORM_DIR "linux")
    # Linux specific optimizations
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/core
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}/network
    ${CMAKE_SOURCE_DIR}/${PLATFORM_DIR}
)

# Core source files
set(CORE_SOURCES
    core/main.c
    core/config.c
    core/utils.c
    core/commands.c
)

# Crypto sources
set(CRYPTO_SOURCES
    crypto/aes.c
    crypto/sha256.c
    crypto/random.c
    crypto/obfuscate.c
)

# Network sources
set(NETWORK_SOURCES
    network/tcp.c
    network/http.c
    network/protocol.c
)

# Platform specific sources
file(GLOB PLATFORM_SOURCES "${PLATFORM_DIR}/*.c")

# Main executable
add_executable(payload
    ${CORE_SOURCES}
    ${CRYPTO_SOURCES}
    ${NETWORK_SOURCES}
    ${PLATFORM_SOURCES}
)

# Link libraries based on platform
if(WIN32)
    target_link_libraries(payload ws2_32 ntdll kernel32)
elseif(NOT APPLE)
    target_link_libraries(payload pthread m)
endif()

# Custom stripping for minimal size
add_custom_command(TARGET payload POST_BUILD
    COMMAND ${CMAKE_STRIP} -s $<TARGET_FILE:payload>
    COMMENT "Stripping debug symbols..."
)

# UPX packing (optional)
find_program(UPX upx)
if(UPX)
    add_custom_command(TARGET payload POST_BUILD
        COMMAND ${UPX} --best --lzma $<TARGET_FILE:payload>
        COMMENT "Packing with UPX..."
    )
endif()

# Testing
enable_testing()
add_subdirectory(tests)