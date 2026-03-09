# sentinel-drv: Kernel-mode WDM driver
# This CMakeLists.txt is a stub. The actual kernel-mode build uses WDK
# infrastructure which requires special handling (inf2cat, stampinf, etc.).
# For now we define the source list; the real build will use a custom
# command or the FindWDK CMake module.

cmake_minimum_required(VERSION 3.20)

set(SENTINEL_DRV_SOURCES
    main.c
)

# Kernel drivers cannot be built with the normal add_executable/add_library
# flow. This stub exists so the top-level CMakeLists.txt can reference the
# subdirectory. The actual build is handled by the WDK build system or a
# FindWDK CMake module that provides wdk_add_driver().
#
# When FindWDK is available:
#   wdk_add_driver(sentinel-drv ${SENTINEL_DRV_SOURCES})
#
# For now, we create an INTERFACE library so the project configures cleanly.
add_library(sentinel-drv INTERFACE)
target_include_directories(sentinel-drv INTERFACE ${CMAKE_SOURCE_DIR}/common)

message(STATUS "sentinel-drv: Configured (kernel driver stub)")
