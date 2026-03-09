cmake_minimum_required(VERSION 3.20)
project(SentinelPOC VERSION 1.0.0 LANGUAGES C CXX)

# ── Global settings ──────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output all binaries to a common location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ── WDK Detection ────────────────────────────────────────────────────────────
# Try to find the Windows Driver Kit. The WDK CMake support is provided by
# the FindWDK module (https://github.com/SergiusTheBest/FindWDK) or by
# setting WDK_ROOT manually.
#
# If WDK is not found, kernel-mode components are skipped and only user-mode
# components are built.

set(SENTINEL_HAS_WDK FALSE)

# Method 1: Check for WDK_ROOT environment variable or CMake variable
if(DEFINED ENV{WDK_ROOT})
    set(WDK_ROOT "$ENV{WDK_ROOT}")
endif()

if(NOT DEFINED WDK_ROOT)
    # Method 2: Probe standard install locations
    file(GLOB _wdk_candidates "C:/Program Files (x86)/Windows Kits/10/Include/*/km")
    if(_wdk_candidates)
        list(SORT _wdk_candidates ORDER DESCENDING)
        list(GET _wdk_candidates 0 _wdk_km_dir)
        get_filename_component(_wdk_ver_dir "${_wdk_km_dir}" DIRECTORY)
        get_filename_component(WDK_ROOT "${_wdk_ver_dir}/../.." ABSOLUTE)
    endif()
endif()

if(DEFINED WDK_ROOT AND EXISTS "${WDK_ROOT}")
    message(STATUS "WDK found at: ${WDK_ROOT}")
    set(SENTINEL_HAS_WDK TRUE)

    # Determine WDK version from the Include directory
    file(GLOB _wdk_versions "${WDK_ROOT}/Include/*")
    list(SORT _wdk_versions ORDER DESCENDING)
    foreach(_ver_path ${_wdk_versions})
        if(IS_DIRECTORY "${_ver_path}/km")
            get_filename_component(WDK_VERSION "${_ver_path}" NAME)
            break()
        endif()
    endforeach()

    if(DEFINED WDK_VERSION)
        message(STATUS "WDK version: ${WDK_VERSION}")
    else()
        message(WARNING "WDK found but could not determine version")
        set(SENTINEL_HAS_WDK FALSE)
    endif()
else()
    message(STATUS "WDK not found -- kernel-mode components will be skipped")
    message(STATUS "  Set WDK_ROOT or install the Windows Driver Kit to enable driver builds")
endif()

# ── Common include path ──────────────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/common)

# ── Sub-projects ─────────────────────────────────────────────────────────────

# Kernel-mode driver (requires WDK)
if(SENTINEL_HAS_WDK)
    add_subdirectory(sentinel-drv)
else()
    message(STATUS "Skipping sentinel-drv (no WDK)")
endif()

# User-mode components (always built)
add_subdirectory(sentinel-hook)
add_subdirectory(sentinel-agent)
add_subdirectory(sentinel-cli)

# Tests
enable_testing()
add_subdirectory(tests)
