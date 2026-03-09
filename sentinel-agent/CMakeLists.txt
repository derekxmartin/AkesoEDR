# sentinel-agent: User-mode service (C++20)
cmake_minimum_required(VERSION 3.20)

add_executable(sentinel-agent
    main.cpp
)

target_include_directories(sentinel-agent PRIVATE ${CMAKE_SOURCE_DIR}/common)
set_target_properties(sentinel-agent PROPERTIES
    CXX_STANDARD 20
    OUTPUT_NAME "sentinel-agent"
)

message(STATUS "sentinel-agent: Configured (agent service stub)")
