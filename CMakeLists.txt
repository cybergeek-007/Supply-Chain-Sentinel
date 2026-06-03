cmake_minimum_required(VERSION 3.16)
project(supply_chain_sentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(SCS_BUILD_CPP_CORE "Build pybind11 C++ entropy extension" ON)
option(SCS_BUILD_CPP_TESTS "Build C++ unit tests (requires GTest)" OFF)

if(SCS_BUILD_CPP_CORE)
    find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
    find_package(pybind11 CONFIG REQUIRED)

    pybind11_add_module(sentinel_core
        src/core/cpp/entropy.cpp
        src/core/cpp/bindings.cpp
    )

    if(UNIX AND NOT APPLE)
        target_compile_options(sentinel_core PRIVATE -O3 -march=native)
    endif()

    set_target_properties(sentinel_core PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/src"
    )
endif()

if(SCS_BUILD_CPP_TESTS)
    enable_testing()
    add_subdirectory(src/core/cpp/tests)
endif()

