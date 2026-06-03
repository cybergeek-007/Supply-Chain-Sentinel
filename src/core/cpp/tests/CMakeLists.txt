cmake_minimum_required(VERSION 3.16)

find_package(GTest REQUIRED)

add_executable(entropy_test entropy_test.cpp ../entropy.cpp)
target_include_directories(entropy_test PRIVATE ..)
target_link_libraries(entropy_test PRIVATE GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(entropy_test)

