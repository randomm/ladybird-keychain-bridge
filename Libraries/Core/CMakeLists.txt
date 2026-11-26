add_library(lkb_core INTERFACE)
target_include_directories(lkb_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestCorePlaceholder tests/TestCorePlaceholder.cpp)
target_link_libraries(TestCorePlaceholder PRIVATE lkb_core)
add_test(NAME TestCorePlaceholder COMMAND TestCorePlaceholder)
