add_library(lkb_core STATIC Origin.cpp)
target_include_directories(lkb_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestCorePlaceholder tests/TestCorePlaceholder.cpp)
target_link_libraries(TestCorePlaceholder PRIVATE lkb_core)
add_test(NAME TestCorePlaceholder COMMAND TestCorePlaceholder)

add_executable(TestOrigin tests/TestOrigin.cpp)
target_link_libraries(TestOrigin PRIVATE lkb_core)
add_test(NAME TestOrigin COMMAND TestOrigin)
