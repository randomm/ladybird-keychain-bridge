add_library(lkb_proto STATIC Frame.cpp Handshake.cpp Json.cpp)
target_link_libraries(lkb_proto PUBLIC lkb_core lkb_crypto)
target_include_directories(lkb_proto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestFrame tests/TestFrame.cpp)
target_link_libraries(TestFrame PRIVATE lkb_proto)
target_include_directories(TestFrame PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME TestFrame COMMAND TestFrame)

add_executable(TestHandshake tests/TestHandshake.cpp)
target_link_libraries(TestHandshake PRIVATE lkb_proto)
target_include_directories(TestHandshake PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(TestHandshake PRIVATE FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
add_test(NAME TestHandshake COMMAND TestHandshake)
