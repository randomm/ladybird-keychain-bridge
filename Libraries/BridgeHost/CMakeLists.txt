add_library(lkb_bridgehost STATIC BridgeHost.cpp)
target_link_libraries(lkb_bridgehost PUBLIC lkb_service)
target_include_directories(lkb_bridgehost PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestBridgeHost tests/TestBridgeHost.cpp)
target_link_libraries(TestBridgeHost PRIVATE lkb_bridgehost)
add_test(NAME TestBridgeHost COMMAND TestBridgeHost)
