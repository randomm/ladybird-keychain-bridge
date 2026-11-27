add_library(lkb_keychain STATIC MasterKey.cpp)
target_link_libraries(lkb_keychain PUBLIC lkb_core)
target_include_directories(lkb_keychain PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(TestMasterKey tests/TestMasterKey.cpp)
target_link_libraries(TestMasterKey PRIVATE lkb_keychain)
add_test(NAME TestMasterKey COMMAND TestMasterKey)
